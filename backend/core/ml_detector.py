from __future__ import annotations

import math
import random
import threading
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from backend.db.database import connect, get_state


_local_model: IsolationForest | None = None
_baseline_count = 0
_baseline_lock = threading.Lock()
_feedback_model: Any = None
_feedback_count = 0
_feedback_metrics: dict[str, float] = {}


def train_isolation_forest() -> dict[str, object]:
    global _local_model, _baseline_count
    with _baseline_lock:
        with connect() as db:
            rows = db.execute(
                """SELECT t.amount, t.velocity_score, t.biometric_score, t.proxy_type
                FROM transactions t
                LEFT JOIN reviewed_feedback f ON f.transaction_id = t.id
                WHERE f.label = 0 OR (f.label IS NULL AND t.status = 'APPROVED')
                ORDER BY t.created_at DESC LIMIT 20000"""
            ).fetchall()
        if len(rows) < 100:
            return {"trained": False, "baseline_transactions": len(rows), "minimum": 100}
        if _local_model is not None and len(rows) - _baseline_count < 25:
            return {"trained": True, "baseline_transactions": _baseline_count}
        features = [
            [
                math.log1p(float(row["amount"])),
                float(row["velocity_score"]),
                float(row["biometric_score"]),
                float(str(row["proxy_type"]).upper() in {"TOR", "ANONYMOUS"}),
            ]
            for row in rows
        ]
        model = IsolationForest(
            n_estimators=100, contamination=0.03, random_state=42, n_jobs=1
        )
        model.fit(features)
        _local_model = model
        _baseline_count = len(rows)
        return {"trained": True, "baseline_transactions": _baseline_count}


def local_model_status() -> dict[str, Any]:
    return {"trained": _local_model is not None, "baseline_transactions": _baseline_count}


def _features(example: dict[str, Any]) -> list[float]:
    proxy = str(example["proxy_type"]).upper() in {"TOR", "ANONYMOUS"}
    return [
        math.log1p(float(example["amount"])),
        float(example["velocity_score"]),
        float(example["biometric_score"]),
        float(proxy),
    ]


def update_feedback_model(examples: list[dict[str, Any]]) -> dict[str, Any]:
    global _feedback_model, _feedback_count, _feedback_metrics
    labels = [int(example["label"]) for example in examples]
    _feedback_count = len(labels)
    if labels.count(0) < 10 or labels.count(1) < 10:
        _feedback_model = None
        _feedback_metrics = {}
        return {"trained": False, "labels": _feedback_count, "minimum_per_class": 10}

    features = [_features(example) for example in examples]
    feature_array = np.asarray(features, dtype=float)
    label_array = np.asarray(labels, dtype=int)
    model = make_pipeline(
        StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=500, random_state=42),
    )
    tune_threshold = _feedback_model is None or _feedback_count % 10 == 0
    if tune_threshold:
        probabilities = cross_val_predict(
            model,
            feature_array,
            label_array,
            cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
            method="predict_proba",
        )[:, 1]
        base_features = [
            [
                0.42 * _clamp(float(example["velocity_score"]))
                + 0.36 * (1.0 - _clamp(float(example["biometric_score"])))
                + 0.17 * float(str(example["proxy_type"]).upper() in {"TOR", "ANONYMOUS"})
                + 0.05 * _clamp(math.log1p(float(example["amount"])) / math.log1p(10000))
            ]
            for example in examples
        ]
        if _local_model is not None:
            anomaly = -_local_model.decision_function(features)
            unsupervised_risk = [_clamp((float(score) - 0.02) / 0.16) for score in anomaly]
            model_risks = [
                _clamp(0.35 * unsupervised + 0.65 * float(supervised))
                for unsupervised, supervised in zip(unsupervised_risk, probabilities)
            ]
        else:
            model_risks = [
                _clamp(0.35 * base[0] + 0.65 * float(supervised))
                for base, supervised in zip(base_features, probabilities)
            ]
        calibrated_scores = [
            _clamp(0.75 * base[0] + 0.25 * model_risk)
            for base, model_risk in zip(base_features, model_risks)
        ]
        choices: list[tuple[float, float, float, float]] = []
        for threshold in [step / 100 for step in range(30, 91)]:
            predictions = [int(score >= threshold) for score in calibrated_scores]
            choices.append(
                (
                    float(f1_score(labels, predictions, zero_division=0)),
                    threshold,
                    float(precision_score(labels, predictions, zero_division=0)),
                    float(recall_score(labels, predictions, zero_division=0)),
                )
            )
        best_f1, best_threshold, precision, recall = max(choices)
        _feedback_metrics = {
            "threshold": best_threshold,
            "cross_validated_f1": best_f1,
            "cross_validated_precision": precision,
            "cross_validated_recall": recall,
        }
    _feedback_model = model.fit(feature_array, label_array)
    return {"trained": True, "labels": _feedback_count, **_feedback_metrics}


def feedback_model_status() -> dict[str, Any]:
    return {
        "trained": _feedback_model is not None,
        "labels": _feedback_count,
        "metrics": dict(_feedback_metrics),
    }


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def assess_transaction(
    amount: float,
    velocity_score: float,
    biometric_score: float,
    proxy_type: str,
    failsafe: bool | None = None,
) -> tuple[float, str]:
    """Fast, deterministic local risk scoring; never depends on cloud availability."""
    proxy_risk = 1.0 if proxy_type.upper() in {"TOR", "ANONYMOUS"} else 0.0
    feature_risk = (
        0.42 * _clamp(velocity_score)
        + 0.36 * (1.0 - _clamp(biometric_score))
        + 0.17 * proxy_risk
        + 0.05 * _clamp(math.log1p(amount) / math.log1p(10000))
    )
    features = [[math.log1p(amount), velocity_score, biometric_score, proxy_risk]]
    if _local_model is not None:
        anomaly = -float(_local_model.decision_function(features)[0])
        model_risk = _clamp((anomaly - 0.02) / 0.16)
    else:
        model_risk = feature_risk
    if _feedback_model is not None:
        supervised_risk = float(_feedback_model.predict_proba(features)[0][1])
        model_risk = _clamp(0.35 * model_risk + 0.65 * supervised_risk)
    is_failsafe = (
        get_state("failsafe_enabled", "false") == "true"
        if failsafe is None
        else failsafe
    )
    learned_threshold = float(get_state("learned_risk_threshold", "0.72"))
    threshold = min(learned_threshold, 0.58) if is_failsafe else learned_threshold
    risk = _clamp(0.75 * feature_risk + 0.25 * model_risk + (0.08 if is_failsafe else 0))
    if risk >= threshold:
        return risk, "BLOCK"
    if risk >= threshold - 0.22:
        return risk, "CHALLENGE"
    return risk, "APPROVE"


def red_team_sample(count: int = 5000) -> dict[str, float | int]:
    rng = random.Random(42)
    is_failsafe = get_state("failsafe_enabled", "false") == "true"
    profiles: list[tuple[float, float, float, float, float]] = []
    for _ in range(count):
        velocity = rng.uniform(0.72, 1.0)
        biometrics = rng.uniform(0.0, 0.35)
        proxy = "TOR" if rng.random() < 0.75 else "NONE"
        amount = rng.uniform(10, 5000)
        profiles.append(
            (math.log1p(amount), velocity, biometrics, 1.0 if proxy == "TOR" else 0.0, amount)
        )
    anomaly_scores = (
        -_local_model.decision_function([profile[:4] for profile in profiles])
        if _local_model is not None
        else [0.0] * count
    )
    learned_threshold = float(get_state("learned_risk_threshold", "0.72"))
    threshold = min(learned_threshold, 0.58) if is_failsafe else learned_threshold
    detected = 0
    supervised_probabilities = (
        _feedback_model.predict_proba([profile[:4] for profile in profiles])[:, 1]
        if _feedback_model is not None
        else None
    )
    for index, ((log_amount, velocity, biometrics, proxy_risk, amount), anomaly) in enumerate(
        zip(profiles, anomaly_scores)
    ):
        model_risk = _clamp((float(anomaly) - 0.02) / 0.16)
        feature_risk = (
            0.42 * velocity
            + 0.36 * (1.0 - biometrics)
            + 0.17 * proxy_risk
            + 0.05 * _clamp(log_amount / math.log1p(10000))
        )
        if _local_model is None:
            model_risk = feature_risk
        if supervised_probabilities is not None:
            model_risk = _clamp(
                0.35 * model_risk + 0.65 * float(supervised_probabilities[index])
            )
        risk = _clamp(
            0.75 * feature_risk
            + 0.25 * model_risk
            + (0.08 if is_failsafe else 0)
        )
        recommendation = "BLOCK" if risk >= threshold else "CHALLENGE" if risk >= threshold - 0.22 else "APPROVE"
        detected += recommendation == "BLOCK" or risk >= 0.58
    return {"profiles_tested": count, "flagged": detected, "detection_rate": detected / count}