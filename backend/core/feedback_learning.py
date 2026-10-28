from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from backend.core.ml_detector import update_feedback_model
from backend.db.audit_logger import record
from backend.db.database import connect, get_state


def load_feedback_model() -> dict[str, object]:
    with connect() as db:
        rows = db.execute(
            """SELECT f.features, f.label FROM reviewed_feedback f
            ORDER BY f.created_at"""
        ).fetchall()
    examples = []
    for row in rows:
        example = json.loads(row["features"])
        example["label"] = row["label"]
        examples.append(example)
    return update_feedback_model(examples)


def record_review(
    transaction_id: str, label: int, reviewed_by: str, actor: str
) -> dict[str, object]:
    with connect() as db:
        transaction = db.execute(
            "SELECT * FROM transactions WHERE id = ?", (transaction_id,)
        ).fetchone()
        if transaction is None:
            raise ValueError(f"Transaction {transaction_id} introuvable.")
        features = {
            "amount": transaction["amount"],
            "velocity_score": transaction["velocity_score"],
            "biometric_score": transaction["biometric_score"],
            "proxy_type": transaction["proxy_type"],
        }
        db.execute(
            """INSERT INTO reviewed_feedback
            (transaction_id, features, label, reviewed_by, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(transaction_id) DO UPDATE SET
            features = excluded.features, label = excluded.label,
            reviewed_by = excluded.reviewed_by, created_at = excluded.created_at""",
            (
                transaction_id,
                json.dumps(features, sort_keys=True, separators=(",", ":")),
                label,
                reviewed_by,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        rows = db.execute(
            """SELECT features, label FROM reviewed_feedback ORDER BY created_at"""
        ).fetchall()
    examples = []
    for row in rows:
        example = json.loads(row["features"])
        example["label"] = row["label"]
        examples.append(example)
    result = update_feedback_model(examples)
    record(
        actor,
        "HUMAN_REVIEW_RECORDED",
        transaction_id,
        {
            "label": "SUSPICIOUS" if label else "LEGITIMATE",
            "reviewed_by": reviewed_by,
            "training_labels": result["labels"],
            "model_trained": result["trained"],
        },
    )
    if result["trained"]:
        _propose_threshold(result, reviewed_by)
    return result


def _propose_threshold(metrics: dict[str, object], reviewed_by: str) -> None:
    threshold = round(float(metrics["threshold"]), 2)
    current = float(get_state("learned_risk_threshold", "0.72"))
    if abs(current - threshold) < 0.03:
        return
    with connect() as db:
        pending = db.execute(
            """SELECT id FROM rules WHERE origin = 'HUMAN_FEEDBACK_LEARNING'
            AND status = 'PENDING_REVIEW' AND payload = ? LIMIT 1""",
            (json.dumps({"risk_threshold": threshold}, sort_keys=True),),
        ).fetchone()
        if pending:
            return
        rule_id = f"RULE-{uuid4().hex[:8].upper()}"
        description = (
            f"Seuil de risque proposé: {threshold:.2f} "
            f"(validation croisée F1={float(metrics['cross_validated_f1']):.2f})"
        )
        db.execute(
            """INSERT INTO rules(id, description, origin, status, created_at, payload)
            VALUES (?, ?, 'HUMAN_FEEDBACK_LEARNING', 'PENDING_REVIEW', ?, ?)""",
            (
                rule_id,
                description,
                datetime.now(timezone.utc).isoformat(),
                json.dumps({"risk_threshold": threshold}, sort_keys=True),
            ),
        )
    record(
        "AGENT-SELF-HEALING",
        "RISK_THRESHOLD_PROPOSED",
        rule_id,
        {
            "risk_threshold": threshold,
            "cross_validated_f1": metrics["cross_validated_f1"],
            "source": "human feedback",
            "reviewed_by": reviewed_by,
        },
    )


def approve_learned_rule(rule_id: str, reviewed_by: str) -> float:
    with connect() as db:
        rule = db.execute(
            """SELECT payload FROM rules
            WHERE id = ? AND origin IN ('HUMAN_FEEDBACK_LEARNING', 'FEDERATED_RECOMMENDATION')
            AND status = 'PENDING_REVIEW'""",
            (rule_id,),
        ).fetchone()
        if rule is None:
            raise ValueError("Règle d'apprentissage en attente introuvable.")
        payload = json.loads(rule["payload"])
        threshold = float(payload["risk_threshold"])
        if not 0.3 <= threshold <= 0.9:
            raise ValueError("Seuil appris hors des limites autorisées.")
        db.execute(
            """UPDATE rules SET status = 'SUPERSEDED'
            WHERE origin IN ('HUMAN_FEEDBACK_LEARNING', 'FEDERATED_RECOMMENDATION')
            AND status = 'ACTIVE'"""
        )
        db.execute(
            "UPDATE rules SET status = 'ACTIVE' WHERE id = ?", (rule_id,)
        )
        db.execute(
            """INSERT INTO app_state(key, value) VALUES('learned_risk_threshold', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (f"{threshold:.2f}",),
        )
    record(
        "HUMAN-SOC-SENIOR",
        "LEARNED_RULE_APPROVED",
        rule_id,
        {"risk_threshold": threshold, "reviewed_by": reviewed_by},
    )
    return threshold
