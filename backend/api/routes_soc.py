from __future__ import annotations

import httpx
import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from backend.core.failsafe_engine import is_enabled, set_enabled
from backend.core.llama_agent import cloud_available
from backend.core.notification_hub import (
    NotificationConfigurationError,
    NotificationDeliveryError,
    create_challenge,
)
from backend.core.feedback_learning import record_review
from backend.core.ml_detector import (
    feedback_model_status,
    local_model_status,
    train_isolation_forest,
)
from backend.db.audit_logger import record, verify_chain
from backend.db.database import connect


router = APIRouter(prefix="/api", tags=["soc"])


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_id: str = Field(min_length=3, max_length=64)
    action: str = Field(pattern=r"^(APPROVE|CHALLENGE|BLOCK)$")
    channel: str = Field(default="FCM", pattern=r"^(FCM|TELEGRAM|SMS)$")


class FailSafeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class SearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=500)


@router.get("/system/status")
def system_status() -> dict[str, object]:
    with connect() as db:
        totals = db.execute(
            """SELECT COUNT(*) AS analyzed,
            SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked,
            SUM(CASE WHEN status = 'CHALLENGE_REQUIRED' THEN 1 ELSE 0 END) AS challenges
            FROM transactions"""
        ).fetchone()
        active_challenges = db.execute(
            "SELECT COUNT(*) FROM challenges WHERE status = 'PENDING'"
        ).fetchone()[0]
    return {
        "cloud": "configured" if cloud_available() else "unconfigured",
        "failsafe_enabled": is_enabled(),
        "transactions_analyzed": totals["analyzed"] or 0,
        "critical_alerts": totals["blocked"] or 0,
        "active_challenges": active_challenges,
        "feedback_model": feedback_model_status(),
        "baseline_model": local_model_status(),
    }


@router.post("/soc/action")
async def transaction_action(
    payload: ActionInput, request: Request, background_tasks: BackgroundTasks
) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        transaction = db.execute(
            "SELECT * FROM transactions WHERE id = ?", (payload.transaction_id,)
        ).fetchone()
        if transaction is None:
            raise HTTPException(status_code=404, detail="Transaction introuvable.")
        if payload.action == "CHALLENGE":
            try:
                challenge = await create_challenge(
                    transaction["id"], transaction["customer_id"], payload.channel
                )
            except NotificationConfigurationError as error:
                raise HTTPException(status_code=503, detail=str(error)) from error
            except NotificationDeliveryError as error:
                raise HTTPException(status_code=429, detail=str(error)) from error
            except httpx.HTTPError as error:
                raise HTTPException(
                    status_code=502,
                    detail="Le fournisseur n'a pas confirmé la livraison du défi.",
                ) from error
            status = "CHALLENGE_REQUIRED"
        else:
            challenge = None
            status = "APPROVED" if payload.action == "APPROVE" else "BLOCKED"
        db.execute(
            "UPDATE transactions SET status = ?, recommendation = ?, updated_at = ? WHERE id = ?",
            (status, payload.action, now, payload.transaction_id),
        )
        item = dict(db.execute(
            "SELECT * FROM transactions WHERE id = ?", (payload.transaction_id,)
        ).fetchone())
    actor = "HUMAN-SOC-OP" if payload.action in {"APPROVE", "BLOCK"} else "AI-ORCHESTRATED"
    record(actor, f"TRANSACTION_{payload.action}", payload.transaction_id, {"status": status})
    if payload.action in {"APPROVE", "BLOCK"}:
        record_review(
            payload.transaction_id,
            1 if payload.action == "BLOCK" else 0,
            request.state.operator["email"],
            actor,
        )
    await request.app.state.broadcast({"type": "transaction_updated", "data": item})
    if payload.action in {"APPROVE", "CHALLENGE"}:
        background_tasks.add_task(train_isolation_forest)
    return {"transaction": item, "challenge": challenge}


@router.post("/system/failsafe-toggle")
async def toggle_failsafe(payload: FailSafeInput, request: Request) -> dict[str, object]:
    enabled = set_enabled(payload.enabled)
    record(
        "HUMAN-CRITICAL-ACTION",
        "FAILSAFE_ENABLED" if enabled else "FAILSAFE_DISABLED",
        "SYSTEM",
        {"failsafe_enabled": enabled},
    )
    await request.app.state.broadcast({"type": "failsafe", "enabled": enabled})
    return {"failsafe_enabled": enabled, "threshold": 0.58 if enabled else 0.72}


@router.get("/audit")
def list_audit(limit: int = 100) -> list[dict[str, object]]:
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=422, detail="limit doit être compris entre 1 et 500.")
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    entries = []
    for row in rows:
        entry = dict(row)
        entry["details"] = json.loads(entry["details"])
        entries.append(entry)
    return entries


@router.get("/audit/integrity")
def audit_integrity() -> dict[str, object]:
    return verify_chain()


@router.post("/registry/search")
def semantic_registry_search(payload: SearchInput) -> dict[str, object]:
    query = payload.query.strip()
    if not query or len(query) > 500:
        raise HTTPException(status_code=422, detail="La requête doit contenir 1 à 500 caractères.")
    normalized = query.lower()
    conditions = []
    params: list[object] = []
    if any(word in normalized for word in ("bloquée", "bloque", "blocked", "block")):
        conditions.append("status = ?")
        params.append("BLOCKED")
    if any(word in normalized for word in ("tor", "proxy")):
        conditions.append("proxy_type = ?")
        params.append("TOR")
    import re
    score_match = re.search(r"(?:score|risque).{0,20}(?:supérieur|greater|>)\s*(?:à\s*)?([0-9]+(?:[.,][0-9]+)?)", normalized)
    if score_match:
        conditions.append("risk_score >= ?")
        params.append(float(score_match.group(1).replace(",", ".")))
    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = "SELECT * FROM transactions" + where + " ORDER BY created_at DESC LIMIT 100"
    with connect() as db:
        rows = db.execute(sql, params).fetchall()
    return {
        "query": query,
        "sql": sql,
        "results": [dict(row) for row in rows],
        "notice": "Interprétation locale par filtres sûrs; aucun SQL arbitraire ou modèle cloud n'est exécuté.",
    }