from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from backend.core.ml_detector import assess_transaction, train_isolation_forest
from backend.db.audit_logger import record
from backend.db.database import connect


router = APIRouter(prefix="/api/transactions", tags=["transactions"])


class TransactionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    amount: float = Field(gt=0, le=10_000_000)
    currency: str = Field(default="EUR", pattern=r"^[A-Z]{3}$")
    proxy_type: str = Field(default="NONE", max_length=24)
    velocity_score: float = Field(default=0, ge=0, le=1)
    biometric_score: float = Field(default=1, ge=0, le=1)


@router.post("", status_code=201)
async def ingest_transaction(
    payload: TransactionInput, request: Request, background_tasks: BackgroundTasks
) -> dict[str, object]:
    risk, recommendation = assess_transaction(
        payload.amount, payload.velocity_score, payload.biometric_score, payload.proxy_type
    )
    transaction_id = f"TX-{uuid4().hex[:8].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    proof_hash = "0x" + hashlib.sha256(
        json.dumps(payload.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    status = {
        "BLOCK": "BLOCKED",
        "CHALLENGE": "CHALLENGE_REQUIRED",
        "APPROVE": "APPROVED",
    }[recommendation]
    with connect() as db:
        db.execute(
            """INSERT INTO transactions
            (id, customer_id, amount, currency, proxy_type, velocity_score, biometric_score,
             ml_score, risk_score, status, recommendation, proof_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                transaction_id,
                payload.customer_id,
                payload.amount,
                payload.currency,
                payload.proxy_type.upper(),
                payload.velocity_score,
                payload.biometric_score,
                risk,
                risk,
                status,
                recommendation,
                proof_hash,
                now,
                now,
            ),
        )
        item = dict(db.execute("SELECT * FROM transactions WHERE id = ?", (transaction_id,)).fetchone())
    record("SYSTEM-ML", "TRANSACTION_ANALYZED", transaction_id, {"risk_score": risk, "recommendation": recommendation})
    await request.app.state.broadcast({"type": "transaction", "data": item})
    background_tasks.add_task(train_isolation_forest)
    return item


@router.get("")
def list_transactions(limit: int = 100) -> list[dict[str, object]]:
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=422, detail="limit doit être compris entre 1 et 500.")
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM transactions ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]