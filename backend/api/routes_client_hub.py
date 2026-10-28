from __future__ import annotations

import httpx
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.core.notification_hub import (
    NotificationConfigurationError,
    NotificationDeliveryError,
    create_challenge,
    store_contact,
    verify_challenge,
)
from backend.core.feedback_learning import record_review
from backend.core.ml_detector import train_isolation_forest
from backend.db.audit_logger import record
from backend.db.database import connect


router = APIRouter(prefix="/api/client-hub", tags=["client-hub"])


class ChallengeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_id: str = Field(min_length=3, max_length=64)
    channel: str = Field(pattern=r"^(FCM|TELEGRAM|SMS)$")


class ChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=3, max_length=64)
    code: str = Field(pattern=r"^[0-9]{6}$")
    biometric_score: float = Field(default=0, ge=0, le=1)


class ManualDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_id: str = Field(min_length=3, max_length=64)
    decision: str = Field(pattern=r"^(APPROVE|BLOCK)$")


class ContactInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    phone: str | None = Field(default=None, pattern=r"^\+[1-9][0-9]{7,14}$")
    telegram_chat_id: str | None = Field(default=None, min_length=1, max_length=64)
    fcm_token: str | None = Field(default=None, min_length=20, max_length=4096)

    @model_validator(mode="after")
    def at_least_one_channel(self) -> "ContactInput":
        if not any((self.phone, self.telegram_chat_id, self.fcm_token)):
            raise ValueError("Au moins une destination de notification est requise.")
        return self


@router.get("/challenges")
def list_challenges() -> list[dict[str, object]]:
    with connect() as db:
        rows = db.execute(
            """SELECT id, transaction_id, customer_id, channel, status, attempts,
            created_at, expires_at FROM challenges ORDER BY created_at DESC LIMIT 100"""
        ).fetchall()
    return [dict(row) for row in rows]


@router.get("/contacts")
def list_contact_ids() -> list[dict[str, str]]:
    with connect() as db:
        rows = db.execute(
            "SELECT customer_id, updated_at FROM customer_contacts ORDER BY customer_id"
        ).fetchall()
    return [dict(row) for row in rows]


@router.put("/contacts")
def update_contact(payload: ContactInput) -> dict[str, str]:
    try:
        store_contact(
            payload.customer_id, payload.phone, payload.telegram_chat_id, payload.fcm_token
        )
    except NotificationConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {"customer_id": payload.customer_id, "status": "stored_encrypted"}


@router.post("/send-challenge", status_code=201)
async def send_challenge(payload: ChallengeInput) -> dict[str, str]:
    with connect() as db:
        transaction = db.execute(
            "SELECT id, customer_id FROM transactions WHERE id = ?", (payload.transaction_id,)
        ).fetchone()
    if transaction is None:
        raise HTTPException(status_code=404, detail="Transaction introuvable.")
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
            status_code=502, detail="Le fournisseur n'a pas confirmé la livraison du défi."
        ) from error
    record("AI-ORCHESTRATED", "CHALLENGE_CREATED", challenge["id"], {"channel": payload.channel})
    return challenge


@router.post("/respond")
def respond_to_challenge(
    payload: ChallengeResponse, background_tasks: BackgroundTasks
) -> dict[str, object]:
    result = verify_challenge(payload.challenge_id, payload.code)
    record(
        "CLIENT-2FA",
        "CHALLENGE_VERIFIED" if result["valid"] else "CHALLENGE_REJECTED",
        payload.challenge_id,
        {"biometric_score": payload.biometric_score, "valid": result["valid"]},
    )
    if result["valid"]:
        with connect() as db:
            challenge = db.execute(
                "SELECT transaction_id FROM challenges WHERE id = ?", (payload.challenge_id,)
            ).fetchone()
            transaction_id = challenge["transaction_id"] if challenge else payload.challenge_id
        record(
            "SYSTEM-LOCAL",
            "TRANSACTION_RELEASED_AFTER_2FA",
            transaction_id,
            {"decision": "OTP_VALIDATED", "biometric_signal": payload.biometric_score},
        )
        background_tasks.add_task(train_isolation_forest)
    return result


@router.post("/manual-decision")
def manual_decision(
    payload: ManualDecision, request: Request, background_tasks: BackgroundTasks
) -> dict[str, str]:
    transaction_id = payload.transaction_id
    decision = payload.decision
    with connect() as db:
        cursor = db.execute(
            "UPDATE transactions SET status = ?, recommendation = ?, updated_at = ? WHERE id = ?",
            (
                "APPROVED" if decision == "APPROVE" else "BLOCKED",
                decision,
                datetime.now(timezone.utc).isoformat(),
                transaction_id,
            ),
        )
    if not cursor.rowcount:
        raise HTTPException(status_code=404, detail="Transaction introuvable.")
    record("HUMAN-SOC-OP", f"CLIENT_HUB_{decision}", transaction_id)
    record_review(
        transaction_id,
        1 if decision == "BLOCK" else 0,
        request.state.operator["email"],
        "HUMAN-SOC-OP",
    )
    if decision == "APPROVE":
        background_tasks.add_task(train_isolation_forest)
    return {"transaction_id": transaction_id, "status": "APPROVED" if decision == "APPROVE" else "BLOCKED"}