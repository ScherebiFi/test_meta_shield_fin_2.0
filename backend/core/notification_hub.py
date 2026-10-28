from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
from pathlib import Path
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet, InvalidToken

from backend.db.database import connect


class NotificationConfigurationError(RuntimeError):
    pass


class NotificationDeliveryError(RuntimeError):
    pass


def _fernet() -> Fernet:
    key = os.getenv("CONTACTS_ENCRYPTION_KEY", "")
    if not key:
        raise NotificationConfigurationError("CONTACTS_ENCRYPTION_KEY n'est pas configurée.")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise NotificationConfigurationError("CONTACTS_ENCRYPTION_KEY est invalide.") from error


def store_contact(
    customer_id: str,
    phone: str | None,
    telegram_chat_id: str | None,
    fcm_token: str | None,
) -> None:
    fernet = _fernet()
    encrypted = [
        fernet.encrypt(value.encode("utf-8")).decode("ascii") if value else None
        for value in (phone, telegram_chat_id, fcm_token)
    ]
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        db.execute(
            """INSERT INTO customer_contacts
            (customer_id, phone_encrypted, telegram_chat_encrypted, fcm_token_encrypted, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(customer_id) DO UPDATE SET
            phone_encrypted = COALESCE(excluded.phone_encrypted, customer_contacts.phone_encrypted),
            telegram_chat_encrypted = COALESCE(excluded.telegram_chat_encrypted, customer_contacts.telegram_chat_encrypted),
            fcm_token_encrypted = COALESCE(excluded.fcm_token_encrypted, customer_contacts.fcm_token_encrypted),
            updated_at = excluded.updated_at""",
            (customer_id, *encrypted, now),
        )


def _get_destination(customer_id: str, channel: str) -> str:
    columns = {
        "SMS": "phone_encrypted",
        "TELEGRAM": "telegram_chat_encrypted",
        "FCM": "fcm_token_encrypted",
    }
    with connect() as db:
        row = db.execute(
            f"SELECT {columns[channel]} AS destination FROM customer_contacts WHERE customer_id = ?",
            (customer_id,),
        ).fetchone()
    if row is None or not row["destination"]:
        raise NotificationConfigurationError(
            f"Aucune destination {channel} enregistrée pour ce client."
        )
    try:
        return _fernet().decrypt(row["destination"].encode("ascii")).decode("utf-8")
    except InvalidToken as error:
        raise NotificationConfigurationError(
            "La clé de chiffrement des coordonnées a changé ou est incorrecte."
        ) from error


def _fcm_access_token(service_account_path: str) -> tuple[str, str]:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    credentials = service_account.Credentials.from_service_account_file(
        service_account_path,
        scopes=["https://www.googleapis.com/auth/firebase.messaging"],
    )
    credentials.refresh(Request())
    return credentials.token, credentials.project_id


async def _deliver(channel: str, customer_id: str, message: str) -> None:
    destination = _get_destination(customer_id, channel)
    timeout = httpx.Timeout(10, connect=5)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if channel == "TELEGRAM":
            token = os.getenv("TELEGRAM_BOT_TOKEN", "")
            if not token:
                raise NotificationConfigurationError("TELEGRAM_BOT_TOKEN n'est pas configuré.")
            response = await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": destination, "text": message, "disable_web_page_preview": True},
            )
            response.raise_for_status()
            payload = response.json()
            if not payload.get("ok"):
                raise NotificationDeliveryError("Telegram a refusé la notification.")
            return

        if channel == "SMS":
            account_sid = os.getenv("TWILIO_ACCOUNT_SID", "")
            auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
            sender = os.getenv("TWILIO_FROM_NUMBER", "")
            if not all((account_sid, auth_token, sender)):
                raise NotificationConfigurationError(
                    "TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN et TWILIO_FROM_NUMBER sont requis."
                )
            response = await client.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
                data={"To": destination, "From": sender, "Body": message},
                auth=(account_sid, auth_token),
            )
            response.raise_for_status()
            return

        account_path = os.getenv("FCM_SERVICE_ACCOUNT_FILE", "")
        if not account_path or not Path(account_path).is_file():
            raise NotificationConfigurationError(
                "FCM_SERVICE_ACCOUNT_FILE doit désigner un compte de service Firebase."
            )
        try:
            access_token, project_id = await asyncio.to_thread(
                _fcm_access_token, account_path
            )
        except (OSError, ValueError) as error:
            raise NotificationConfigurationError(
                "Impossible de charger le compte de service Firebase."
            ) from error
        response = await client.post(
            f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "message": {
                    "token": destination,
                    "notification": {"title": "Meta ShieldFin — Vérification", "body": message},
                }
            },
        )
        response.raise_for_status()


async def create_challenge(transaction_id: str, customer_id: str, channel: str) -> dict[str, str]:
    challenge_id = f"CH-{uuid4().hex[:10].upper()}"
    code = f"{secrets.randbelow(1_000_000):06d}"
    pepper = os.getenv("OTP_PEPPER") or os.getenv("AUTH_SECRET_KEY", "")
    if len(pepper) < 32:
        raise NotificationConfigurationError("Une clé OTP_PEPPER de 32 caractères est requise.")
    code_hash = hmac.new(pepper.encode(), code.encode(), hashlib.sha256).hexdigest()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=5)
    with connect() as db:
        recent = db.execute(
            """SELECT COUNT(*) FROM challenges WHERE customer_id = ?
            AND created_at >= ?""",
            (customer_id, (now - timedelta(minutes=15)).isoformat()),
        ).fetchone()[0]
        if recent >= 3:
            raise NotificationDeliveryError(
                "Limite atteinte : maximum de trois défis par client sur quinze minutes."
            )
        db.execute(
            """INSERT INTO challenges
            (id, transaction_id, customer_id, channel, status, code_hash, attempts, created_at, expires_at)
            VALUES (?, ?, ?, ?, 'DISPATCHING', ?, 0, ?, ?)""",
            (
                challenge_id,
                transaction_id,
                customer_id,
                channel,
                code_hash,
                now.isoformat(),
                expires.isoformat(),
            ),
        )
    try:
        await _deliver(
            channel,
            customer_id,
            f"Votre code de vérification Meta ShieldFin est {code}. Il expire dans cinq minutes. "
            "Ne le communiquez à personne.",
        )
    except (NotificationConfigurationError, NotificationDeliveryError, httpx.HTTPError):
        with connect() as db:
            db.execute("UPDATE challenges SET status = 'DELIVERY_FAILED' WHERE id = ?", (challenge_id,))
        raise
    with connect() as db:
        db.execute("UPDATE challenges SET status = 'PENDING' WHERE id = ?", (challenge_id,))
    return {
        "id": challenge_id,
        "status": "SENT",
        "channel": channel,
        "expires_at": expires.isoformat(),
        "delivery_note": f"Défi transmis au fournisseur {channel}.",
    }


def verify_challenge(challenge_id: str, code: str) -> dict[str, str | bool]:
    pepper = os.getenv("OTP_PEPPER") or os.getenv("AUTH_SECRET_KEY", "")
    supplied_hash = hmac.new(pepper.encode(), code.encode(), hashlib.sha256).hexdigest()
    now = datetime.now(timezone.utc)
    with connect() as db:
        challenge = db.execute(
            "SELECT * FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
        if challenge is None:
            return {"valid": False, "reason": "Défi introuvable."}
        if challenge["status"] != "PENDING":
            return {"valid": False, "reason": "Défi déjà traité ou expiré."}
        if now > datetime.fromisoformat(challenge["expires_at"]):
            db.execute("UPDATE challenges SET status = 'EXPIRED' WHERE id = ?", (challenge_id,))
            return {"valid": False, "reason": "Défi expiré."}
        attempts = challenge["attempts"] + 1
        if attempts > 5:
            db.execute("UPDATE challenges SET status = 'LOCKED', attempts = ? WHERE id = ?", (attempts, challenge_id))
            return {"valid": False, "reason": "Nombre maximal de tentatives atteint."}
        valid = hmac.compare_digest(supplied_hash, challenge["code_hash"])
        status = "VERIFIED" if valid else ("LOCKED" if attempts >= 5 else "PENDING")
        db.execute(
            "UPDATE challenges SET status = ?, attempts = ? WHERE id = ?",
            (status, attempts, challenge_id),
        )
        if valid:
            db.execute(
                "UPDATE transactions SET status = 'APPROVED', recommendation = 'APPROVE', "
                "updated_at = ? WHERE id = ?",
                (now.isoformat(), challenge["transaction_id"]),
            )
    return {"valid": valid, "reason": "Code validé." if valid else "Code incorrect."}