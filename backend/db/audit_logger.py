from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from backend.db.database import connect, json_details


GENESIS_HASH = "0" * 64


def record(actor: str, action: str, entity_id: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    safe_details = details or {}
    with connect() as db:
        previous = db.execute(
            "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else GENESIS_HASH
        serialized = json_details(safe_details)
        canonical = "|".join((created_at, actor, action, entity_id, serialized, previous_hash))
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        cursor = db.execute(
            """INSERT INTO audit_logs
            (created_at, actor, action, entity_id, details, previous_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (created_at, actor, action, entity_id, serialized, previous_hash, entry_hash),
        )
        entry_id = cursor.fetchone()["id"]
        return {
            "id": entry_id,
            "created_at": created_at,
            "actor": actor,
            "action": action,
            "entity_id": entity_id,
            "details": safe_details,
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
        }


def verify_chain() -> dict[str, Any]:
    with connect() as db:
        entries = db.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
    expected_previous = GENESIS_HASH
    for row in entries:
        if row["previous_hash"] != expected_previous:
            return {"valid": False, "checked": row["id"] - 1, "failed_entry_id": row["id"]}
        canonical = "|".join(
            (
                row["created_at"],
                row["actor"],
                row["action"],
                row["entity_id"],
                row["details"],
                row["previous_hash"],
            )
        )
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if expected_hash != row["entry_hash"]:
            return {"valid": False, "checked": row["id"] - 1, "failed_entry_id": row["id"]}
        expected_previous = row["entry_hash"]
    return {"valid": True, "checked": len(entries), "failed_entry_id": None}