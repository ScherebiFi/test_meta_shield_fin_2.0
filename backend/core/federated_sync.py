from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from backend.core.ml_detector import feedback_model_status
from backend.db.audit_logger import record
from backend.db.database import connect


class FederationConfigurationError(RuntimeError):
    pass


def _configured_peers() -> list[dict[str, str]]:
    try:
        peers = json.loads(os.getenv("FEDERATED_PEERS", "[]"))
    except json.JSONDecodeError as error:
        raise FederationConfigurationError("FEDERATED_PEERS doit être un tableau JSON.") from error
    if not isinstance(peers, list):
        raise FederationConfigurationError("FEDERATED_PEERS doit être un tableau JSON.")
    for peer in peers:
        if (
            not isinstance(peer, dict)
            or not isinstance(peer.get("id"), str)
            or not isinstance(peer.get("url"), str)
            or not peer["url"].startswith("https://")
            or len(str(peer.get("secret", ""))) < 32
        ):
            raise FederationConfigurationError(
                "Chaque partenaire exige id, URL HTTPS et secret HMAC de 32 caractères."
            )
    return peers


def _trusted_peers() -> dict[str, str]:
    try:
        peers = json.loads(os.getenv("FEDERATION_TRUSTED_PEERS", "{}"))
    except json.JSONDecodeError as error:
        raise FederationConfigurationError(
            "FEDERATION_TRUSTED_PEERS doit être un objet JSON."
        ) from error
    if not isinstance(peers, dict) or any(
        not isinstance(peer_id, str) or not isinstance(secret, str) or len(secret) < 32
        for peer_id, secret in peers.items()
    ):
        raise FederationConfigurationError(
            "Les secrets des partenaires doivent comporter au moins 32 caractères."
        )
    return peers


def _local_aggregate() -> dict[str, object]:
    with connect() as db:
        rows = db.execute(
            "SELECT COUNT(*) AS count, SUM(label) AS suspicious FROM reviewed_feedback"
        ).fetchone()
    count = int(rows["count"] or 0)
    if count < 20:
        return {"cohort_size": count, "eligible": False}
    status = feedback_model_status()
    if not status["trained"]:
        return {"cohort_size": count, "eligible": False}
    return {
        "cohort_size": count,
        "eligible": True,
        "suspicious_count": int(rows["suspicious"] or 0),
        "threshold": status["metrics"]["threshold"],
        "cross_validated_f1": status["metrics"]["cross_validated_f1"],
    }


def _signature(secret: str, timestamp: str, nonce: str, body: bytes) -> str:
    signed = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()


async def synchronize() -> dict[str, object]:
    peers = _configured_peers()
    if not peers:
        raise FederationConfigurationError("Aucun partenaire HTTPS n'est défini dans FEDERATED_PEERS.")
    node_id = os.getenv("FEDERATION_NODE_ID", "")
    if not node_id:
        raise FederationConfigurationError("FEDERATION_NODE_ID doit identifier cette instance.")
    aggregate = _local_aggregate()
    payload = {
        "version": 1,
        "peer_id": node_id,
        "sent_at": int(time.time()),
        "nonce": uuid4().hex,
        "aggregate": aggregate,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    results = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(10, connect=5)) as client:
        for peer in peers:
            timestamp = str(payload["sent_at"])
            signature = _signature(peer["secret"], timestamp, payload["nonce"], body)
            try:
                response = await client.post(
                    peer["url"].rstrip("/") + "/api/federated/receive",
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Federation-Peer": node_id,
                        "X-Federation-Timestamp": timestamp,
                        "X-Federation-Nonce": payload["nonce"],
                        "X-Federation-Signature": signature,
                    },
                )
                response.raise_for_status()
                results.append({"peer_id": peer["id"], "status": "synchronized"})
            except httpx.HTTPError as error:
                results.append(
                    {
                        "peer_id": peer["id"],
                        "status": "failed",
                        "error": str(error)[:300],
                    }
                )
    success_count = sum(result["status"] == "synchronized" for result in results)
    record(
        "AGENT-SELF-HEALING",
        "FEDERATED_SYNC_COMPLETED",
        node_id,
        {
            "partners": len(peers),
            "successful": success_count,
            "aggregate_eligible": aggregate["eligible"],
        },
    )
    return {
        "status": "completed" if success_count == len(peers) else "partial_failure",
        "aggregate": aggregate,
        "partners": results,
    }


async def receive_aggregate(headers: dict[str, str], body: bytes) -> dict[str, object]:
    peers = _trusted_peers()
    peer_id = headers.get("x-federation-peer", "")
    timestamp = headers.get("x-federation-timestamp", "")
    nonce = headers.get("x-federation-nonce", "")
    signature = headers.get("x-federation-signature", "")
    secret = peers.get(peer_id)
    if not secret:
        raise PermissionError("Partenaire fédéré non autorisé.")
    try:
        sent_at = int(timestamp)
        payload = json.loads(body)
    except (ValueError, json.JSONDecodeError) as error:
        raise ValueError("En-têtes ou corps fédéré invalides.") from error
    if abs(int(time.time()) - sent_at) > 300:
        raise TimeoutError("Signature fédérée expirée.")
    if not nonce or len(nonce) > 128 or len(body) > 16_384:
        raise ValueError("Nonce ou agrégat fédéré invalide.")
    expected = _signature(secret, timestamp, nonce, body)
    if not hmac.compare_digest(expected, signature):
        raise PermissionError("Signature HMAC invalide.")
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or payload.get("peer_id") != peer_id
        or payload.get("nonce") != nonce
        or payload.get("sent_at") != sent_at
    ):
        raise ValueError("Enveloppe fédérée non conforme.")
    aggregate = payload.get("aggregate")
    if not isinstance(aggregate, dict):
        raise ValueError("Agrégat fédéré invalide.")
    eligible = aggregate.get("eligible") is True
    if eligible:
        threshold = aggregate.get("threshold")
        cohort_size = aggregate.get("cohort_size")
        if (
            not isinstance(threshold, (float, int))
            or not 0.3 <= threshold <= 0.9
            or not isinstance(cohort_size, int)
            or cohort_size < 20
        ):
            raise ValueError("Seuil ou taille de cohorte fédérée hors limites.")
        proposal = {
            "risk_threshold": round(float(threshold), 2),
            "partner": peer_id,
            "cohort_size": cohort_size,
        }
        with connect() as db:
            db.execute(
                "INSERT INTO federated_nonces(peer_id, nonce, created_at) VALUES (?, ?, ?)",
                (peer_id, nonce, datetime.now(timezone.utc).isoformat()),
            )
            rule_id = f"RULE-{uuid4().hex[:8].upper()}"
            db.execute(
                """INSERT INTO rules(id, description, origin, status, created_at, payload)
                VALUES (?, ?, 'FEDERATED_RECOMMENDATION', 'PENDING_REVIEW', ?, ?)""",
                (
                    rule_id,
                    f"Proposition du partenaire {peer_id}: seuil {proposal['risk_threshold']:.2f}",
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(proposal, sort_keys=True),
                ),
            )
    else:
        with connect() as db:
            db.execute(
                "INSERT INTO federated_nonces(peer_id, nonce, created_at) VALUES (?, ?, ?)",
                (peer_id, nonce, datetime.now(timezone.utc).isoformat()),
            )
        rule_id = None
    record(
        "FEDERATED-PEER",
        "FEDERATED_AGGREGATE_RECEIVED",
        peer_id,
        {
            "eligible": eligible,
            "cohort_size": aggregate.get("cohort_size", 0),
            "rule_id": rule_id,
        },
    )
    return {
        "accepted": True,
        "eligible": eligible,
        "rule_id": rule_id,
        "message": "Agrégat reçu; toute proposition nécessite une approbation humaine.",
    }
