from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy.exc import IntegrityError

from backend.core.self_healing_agent import approve_rule, run_red_team, veto_rule
from backend.core.federated_sync import (
    FederationConfigurationError,
    receive_aggregate,
    synchronize,
)
from backend.db.database import connect


router = APIRouter(prefix="/api", tags=["self-healing"])


@router.get("/self-healing/rules")
def list_rules() -> list[dict[str, object]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM rules ORDER BY created_at DESC").fetchall()
    rules = []
    for row in rows:
        rule = dict(row)
        rules.append(rule)
    return rules


@router.post("/self-healing/red-team-simulation")
def red_team_simulation() -> dict[str, object]:
    result = run_red_team()
    return {"status": "completed", **result}


@router.post("/federated/sync")
async def federated_sync() -> dict[str, object]:
    try:
        result = await synchronize()
    except FederationConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    if result["status"] == "partial_failure":
        raise HTTPException(status_code=502, detail=result)
    return result


@router.post("/federated/receive")
async def receive_federated_update(request: Request) -> dict[str, object]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > 16_384:
            raise HTTPException(status_code=413, detail="Agrégat fédéré trop volumineux.")
        chunks.append(chunk)
    body = b"".join(chunks)
    try:
        return await receive_aggregate(
            {key.lower(): value for key, value in request.headers.items()}, body
        )
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except TimeoutError as error:
        raise HTTPException(status_code=408, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except IntegrityError as error:
        raise HTTPException(status_code=409, detail="Nonce fédéré déjà utilisé.") from error


@router.post("/self-healing/rules/{rule_id}/veto")
def veto(rule_id: str, request: Request) -> dict[str, str]:
    if not veto_rule(rule_id, request.state.operator["email"]):
        raise HTTPException(status_code=404, detail="Règle active introuvable.")
    return {"id": rule_id, "status": "VETOED"}


@router.post("/self-healing/rules/{rule_id}/approve")
def approve(rule_id: str, request: Request) -> dict[str, object]:
    try:
        threshold = approve_rule(rule_id, request.state.operator["email"])
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return {"id": rule_id, "status": "ACTIVE", "risk_threshold": threshold}
