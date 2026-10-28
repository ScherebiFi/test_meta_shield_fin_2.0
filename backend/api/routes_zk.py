from __future__ import annotations

import json
import subprocess
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.security.zk_proof_verifier import verify_snark


router = APIRouter(prefix="/api/zk", tags=["zk-proof"])


class ProofInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proof: dict[str, Any]
    public_signals: list[str] = Field(max_length=128)


@router.post("/verify")
def verify_proof(payload: ProofInput) -> dict[str, Any]:
    if len(json.dumps(payload.proof)) > 256_000:
        raise HTTPException(status_code=413, detail="La preuve dépasse 256 Ko.")
    try:
        return verify_snark(payload.proof, payload.public_signals)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail="snarkjs est introuvable.") from error
    except subprocess.TimeoutExpired as error:
        raise HTTPException(status_code=504, detail="La vérification ZK a dépassé 10 secondes.") from error
