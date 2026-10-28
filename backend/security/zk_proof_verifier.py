from __future__ import annotations

import hashlib
import hmac
import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def verify_integrity(public_input: str, expected_hash: str) -> dict[str, Any]:
    """Verify a SHA-256 integrity commitment; this is not a ZK-SNARK verifier."""
    actual = hashlib.sha256(public_input.encode("utf-8")).hexdigest()
    return {
        "valid": hmac.compare_digest(actual, expected_hash.removeprefix("0x").lower()),
        "scheme": "SHA-256 integrity commitment",
        "zk_snark_enabled": bool(os.getenv("ZK_VERIFICATION_KEY")),
        "note": "La vérification Groth16 nécessite une clé de vérification et snarkjs.",
    }


def verify_snark(proof: dict[str, Any], public_signals: list[str]) -> dict[str, Any]:
    key_path = os.getenv("ZK_VERIFICATION_KEY_PATH")
    if not key_path or not Path(key_path).is_file():
        raise RuntimeError("Clé de vérification ZK absente ou inaccessible.")
    if len(json.dumps(proof)) > 256_000 or len(json.dumps(public_signals)) > 64_000:
        raise ValueError("La preuve dépasse la taille maximale autorisée.")
    executable = os.getenv("SNARKJS_BIN", "snarkjs")
    with tempfile.TemporaryDirectory(prefix="shieldfin-zk-") as directory:
        proof_path = Path(directory) / "proof.json"
        signals_path = Path(directory) / "public.json"
        proof_path.write_text(json.dumps(proof), encoding="utf-8")
        signals_path.write_text(json.dumps(public_signals), encoding="utf-8")
        result = subprocess.run(
            [
                executable,
                "groth16",
                "verify",
                key_path,
                str(proof_path),
                str(signals_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    output = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode:
        return {"valid": False, "protocol": "groth16", "message": output[:500]}
    return {
        "valid": output.splitlines()[-1].strip().upper() == "OK" if output else False,
        "protocol": "groth16",
        "message": output[:500] or "Aucune confirmation du vérificateur snarkjs.",
    }