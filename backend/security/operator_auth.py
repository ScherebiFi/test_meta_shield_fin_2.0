from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from backend.db.database import connect


router = APIRouter(prefix="/api/auth", tags=["authentication"])
password_hasher = PasswordHasher()
SESSION_COOKIE = "shieldfin_session"
SESSION_DURATION = timedelta(hours=8)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class OperatorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=16, max_length=256)
    role: str = Field(pattern=r"^(ANALYST|SENIOR)$")


def _secret() -> str:
    secret = os.getenv("AUTH_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("AUTH_SECRET_KEY doit contenir au moins 32 caractères.")
    return secret


def bootstrap_operator() -> None:
    _secret()
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not email or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise RuntimeError("ADMIN_EMAIL doit être défini avec une adresse valide.")
    if len(password) < 16:
        raise RuntimeError("ADMIN_PASSWORD doit contenir au moins 16 caractères.")
    with connect() as db:
        existing = db.execute("SELECT email FROM operators LIMIT 1").fetchone()
        if existing is None:
            db.execute(
                "INSERT INTO operators(email, password_hash, role, active, created_at) "
                "VALUES (?, ?, 'SENIOR', 1, ?)",
                (
                    email,
                    password_hasher.hash(password),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


def create_session(email: str, role: str) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    expires_at = now + SESSION_DURATION
    jti = uuid4().hex
    token = jwt.encode(
        {
            "sub": email,
            "role": role,
            "iat": now,
            "exp": expires_at,
            "jti": jti,
            "iss": "meta-shieldfin",
            "aud": "meta-shieldfin-operator",
        },
        _secret(),
        algorithm="HS256",
    )
    with connect() as db:
        db.execute(
            "INSERT INTO operator_sessions(jti, email, expires_at) VALUES (?, ?, ?)",
            (jti, email, expires_at.isoformat()),
        )
    return token, expires_at.isoformat()


def authenticate_token(token: str) -> dict[str, str] | None:
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            _secret(),
            algorithms=["HS256"],
            issuer="meta-shieldfin",
            audience="meta-shieldfin-operator",
            options={"require": ["sub", "role", "exp", "jti"]},
        )
    except (jwt.InvalidTokenError, RuntimeError):
        return None
    with connect() as db:
        session = db.execute(
            """SELECT s.jti, o.email, o.role FROM operator_sessions s
            JOIN operators o ON o.email = s.email
            WHERE s.jti = ? AND s.email = ? AND s.revoked = 0 AND o.active = 1""",
            (claims["jti"], claims["sub"]),
        ).fetchone()
    if session is None:
        return None
    return {"email": session["email"], "role": session["role"], "jti": session["jti"]}


def revoke_session(jti: str) -> None:
    with connect() as db:
        db.execute("UPDATE operator_sessions SET revoked = 1 WHERE jti = ?", (jti,))


def _allow_login(ip: str) -> bool:
    now = time.time()
    with connect() as db:
        db.execute(
            """INSERT INTO auth_login_attempts(ip_address, window_started, attempts)
            VALUES (?, ?, 1)
            ON CONFLICT(ip_address) DO UPDATE SET
            attempts = CASE WHEN ? - auth_login_attempts.window_started >= 300
                THEN 1 ELSE auth_login_attempts.attempts + 1 END,
            window_started = CASE WHEN ? - auth_login_attempts.window_started >= 300
                THEN ? ELSE auth_login_attempts.window_started END""",
            (ip, now, now, now, now),
        )
        row = db.execute(
            "SELECT attempts FROM auth_login_attempts WHERE ip_address = ?", (ip,)
        ).fetchone()
        if row is None:
            raise RuntimeError("Le compteur de tentatives de connexion n'a pas été enregistré.")
        attempts = int(row["attempts"])
    return attempts <= 5


@router.post("/login")
def login(payload: LoginInput, request: Request, response: Response) -> dict[str, str]:
    client_ip = request.client.host if request.client else "unknown"
    if not _allow_login(client_ip):
        raise HTTPException(status_code=429, detail="Trop de tentatives. Réessayez dans cinq minutes.")
    email = payload.email.strip().lower()
    with connect() as db:
        operator = db.execute(
            "SELECT email, password_hash, role FROM operators WHERE email = ? AND active = 1",
            (email,),
        ).fetchone()
    valid_password = False
    if operator is not None:
        try:
            valid_password = password_hasher.verify(operator["password_hash"], payload.password)
        except (VerifyMismatchError, InvalidHashError):
            valid_password = False
    if not valid_password or operator is None:
        raise HTTPException(status_code=401, detail="Identifiants invalides.")
    with connect() as db:
        db.execute("DELETE FROM auth_login_attempts WHERE ip_address = ?", (client_ip,))
    token, expires_at = create_session(operator["email"], operator["role"])
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=os.getenv(
            "COOKIE_SECURE",
            "false" if os.getenv("APP_ENV", "development") != "production" else "true",
        ).lower() == "true",
        samesite="strict",
        max_age=int(SESSION_DURATION.total_seconds()),
        path="/",
    )
    return {"email": operator["email"], "role": operator["role"], "expires_at": expires_at}


@router.post("/logout")
def logout(request: Request, response: Response) -> dict[str, str]:
    operator = getattr(request.state, "operator", None)
    if operator:
        revoke_session(operator["jti"])
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=os.getenv(
            "COOKIE_SECURE",
            "false" if os.getenv("APP_ENV", "development") != "production" else "true",
        ).lower() == "true",
        samesite="strict",
    )
    return {"status": "logged_out"}


@router.get("/me")
def current_operator(request: Request) -> dict[str, str]:
    return request.state.operator


@router.get("/operators")
def list_operators() -> list[dict[str, str | int]]:
    with connect() as db:
        rows = db.execute(
            "SELECT email, role, active, created_at FROM operators ORDER BY email"
        ).fetchall()
    return [dict(row) for row in rows]


@router.post("/operators", status_code=201)
def create_operator(payload: OperatorInput) -> dict[str, str]:
    email = payload.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=422, detail="Adresse e-mail invalide.")
    with connect() as db:
        existing = db.execute("SELECT email FROM operators WHERE email = ?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Ce compte opérateur existe déjà.")
        db.execute(
            "INSERT INTO operators(email, password_hash, role, active, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (
                email,
                password_hasher.hash(payload.password),
                payload.role,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return {"email": email, "role": payload.role}


@router.post("/operators/{email}/deactivate")
def deactivate_operator(email: str, request: Request) -> dict[str, str]:
    email = email.strip().lower()
    if email == request.state.operator["email"]:
        raise HTTPException(status_code=409, detail="Un opérateur ne peut pas désactiver son propre compte.")
    with connect() as db:
        cursor = db.execute("UPDATE operators SET active = 0 WHERE email = ?", (email,))
    if not cursor.rowcount:
        raise HTTPException(status_code=404, detail="Compte opérateur introuvable.")
    return {"email": email, "status": "deactivated"}
