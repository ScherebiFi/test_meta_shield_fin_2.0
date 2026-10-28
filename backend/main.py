from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from typing import AsyncIterator
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from backend.api.routes_aml import router as aml_router
from backend.api.routes_client_hub import router as client_hub_router
from backend.api.routes_self_healing import router as self_healing_router
from backend.api.routes_soc import router as soc_router
from backend.api.routes_transactions import router as transactions_router
from backend.api.routes_zk import router as zk_router
from backend.db.database import init_db
from backend.core.feedback_learning import load_feedback_model
from backend.core.ml_detector import train_isolation_forest
from backend.security.operator_auth import (
    SESSION_COOKIE,
    authenticate_token,
    bootstrap_operator,
    router as auth_router,
)


FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    bootstrap_operator()
    train_isolation_forest()
    load_feedback_model()
    yield


class ConnectionManager:
    def __init__(self) -> None:
        self.connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.connections.discard(websocket)

    async def broadcast(self, message: dict[str, object]) -> None:
        disconnected: list[WebSocket] = []
        for connection in tuple(self.connections):
            try:
                await connection.send_json(message)
            except (OSError, RuntimeError, WebSocketDisconnect):
                disconnected.append(connection)
        for connection in disconnected:
            self.disconnect(connection)


manager = ConnectionManager()
app = FastAPI(
    title="Meta ShieldFin",
    description="Console SOC de démonstration pour la surveillance et l'investigation de transactions.",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.broadcast = manager.broadcast


class OperatorAuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path
        if path in {
            "/health",
            "/api/auth/login",
            "/api/federated/receive",
            "/api/client-hub/respond",
        } or path.startswith("/assets/") or path == "/":
            return await call_next(request)
        if path.startswith("/api/"):
            token = request.cookies.get(SESSION_COOKIE)
            authorization = request.headers.get("authorization", "")
            if not token and authorization.startswith("Bearer "):
                token = authorization.removeprefix("Bearer ").strip()
            operator = authenticate_token(token) if token else None
            is_ingest = path == "/api/transactions" and request.method == "POST"
            supplied_key = request.headers.get("x-api-key", "")
            expected_key = os.getenv("TRANSACTION_INGESTION_API_KEY", "")
            service_auth = (
                is_ingest
                and len(expected_key) >= 32
                and secrets.compare_digest(supplied_key, expected_key)
            )
            if operator is None and not service_auth:
                return JSONResponse({"detail": "Authentification opérateur requise."}, status_code=401)
            if operator is not None:
                request.state.operator = operator
                senior_paths = (
                    path == "/api/system/failsafe-toggle"
                    or path.startswith("/api/self-healing/rules/")
                    or path == "/api/federated/sync"
                    or path == "/api/client-hub/contacts"
                    or path.startswith("/api/auth/operators")
                )
                if senior_paths and operator["role"] != "SENIOR":
                    return JSONResponse({"detail": "Rôle analyste senior requis."}, status_code=403)
            elif service_auth:
                request.state.operator = {"email": "transaction-ingestion-service", "role": "SERVICE"}
        return await call_next(request)


app.add_middleware(OperatorAuthenticationMiddleware)

allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

app.include_router(transactions_router)
app.include_router(auth_router)
app.include_router(zk_router)
app.include_router(soc_router)
app.include_router(client_hub_router)
app.include_router(aml_router)
app.include_router(self_healing_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.websocket("/ws/live-soc")
async def live_soc(websocket: WebSocket) -> None:
    if websocket.headers.get("origin") not in allowed_origins:
        await websocket.close(code=4403, reason="Origin not allowed")
        return
    token = websocket.cookies.get(SESSION_COOKIE)
    if not token or authenticate_token(token) is None:
        await websocket.close(code=4401, reason="Authentication required")
        return
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR), name="frontend-assets")


@app.get("/")
def home() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")