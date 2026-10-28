from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

from backend import main
from backend.db import database


class ShieldFinApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        os.environ.pop("DATABASE_URL", None)
        os.environ["APP_ENV"] = "development"
        os.environ["COOKIE_SECURE"] = "false"
        os.environ["AUTH_SECRET_KEY"] = "test-secret-key-with-at-least-32-characters"
        os.environ["ADMIN_EMAIL"] = "admin@example.test"
        os.environ["ADMIN_PASSWORD"] = "test-admin-password-more-than-16"
        os.environ["OTP_PEPPER"] = "test-otp-pepper-with-at-least-32-characters"
        os.environ["CONTACTS_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
        os.environ.pop("ZK_VERIFICATION_KEY_PATH", None)
        self.client_context = TestClient(main.app)
        self.client = self.client_context.__enter__()
        login = self.client.post(
            "/api/auth/login",
            json={"email": "admin@example.test", "password": "test-admin-password-more-than-16"},
        )
        self.assertEqual(login.status_code, 200)

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)
        database.close_engines()
        self.temp_dir.cleanup()

    def test_seeded_data_and_audit_chain(self) -> None:
        transactions = self.client.get("/api/transactions")
        self.assertEqual(transactions.status_code, 200)
        self.assertEqual(len(transactions.json()), 3)
        integrity = self.client.get("/api/audit/integrity")
        self.assertTrue(integrity.json()["valid"])
        self.assertEqual(integrity.json()["checked"], 3)

    def test_failsafe_toggle_is_audited(self) -> None:
        response = self.client.post("/api/system/failsafe-toggle", json={"enabled": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["threshold"], 0.58)
        self.assertTrue(self.client.get("/api/system/status").json()["failsafe_enabled"])
        self.assertTrue(self.client.get("/api/audit/integrity").json()["valid"])

    def test_challenge_flow_approves_transaction(self) -> None:
        with patch(
            "backend.core.notification_hub._deliver", new_callable=AsyncMock
        ), patch("backend.core.notification_hub.secrets.randbelow", return_value=123456):
            created = self.client.post(
                "/api/client-hub/send-challenge",
                json={"transaction_id": "TX-9041", "channel": "FCM"},
            )
        self.assertEqual(created.status_code, 201)
        challenge_id = created.json()["id"]
        response = TestClient(main.app).post(
            "/api/client-hub/respond",
            json={
                "challenge_id": challenge_id,
                "code": "123456",
                "biometric_score": 0.96,
            },
        )
        self.assertTrue(response.json()["valid"])
        transaction = next(
            item for item in self.client.get("/api/transactions").json()
            if item["id"] == "TX-9041"
        )
        self.assertEqual(transaction["status"], "APPROVED")

    def test_registry_search_uses_bounded_filters(self) -> None:
        response = self.client.post(
            "/api/registry/search",
            json={"query": "Montre les transactions bloquées avec proxy Tor et score supérieur à 0.8"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["id"] for row in response.json()["results"]], ["TX-9042"])
        self.assertIn("aucun SQL arbitraire", response.json()["notice"])

    def test_aml_export_and_unconfigured_zk(self) -> None:
        report = self.client.get("/api/aml/export-tracfin")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.headers["content-type"], "application/pdf")
        proof = self.client.post(
            "/api/zk/verify",
            json={"proof": {"protocol": "groth16"}, "public_signals": ["1"]},
        )
        self.assertEqual(proof.status_code, 503)

    def test_graph_reports_unconfigured_provider(self) -> None:
        os.environ.pop("NEO4J_URI", None)
        os.environ.pop("NEO4J_USERNAME", None)
        os.environ.pop("NEO4J_PASSWORD", None)
        graph = self.client.get("/api/aml/graph")
        self.assertEqual(graph.status_code, 200)
        self.assertFalse(graph.json()["connected"])

    def test_red_team_simulation_uses_synthetic_profiles(self) -> None:
        response = self.client.post("/api/self-healing/red-team-simulation")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["profiles_tested"], 5000)
        self.assertGreaterEqual(response.json()["detection_rate"], 0)
        self.assertLessEqual(response.json()["detection_rate"], 1)

    def test_api_requires_operator_authentication(self) -> None:
        unauthenticated = TestClient(main.app)
        response = unauthenticated.get("/api/system/status")
        self.assertEqual(response.status_code, 401)

    def test_notification_contacts_are_encrypted_and_senior_only(self) -> None:
        result = self.client.put(
            "/api/client-hub/contacts",
            json={"customer_id": "USR-4092", "phone": "+33123456789"},
        )
        self.assertEqual(result.status_code, 200)
        with database.connect() as db:
            row = db.execute(
                "SELECT phone_encrypted FROM customer_contacts WHERE customer_id = ?",
                ("USR-4092",),
            ).fetchone()
        self.assertNotEqual(row["phone_encrypted"], "+33123456789")

    def test_challenge_fails_closed_without_delivery_provider(self) -> None:
        response = self.client.post(
            "/api/client-hub/send-challenge",
            json={"transaction_id": "TX-9041", "channel": "FCM"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertIn("Aucune destination FCM", response.json()["detail"])

    def test_human_feedback_trains_and_proposes_rule_for_review(self) -> None:
        from backend.core.feedback_learning import record_review
        from backend.core.ml_detector import feedback_model_status

        with database.connect() as db:
            for index in range(20):
                suspicious = index % 2 == 1
                transaction_id = f"TX-TRAIN-{index:02d}"
                amount = 3000.0 if suspicious else 35.0
                velocity = 0.94 if suspicious else 0.04
                biometric = 0.08 if suspicious else 0.98
                proxy = "TOR" if suspicious else "NONE"
                now = f"2026-10-28T12:{index:02d}:00+00:00"
                db.execute(
                    """INSERT INTO transactions
                    (id, customer_id, amount, currency, proxy_type, velocity_score,
                     biometric_score, ml_score, risk_score, status, recommendation,
                     proof_hash, created_at, updated_at)
                    VALUES (?, ?, ?, 'EUR', ?, ?, ?, 0, 0, 'REVIEWED', 'REVIEW', ?, ?, ?)""",
                    (
                        transaction_id, "USR-TRAIN", amount, proxy, velocity,
                        biometric, "test-hash", now, now,
                    ),
                )
        for index in range(20):
            record_review(
                f"TX-TRAIN-{index:02d}", index % 2, "analyst@example.test", "HUMAN-SOC-OP"
            )

        self.assertTrue(feedback_model_status()["trained"])
        rules = self.client.get("/api/self-healing/rules").json()
        proposed = next(rule for rule in rules if rule["status"] == "PENDING_REVIEW")
        approved = self.client.post(
            f"/api/self-healing/rules/{proposed['id']}/approve"
        )
        self.assertEqual(approved.status_code, 200)
        self.assertGreaterEqual(approved.json()["risk_threshold"], 0.3)
        self.assertLessEqual(approved.json()["risk_threshold"], 0.9)
        self.assertEqual(
            approved.json()["risk_threshold"],
            self.client.get("/api/system/status").json()["feedback_model"]["metrics"]["threshold"],
        )
        from backend.core.ml_detector import assess_transaction

        _, recommendation = assess_transaction(3000, 0.94, 0.08, "TOR")
        self.assertEqual(recommendation, "BLOCK")
        veto = self.client.post(f"/api/self-healing/rules/{proposed['id']}/veto")
        self.assertEqual(veto.status_code, 200)
        self.assertEqual(float(database.get_state("learned_risk_threshold")), 0.72)
        self.assertTrue(self.client.get("/api/audit/integrity").json()["valid"])

    def test_federated_receiver_verifies_signature_and_rejects_replay(self) -> None:
        secret = "shared-federation-secret-at-least-32-chars"
        os.environ["FEDERATION_TRUSTED_PEERS"] = json.dumps({"bank-peer": secret})
        payload = {
            "version": 1,
            "peer_id": "bank-peer",
            "sent_at": int(time.time()),
            "nonce": "nonce-test-001",
            "aggregate": {"cohort_size": 5, "eligible": False},
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        timestamp = str(payload["sent_at"])
        signature = hmac.new(
            secret.encode(),
            timestamp.encode() + b"\n" + payload["nonce"].encode() + b"\n" + body,
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "X-Federation-Peer": "bank-peer",
            "X-Federation-Timestamp": timestamp,
            "X-Federation-Nonce": payload["nonce"],
            "X-Federation-Signature": signature,
            "Content-Type": "application/json",
        }
        first = self.client.post("/api/federated/receive", content=body, headers=headers)
        replay = self.client.post("/api/federated/receive", content=body, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 409)


if __name__ == "__main__":
    unittest.main()
