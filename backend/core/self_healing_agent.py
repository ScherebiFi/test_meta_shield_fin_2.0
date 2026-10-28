from __future__ import annotations

from backend.core.ml_detector import red_team_sample
from backend.core.feedback_learning import approve_learned_rule
from backend.db.audit_logger import record
from backend.db.database import connect


def veto_rule(rule_id: str, reviewed_by: str) -> bool:
    with connect() as db:
        rule = db.execute(
            """SELECT origin, status FROM rules
            WHERE id = ? AND status IN ('ACTIVE', 'PENDING_REVIEW')""",
            (rule_id,),
        ).fetchone()
        if rule is None:
            return False
        cursor = db.execute(
            """UPDATE rules SET status = 'VETOED'
            WHERE id = ? AND status IN ('ACTIVE', 'PENDING_REVIEW')""",
            (rule_id,),
        )
        threshold_reset = (
            rule["status"] == "ACTIVE"
            and rule["origin"] in ("HUMAN_FEEDBACK_LEARNING", "FEDERATED_RECOMMENDATION")
        )
        if cursor.rowcount and threshold_reset:
            db.execute(
                """INSERT INTO app_state(key, value) VALUES('learned_risk_threshold', '0.72')
                ON CONFLICT(key) DO UPDATE SET value = excluded.value"""
            )
    if cursor.rowcount:
        record(
            "HUMAN-VETO",
            "RULE_VETOED",
            rule_id,
            {"reviewed_by": reviewed_by, "threshold_reset": threshold_reset},
        )
        return True
    return False


def approve_rule(rule_id: str, reviewed_by: str) -> float:
    return approve_learned_rule(rule_id, reviewed_by)


def run_red_team() -> dict[str, float | int]:
    result = red_team_sample()
    record("AGENT-SELF-HEALING", "RED_TEAM_SIMULATION", "LOCAL-ML", result)
    return result