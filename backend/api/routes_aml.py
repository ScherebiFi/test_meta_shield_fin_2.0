from __future__ import annotations

import os
from datetime import datetime, timezone
from io import BytesIO

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from backend.core.llama_agent import ask_llama, cloud_available
from backend.db.audit_logger import record
from backend.db.database import connect
from backend.db.neo4j_connector import read_network


router = APIRouter(prefix="/api/aml", tags=["aml"])


def _summary() -> dict[str, object]:
    with connect() as db:
        transactions = db.execute(
            "SELECT id, customer_id, amount, currency, proxy_type, risk_score, status, created_at "
            "FROM transactions WHERE risk_score >= 0.5 ORDER BY risk_score DESC LIMIT 20"
        ).fetchall()
    return {
        "case_id": "AML-" + datetime.now(timezone.utc).strftime("%Y%m%d"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "high_risk_transactions": [dict(row) for row in transactions],
        "provider": "groq" if cloud_available() else "local",
    }


@router.get("/case")
def get_case() -> dict[str, object]:
    return _summary()


@router.get("/graph")
def get_graph() -> dict[str, object]:
    return read_network()


@router.post("/deep-analyze")
async def deep_analyze() -> dict[str, object]:
    summary = _summary()
    cloud_opt_in = os.getenv("GROQ_ALLOW_ANONYMIZED_AGGREGATES", "").lower() == "true"
    if cloud_available() and cloud_opt_in:
        rows = summary["high_risk_transactions"]
        aggregate = {
            "high_risk_transaction_count": len(rows),
            "blocked_count": sum(row["status"] == "BLOCKED" for row in rows),
            "challenge_count": sum(row["status"] == "CHALLENGE_REQUIRED" for row in rows),
        }
        report = await ask_llama(
            "Tu es un assistant de conformité AML. Analyse les indicateurs fournis sans inventer "
            "de faits. Mentionne que toute déclaration officielle doit être validée par un humain. "
            "Les indicateurs sont agrégés et ne décrivent pas de transactions individuelles.",
            str(aggregate),
        )
        provider = "groq"
    else:
        records = summary["high_risk_transactions"]
        report = (
            f"{len(records)} transaction(s) nécessitent une revue. "
            "Les indicateurs disponibles sont des scores internes et ne constituent pas une preuve "
            "de blanchiment. Un analyste conformité doit examiner les éléments et valider toute suite. "
            "Aucune donnée n'a été transmise au cloud."
        )
        provider = "local_fallback"
    record(
        "AI-LLAMA" if provider == "groq" else "SYSTEM-LOCAL",
        "AML_DEEP_ANALYSIS",
        str(summary["case_id"]),
        {"provider": provider},
    )
    return {"case_id": summary["case_id"], "provider": provider, "report": report, "data": summary}


@router.get("/export-tracfin")
def export_report() -> StreamingResponse:
    summary = _summary()
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)
    width, height = A4
    y = height - 52
    pdf.setTitle(f"Rapport AML {summary['case_id']}")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(48, y, "Meta ShieldFin - Rapport d'investigation AML")
    y -= 28
    pdf.setFont("Helvetica", 10)
    pdf.drawString(48, y, f"Dossier: {summary['case_id']}  |  Généré: {summary['generated_at']}")
    y -= 26
    pdf.drawString(48, y, "Document de démonstration - validation humaine requise avant tout dépôt officiel.")
    y -= 30
    for row in summary["high_risk_transactions"]:
        line = (
            f"{row['id']} | {row['customer_id']} | {row['amount']:.2f} {row['currency']} | "
            f"risque {row['risk_score']:.2f} | {row['status']}"
        )
        pdf.drawString(48, y, line[:105])
        y -= 17
        if y < 60:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - 52
    pdf.save()
    output.seek(0)
    record("HUMAN-SOC-OP", "COMPLIANCE_REPORT_EXPORTED", str(summary["case_id"]), {"format": "PDF"})
    return StreamingResponse(
        output,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{summary["case_id"]}.pdf"'},
    )
