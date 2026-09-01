import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Event, Incident, Timeline
from ..security import current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])

styles = getSampleStyleSheet()


def _pdf(incident: Incident, event: Event | None, timeline: list[Timeline]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    story = [
        Paragraph("Self-Healing SOC - Incident Report", styles["Title"]),
        Spacer(1, 14),
        Paragraph(f"<b>Incident #{incident.id}:</b> {incident.title}", styles["Normal"]),
        Paragraph(f"<b>Status:</b> {incident.status}", styles["Normal"]),
        Paragraph(f"<b>Priority:</b> {incident.priority}", styles["Normal"]),
        Paragraph(f"<b>Risk score:</b> {incident.risk_score}", styles["Normal"]),
        Paragraph(f"<b>Response:</b> {incident.response_status}", styles["Normal"]),
        Paragraph(f"<b>Healing:</b> {incident.healing_status}", styles["Normal"]),
        Spacer(1, 14),
    ]
    if event is not None:
        story.extend(
            [
                Paragraph("Source Event", styles["Heading2"]),
                Paragraph(
                    f"Endpoint: {event.endpoint}<br/>"
                    f"Type: {event.event_type}<br/>"
                    f"Source IP: {event.source_ip or 'n/a'}<br/>"
                    f"Severity: {event.severity}<br/>"
                    f"MITRE ATT&amp;CK: {event.mitre_technique or 'n/a'}<br/>"
                    f"Explanation: {event.explanation or 'n/a'}",
                    styles["Normal"],
                ),
                Spacer(1, 14),
            ]
        )
    if timeline:
        story.append(Paragraph("Timeline", styles["Heading2"]))
        rows = [["Time (UTC)", "Actor", "Action", "Detail"]]
        for row in timeline:
            rows.append(
                [
                    row.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    row.actor,
                    row.action,
                    row.detail[:120],
                ]
            )
        table = Table(rows, colWidths=[4 * cm, 3 * cm, 4 * cm, 7 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), "#1f2937"),
                    ("TEXTCOLOR", (0, 0), (-1, 0), "white"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.4, "#9ca3af"),
                ]
            )
        )
        story.append(table)
    doc.build(story)
    return buffer.getvalue()


@router.get("/incident/{incident_id}.pdf")
def incident_pdf(
    incident_id: int,
    db: Session = Depends(get_db),
    user=Depends(current_user),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    event = db.get(Event, incident.event_id)
    timeline = list(
        db.scalars(
            select(Timeline).where(Timeline.incident_id == incident.id).order_by(Timeline.id.asc())
        )
    )
    pdf_bytes = _pdf(incident, event, timeline)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident_{incident.id}.pdf"'},
    )
