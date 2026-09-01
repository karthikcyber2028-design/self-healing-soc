from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..ml.scoring import score
from ..mitre import map_mitre
from ..models import AuditLog, Event, Incident, Timeline
from ..schemas import EventCreate, EventOut, IncidentOut, StatsOut, TimelineOut
from ..security import current_user, require_roles

router = APIRouter(prefix="/api", tags=["soc"])

INCIDENT_THRESHOLD = 65.0
CRITICAL_THRESHOLD = 85.0


@router.post("/events", response_model=EventOut)
def ingest_event(body: EventCreate, db: Session = Depends(get_db)):
    event = Event(**body.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.get("/events", response_model=list[EventOut])
def list_events(limit: int = 100, db: Session = Depends(get_db)):
    return list(db.scalars(select(Event).order_by(Event.id.desc()).limit(limit)))


@router.post("/events/{event_id}/analyze", response_model=EventOut)
def analyze_event(
    event_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_roles("analyst", "admin")),
):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    result = score(event)
    event.analyzed = True
    event.risk_score = result["risk_score"]
    event.explanation = result["explanation"]
    event.mitre_technique = map_mitre(event.event_type)

    timeline_rows = []
    if event.risk_score >= INCIDENT_THRESHOLD and not db.scalar(
        select(Incident).where(Incident.event_id == event.id)
    ):
        priority = "critical" if event.risk_score >= CRITICAL_THRESHOLD else "high"
        incident = Incident(
            event_id=event.id,
            title=f"{event.event_type} on {event.endpoint}",
            priority=priority,
            risk_score=event.risk_score,
        )
        db.add(incident)
        db.flush()
        timeline_rows.append(
            Timeline(
                incident_id=incident.id,
                actor="decision-engine",
                action="DETECTED",
                detail=f"risk={event.risk_score} mitre={event.mitre_technique}",
            )
        )

    db.add(
        AuditLog(
            username=user.username,
            action="ANALYZE_EVENT",
            detail=f"event={event.id} risk={event.risk_score}",
        )
    )
    for row in timeline_rows:
        db.add(row)
    db.commit()
    db.refresh(event)
    return event


@router.get("/incidents", response_model=list[IncidentOut])
def list_incidents(db: Session = Depends(get_db)):
    return list(db.scalars(select(Incident).order_by(Incident.id.desc())))


@router.get("/incidents/{incident_id}/timeline", response_model=list[TimelineOut])
def incident_timeline(incident_id: int, db: Session = Depends(get_db)):
    return list(
        db.scalars(
            select(Timeline)
            .where(Timeline.incident_id == incident_id)
            .order_by(Timeline.id.asc())
        )
    )


@router.post("/incidents/{incident_id}/simulate-response", response_model=IncidentOut)
def simulate_response(
    incident_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_roles("analyst", "admin")),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.healing_status == "resolved":
        return incident

    event = db.get(Event, incident.event_id)
    endpoint = event.endpoint if event else "unknown"

    incident.response_status = "contained_simulation"
    incident.healing_status = "healing"
    now = datetime.now(timezone.utc)

    steps = [
        ("simulated-response", "CONTAINMENT_SIMULATED",
         f"SOC-SIM: host {endpoint} isolated in simulation; outbound block applied (no live change)"),
        ("self-healing-engine", "HEALING_STARTED",
         "health checks scheduled; restore-from-backup simulation queued"),
    ]
    if incident.status != "resolved":
        incident.status = "resolved"
        incident.resolved_at = now
        steps.append(
            ("validation-service", "HEALING_VALIDATED",
             "post-heal checks passed; monitoring resumed")
        )

    for actor, action, detail in steps:
        db.add(Timeline(incident_id=incident.id, actor=actor, action=action, detail=detail))
    incident.healing_status = "validated"
    incident.status = "resolved"

    db.add(
        AuditLog(
            username=user.username,
            action="SIMULATE_RESPONSE",
            detail=f"incident={incident.id} contained={endpoint} (simulation only)",
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    total_events = db.scalar(select(func.count(Event.id))) or 0
    total_incidents = db.scalar(select(func.count(Incident.id))) or 0
    critical = db.scalar(
        select(func.count(Incident.id)).where(Incident.priority == "critical")
    ) or 0
    healed = db.scalar(
        select(func.count(Incident.id)).where(Incident.healing_status == "validated")
    ) or 0
    avg_risk = db.scalar(select(func.avg(Event.risk_score))) or 0.0
    return StatsOut(
        total_events=total_events,
        total_incidents=total_incidents,
        critical_incidents=critical,
        healed_incidents=healed,
        avg_risk=round(float(avg_risk), 1),
    )


@router.get("/audit", response_model=list[dict])
def audit_logs(limit: int = 100, user=Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    return [
        {
            "id": r.id,
            "username": r.username,
            "action": r.action,
            "detail": r.detail,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
