from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    username: str
    role: str
    active: bool


FEATURE_DESCRIPTIONS = {
    "failed_logins": "Failed login attempts",
    "unique_ports": "Unique destination ports touched",
    "process_spawns": "Processes spawned",
    "network_rate": "Network flow rate",
}


class EventCreate(BaseModel):
    endpoint: str
    event_type: str = Field(
        pattern="^(login|brute_force|port_scan|suspicious_process|malware|data_exfiltration)$"
    )
    source_ip: str = ""
    severity: str = Field(default="low", pattern="^(low|medium|high|critical)$")
    message: str = ""
    failed_logins: int = 0
    unique_ports: int = 0
    process_spawns: int = 0
    network_rate: float = 0.0


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    endpoint: str
    event_type: str
    source_ip: str
    severity: str
    message: str
    analyzed: bool
    risk_score: float
    explanation: str
    mitre_technique: str
    created_at: datetime


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int
    title: str
    status: str
    priority: str
    risk_score: float
    response_status: str
    healing_status: str
    created_at: datetime
    resolved_at: datetime | None = None


class TimelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    actor: str
    action: str
    detail: str
    created_at: datetime


class StatsOut(BaseModel):
    total_events: int
    total_incidents: int
    critical_incidents: int
    healed_incidents: int
    avg_risk: float
