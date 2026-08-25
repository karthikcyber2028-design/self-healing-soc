"""
Self-Healing SOC Agent - Complete Demo Backend (single file, Colab-ready).

Flow: Endpoint events -> ML anomaly detection -> Risk scoring -> Explainability
      -> MITRE ATT&CK mapping -> Incidents -> Simulated self-healing -> Validation.

Demo-grade security (fixed salt/secret). Synthetic data only - no real endpoints.
"""

import io
import os
import pickle
import random
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import jwt
import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc.db")
MODEL_PATH = os.path.join(BASE_DIR, "soc_model.joblib")

SALT = "shs-soc-demo-salt"
SECRET_KEY = "shs-demo-secret-change-me-in-production"
ALGORITHM = "HS256"
TOKEN_HOURS = 12

FEATURES = [
    "failed_logins",
    "ports_touched",
    "packets_per_min",
    "cpu_pct",
    "bytes_out",
    "process_flag",
]

SEVERITY_WEIGHT = {
    "login": 0.10,
    "port_scan": 0.45,
    "suspicious_process": 0.55,
    "brute_force": 0.70,
    "dos": 0.85,
    "malware": 0.80,
    "data_exfiltration": 0.95,
}

MITRE_MAP = {
    "login": ("T1078", "Valid Accounts"),
    "port_scan": ("T1046", "Network Service Discovery"),
    "suspicious_process": ("T1059", "Command and Scripting Interpreter"),
    "brute_force": ("T1110", "Brute Force"),
    "dos": ("T1498", "Network Denial of Service"),
    "malware": ("T1204", "User Execution"),
    "data_exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
}

BAND_CUTS = ((35.0, "low"), (60.0, "medium"), (80.0, "high"), (101.0, "critical"))
INCIDENT_BANDS = {"high", "critical"}

HOSTS = ["EDGE-01", "EDGE-02", "EDGE-03"]


def utcnow():
    return datetime.utcnow()


def hash_pw(password: str) -> str:
    return hashlib.sha256((SALT + password).encode("utf-8")).hexdigest()


def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": utcnow() + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# --------------------------------------------------------------------------- #
# Database models
# --------------------------------------------------------------------------- #
engine = create_engine(
    "sqlite:///" + DB_PATH, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    pw_hash = Column(String(128), nullable=False)
    role = Column(String(16), nullable=False)  # admin | analyst | viewer


class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=utcnow)
    hostname = Column(String(64), nullable=False)
    agent = Column(String(32), default="shs-agent")
    event_type = Column(String(32), nullable=False)
    failed_logins = Column(Float, default=0)
    ports_touched = Column(Float, default=0)
    packets_per_min = Column(Float, default=0)
    cpu_pct = Column(Float, default=0)
    bytes_out = Column(Float, default=0)
    process_flag = Column(Float, default=0)
    analyzed = Column(Boolean, default=False)
    anomaly = Column(Float)
    risk_score = Column(Float)
    risk_band = Column(String(12))
    mitre_id = Column(String(12))
    mitre_name = Column(String(64))
    explanation = Column(Text)
    incident_id = Column(Integer)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow)
    event_id = Column(Integer)
    hostname = Column(String(64))
    title = Column(String(160))
    event_type = Column(String(32))
    mitre_id = Column(String(12))
    mitre_name = Column(String(64))
    risk_band = Column(String(12))
    risk_score = Column(Float)
    status = Column(String(16), default="open")  # open|contained|healed|resolved
    healing_validated = Column(Boolean, default=False)
    actions = Column(JSON, default=list)
    closed_at = Column(DateTime)


# --------------------------------------------------------------------------- #
# ML: baseline model + scoring
# --------------------------------------------------------------------------- #
MODEL = {}


def _synthetic_normals(n=800, seed=42):
    rng = np.random.default_rng(seed)
    return {
        "failed_logins": np.clip(rng.poisson(0.2, n), 0, 2).astype(float),
        "ports_touched": rng.integers(0, 4, n).astype(float),
        "packets_per_min": np.clip(rng.normal(300, 80, n), 20, None),
        "cpu_pct": np.clip(rng.normal(25, 10, n), 1, None),
        "bytes_out": np.clip(rng.normal(5e5, 2e5, n), 1e4, None),
        "process_flag": rng.binomial(1, 0.02, n).astype(float),
    }


def train_baseline_model():
    normals = _synthetic_normals()
    X = np.column_stack([normals[f] for f in FEATURES])
    mean = X.mean(axis=0)
    std = np.where(X.std(axis=0) == 0, 1.0, X.std(axis=0))

    method = "statistical-zscore"
    scores_sorted = None
    forest = None
    try:
        from sklearn.ensemble import IsolationForest

        forest = IsolationForest(
            n_estimators=120, contamination=0.08, random_state=42
        ).fit(X)
        raw = forest.score_samples(X)
        scores_sorted = np.sort(raw)
        method = "isolation-forest"
    except Exception:
        forest = None

    MODEL.clear()
    MODEL.update(
        {
            "features": FEATURES,
            "mean": mean,
            "std": std,
            "method": method,
            "scores_sorted": scores_sorted,
            "trained_at": utcnow().isoformat(),
        }
    )
    with open(MODEL_PATH, "wb") as fh:
        pickle.dump(MODEL.copy(), fh)
    return METHOD_LABEL[method]


METHOD_LABEL = {
    "isolation-forest": "Isolation Forest",
    "statistical-zscore": "Statistical z-score ensemble",
}


def load_or_train_model() -> str:
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as fh:
                data = pickle.load(fh)
            if isinstance(data, dict) and data.get("features") == FEATURES:
                MODEL.clear()
                MODEL.update(data)
                return METHOD_LABEL.get(data.get("method"), "ML")
        except Exception:
            pass
    return train_baseline_model()


def score_metrics(metrics: dict, event_type: str) -> dict:
    """Statistical z-score scoring. Used as fallback when sklearn unavailable."""
    x = np.array([float(metrics.get(f, 0) or 0) for f in FEATURES])
    z = (x - MODEL["mean"]) / MODEL["std"]
    stat = np.clip(np.abs(z) / 3.5, 0, 1)
    anomaly = float(np.clip(0.9 * stat.mean() + 0.1 * stat.max(), 0, 1))

    order = np.argsort(-np.abs(z))
    drivers = [
        (FEATURES[i], float(z[i]))
        for i in order[:2]
        if abs(z[i]) >= 1.5
    ]
    driver_txt = "; ".join(f"{f} (z={v:+.1f})" for f, v in drivers) or (
        "all metrics within normal ranges"
    )

    weight = SEVERITY_WEIGHT.get(event_type, 0.4)
    risk = round(100 * (0.55 * anomaly + 0.45 * weight), 1)
    band = next(b for cut, b in BAND_CUTS if risk < cut)

    mitre_id, mitre_name = MITRE_MAP.get(event_type, ("", ""))
    explanation = (
        f"{event_type}: anomaly={anomaly:.2f} ({METHOD_LABEL[method]}); "
        f"drivers: {driver_txt}; severity weight={weight:.2f}"
    )
    return {
        "anomaly": round(anomaly, 3),
        "risk_score": risk,
        "risk_band": band,
        "mitre_id": mitre_id,
        "mitre_name": mitre_name,
        "explanation": explanation,
    }


# Cached sklearn estimator path (set during startup when available).
FOREST_CACHE = {}


def score_with_forest(metrics: dict, event_type: str) -> dict | None:
    """Use cached IsolationForest when available; returns None otherwise."""
    est = FOREST_CACHE.get("est")
    sorted_scores = FOREST_CACHE.get("sorted_scores")
    if est is None or sorted_scores is None:
        return None
    x = np.array([float(metrics.get(f, 0) or 0) for f in FEATURES])
    z = (x - MODEL["mean"]) / MODEL["std"]
    raw = est.score_samples(x.reshape(1, -1))[0]
    rank = np.searchsorted(sorted_scores, raw)
    anomaly = float(np.clip(1.0 - rank / len(sorted_scores), 0, 0.995))

    order = np.argsort(-np.abs(z))
    drivers = [
        (FEATURES[i], float(z[i]))
        for i in order[:2]
        if abs(z[i]) >= 1.5
    ]
    driver_txt = "; ".join(f"{f} (z={v:+.1f})" for f, v in drivers) or (
        "all metrics within normal ranges"
    )
    weight = SEVERITY_WEIGHT.get(event_type, 0.4)
    risk = round(100 * (0.55 * anomaly + 0.45 * weight), 1)
    band = next(b for cut, b in BAND_CUTS if risk < cut)
    mitre_id, mitre_name = MITRE_MAP.get(event_type, ("", ""))
    explanation = (
        f"{event_type}: anomaly={anomaly:.2f} (Isolation Forest); "
        f"drivers: {driver_txt}; severity weight={weight:.2f}"
    )
    return {
        "anomaly": round(anomaly, 3),
        "risk_score": risk,
        "risk_band": band,
        "mitre_id": mitre_id,
        "mitre_name": mitre_name,
        "explanation": explanation,
    }


# --------------------------------------------------------------------------- #
# Self-healing playbooks (simulated)
# --------------------------------------------------------------------------- #
def _ip_for(iid: int) -> str:
    return f"10.66.{(iid >> 8) & 255}.{iid & 255}"


PLAYBOOKS = {
    "brute_force": [
        ("Containment", "block_source_ip", "Firewall rule added blocking attacker IP {ip}"),
        ("Containment", "disable_account", "Targeted account temporarily disabled"),
        ("Healing", "rotate_credentials", "Credentials rotated; MFA re-enforced"),
        ("Validation", "monitor_auth_logs", "Monitored auth logs 5 min: zero further failures"),
    ],
    "port_scan": [
        ("Containment", "tarpit_source", "Source IP moved into tarpit / rate-limited"),
        ("Healing", "harden_ports", "Unused listening ports closed on host"),
        ("Validation", "verify_scan_stop", "IDS confirms scanning activity stopped"),
    ],
    "suspicious_process": [
        ("Containment", "suspend_process", "Suspicious process suspended (PID captured)"),
        ("Healing", "remove_persistence", "Run-key / cron persistence entries removed"),
        ("Validation", "rescan_host", "Rescan clean; process did not restart"),
    ],
    "malware": [
        ("Containment", "quarantine_file", "Malicious binary quarantined"),
        ("Containment", "kill_process", "Parent process terminated"),
        ("Healing", "full_antivirus_scan", "Full AV scan scheduled and completed"),
        ("Validation", "verify_clean", "Host verified clean on rescans"),
    ],
    "dos": [
        ("Containment", "enable_rate_limit", "Edge rate-limiting enabled"),
        ("Containment", "blackhole_route", "Attack prefixes blackholed upstream"),
        ("Healing", "autoscale_edge", "Edge replicas scaled out to absorb traffic"),
        ("Validation", "latency_check", "Latency back to baseline SLA"),
    ],
    "data_exfiltration": [
        ("Containment", "isolate_host", "Host network-isolated (management VLAN only)"),
        ("Containment", "block_destination", "External destination domain/IP blocked"),
        ("Healing", "revoke_sessions_tokens", "User sessions and API tokens revoked"),
        ("Validation", "dlp_verify", "DLP monitors report zero outbound anomalies"),
    ],
}
FALLBACK_PLAYBOOK = [
    ("Containment", "restrict_host", "Restrictive policy applied to host"),
    ("Healing", "baseline_recheck", "Configuration rebaselined"),
    ("Validation", "monitor", "Continuous monitoring confirmed stable"),
]


def run_playbook(incident: Incident) -> list:
    steps = PLAYBOOKS.get(incident.event_type, FALLBACK_PLAYBOOK)
    t0 = utcnow()
    actions = []
    phase_seen = set()
    for i, (phase, action, detail) in enumerate(steps):
        phase_seen.add(phase)
        actions.append(
            {
                "time": (t0 + timedelta(seconds=i + 1)).isoformat(),
                "phase": phase,
                "action": action,
                "detail": detail.format(ip=_ip_for(incident.id)),
                "result": "success",
            }
        )
    incident.status = "contained" if "Healing" not in phase_seen else "healed"
    incident.status = "resolved"
    incident.healing_validated = True
    incident.closed_at = utcnow()
    incident.actions = actions
    return actions


# --------------------------------------------------------------------------- #
# Event simulator (synthetic attack profiles)
# --------------------------------------------------------------------------- #
TYPE_MIX = [
    ("login", 0.30),
    ("port_scan", 0.17),
    ("brute_force", 0.14),
    ("suspicious_process", 0.12),
    ("malware", 0.11),
    ("dos", 0.07),
    ("data_exfiltration", 0.09),
]


def _sample_type() -> str:
    r = random.random()
    acc = 0.0
    for t, w in TYPE_MIX:
        acc += w
        if r <= acc:
            return t
    return "login"


def synth_metrics(event_type: str) -> dict:
    base = {
        "failed_logins": 0,
        "ports_touched": random.randint(0, 3),
        "packets_per_min": max(20.0, random.gauss(300, 80)),
        "cpu_pct": max(1.0, random.gauss(25, 10)),
        "bytes_out": max(1e4, random.gauss(5e5, 2e5)),
        "process_flag": 1 if random.random() < 0.02 else 0,
    }
    if event_type == "login":
        if random.random() < 0.25:  # some failed-login noise
            base["failed_logins"] = random.randint(3, 6)
        else:
            base["failed_logins"] = 0
    elif event_type == "brute_force":
        base["failed_logins"] = random.randint(8, 45)
        base["cpu_pct"] += random.uniform(5, 20)
    elif event_type == "port_scan":
        base["ports_touched"] = random.randint(30, 500)
        base["packets_per_min"] *= random.uniform(1.5, 3)
    elif event_type == "suspicious_process":
        base["process_flag"] = 1
        base["cpu_pct"] = random.uniform(60, 95)
        base["bytes_out"] *= random.uniform(1, 4)
    elif event_type == "malware":
        base["process_flag"] = 1
        base["cpu_pct"] = random.uniform(75, 100)
        base["bytes_out"] *= random.uniform(2, 6)
        base["packets_per_min"] *= random.uniform(1.2, 2.5)
    elif event_type == "dos":
        base["packets_per_min"] = random.uniform(5000, 40000)
        base["cpu_pct"] = random.uniform(88, 100)
    elif event_type == "data_exfiltration":
        base["bytes_out"] = random.uniform(5e6, 9e7)
        base["cpu_pct"] = random.uniform(40, 80)
        base["process_flag"] = 1 if random.random() < 0.6 else 0
    return base


def generate_events(session: Session, n: int, host_cycle=True) -> int:
    made = 0
    for i in range(min(max(n, 1), 50)):
        etype = _sample_type()
        host = HOSTS[i % len(HOSTS)] if host_cycle else random.choice(HOSTS)
        m = synth_metrics(etype)
        session.add(
            Event(
                ts=utcnow(),
                hostname=host,
                agent="shs-agent-v2",
                event_type=etype,
                **m,
            )
        )
        made += 1
    session.commit()
    return made


# --------------------------------------------------------------------------- #
# Auth helpers
# --------------------------------------------------------------------------- #
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> User:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=payload.get("sub")).first()
    finally:
        db.close()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
    return user


def require_role(*roles):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user.role}' not permitted (needs: {', '.join(roles)})",
            )
        return user

    return checker


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class TokenIn(BaseModel):
    username: str
    password: str


class EventIn(BaseModel):
    hostname: str = Field(..., examples=["EDGE-01"])
    event_type: str = Field("login", examples=["brute_force"])
    failed_logins: float = 0
    ports_touched: float = 0
    packets_per_min: float = 0
    cpu_pct: float = 0
    bytes_out: float = 0
    process_flag: float = 0


class GenerateIn(BaseModel):
    count: int = Field(18, ge=1, le=50)


# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #
SEED_USERS = [
    ("admin", "Admin@12345", "admin"),
    ("analyst", "Analyst@12345", "analyst"),
    ("viewer", "Viewer@12345", "viewer"),
]


def init_db():
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        for uname, pwd, role in SEED_USERS:
            if not db.query(User).filter_by(username=uname).first():
                db.add(User(username=uname, pw_hash=hash_pw(pwd), role=role))
        db.commit()
    finally:
        db.close()
    label = load_or_train_model()
    if MODEL["method"] == "statistical-zscore":
        pass
    else:
        try:
            from sklearn.ensemble import IsolationForest

            normals = _synthetic_normals()
            X = np.column_stack([normals[f] for f in FEATURES])
            FOREST_CACHE["est"] = IsolationForest(
                n_estimators=120, contamination=0.08, random_state=42
            ).fit(X)
            FOREST_CACHE["sorted_scores"] = np.sort(
                FOREST_CACHE["est"].score_samples(X)
            )
        except Exception:
            FOREST_CACHE.clear()
    return label


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Self-Healing SOC Demo API", version="2.0", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "mode": "colab-demo",
        "model_method": METHOD_LABEL.get(MODEL.get("method"), "untrained"),
        "time": utcnow().isoformat(),
    }


@app.post("/token")
def login(body: TokenIn):
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=body.username).first()
        if not user or user.pw_hash != hash_pw(body.password):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad credentials")
        return {
            "access_token": create_token(user.username, user.role),
            "token_type": "bearer",
            "username": user.username,
            "role": user.role,
        }
    finally:
        db.close()


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}


@app.post("/events", dependencies=[Depends(require_role("analyst", "admin"))])
def ingest_event(body: EventIn):
    db = SessionLocal()
    try:
        ev = Event(ts=utcnow(), hostname=body.hostname, agent="external", event_type=body.event_type, **{k: getattr(body, k) for k in FEATURES})
        db.add(ev)
        db.commit()
        return {"status": "queued", "event_id": ev.id}
    finally:
        db.close()


@app.get("/events")
def list_events(limit: int = 100, user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = (
            db.query(Event)
            .order_by(Event.id.desc())
            .limit(min(limit, 200))
            .all()
        )
        return [
            {
                "id": e.id,
                "ts": e.ts.isoformat() if e.ts else None,
                "hostname": e.hostname,
                "event_type": e.event_type,
                "analyzed": e.analyzed,
                "risk_score": e.risk_score,
                "risk_band": e.risk_band,
            }
            for e in rows
        ]
    finally:
        db.close()


@app.post("/analyze", dependencies=[Depends(require_role("analyst", "admin"))])
def analyze():
    db = SessionLocal()
    try:
        pending = db.query(Event).filter_by(analyzed=False).all()
        alerts = incidents = 0
        for e in pending:
            metrics = {f: getattr(e, f) for f in FEATURES}
            res = score_with_forest(metrics, e.event_type) or score_metrics(
                metrics, e.event_type
            )
            e.analyzed = True
            e.anomaly = res["anomaly"]
            e.risk_score = res["risk_score"]
            e.risk_band = res["risk_band"]
            e.mitre_id = res["mitre_id"]
            e.mitre_name = res["mitre_name"]
            e.explanation = res["explanation"]

            if e.risk_band in INCIDENT_BANDS:
                inc = Incident(
                    created_at=utcnow(),
                    event_id=e.id,
                    hostname=e.hostname,
                    title=f"{e.event_type.upper()} detected on {e.hostname}",
                    event_type=e.event_type,
                    mitre_id=e.mitre_id,
                    mitre_name=e.mitre_name,
                    risk_band=e.risk_band,
                    risk_score=e.risk_score,
                    status="open",
                    actions=[],
                )
                db.add(inc)
                db.flush()
                e.incident_id = inc.id
                incidents += 1
            alerts += 1
        db.commit()
        return {"processed": len(pending), "alerts": alerts, "incidents_created": incidents}
    finally:
        db.close()


@app.get("/alerts")
def alerts(
    min_risk: float = 0.0,
    limit: int = 100,
    user: User = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        rows = (
            db.query(Event)
            .filter(Event.analyzed.is_(True), Event.risk_score >= min_risk)
            .order_by(Event.risk_score.desc())
            .limit(min(limit, 200))
            .all()
        )
        return [
            {
                "id": e.id,
                "ts": e.ts.isoformat() if e.ts else None,
                "hostname": e.hostname,
                "event_type": e.event_type,
                "anomaly": e.anomaly,
                "risk_score": e.risk_score,
                "risk_band": e.risk_band,
                "mitre_id": e.mitre_id,
                "mitre_name": e.mitre_name,
                "explanation": e.explanation,
                "incident_id": e.incident_id,
            }
            for e in rows
        ]
    finally:
        db.close()


@app.get("/incidents")
def incidents_list(user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(Incident).order_by(Incident.id.desc()).all()
        return [
            {
                "id": i.id,
                "created_at": i.created_at.isoformat() if i.created_at else None,
                "hostname": i.hostname,
                "title": i.title,
                "event_type": i.event_type,
                "mitre_id": i.mitre_id,
                "mitre_name": i.mitre_name,
                "risk_band": i.risk_band,
                "risk_score": i.risk_score,
                "status": i.status,
                "healing_validated": i.healing_validated,
                "closed_at": i.closed_at.isoformat() if i.closed_at else None,
                "actions": i.actions or [],
            }
            for i in rows
        ]
    finally:
        db.close()


@app.post("/incidents/{incident_id}/heal")
def heal_incident(
    incident_id: int,
    user: User = Depends(require_role("analyst", "admin")),
):
    db = SessionLocal()
    try:
        inc = db.query(Incident).filter_by(id=incident_id).first()
        if not inc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
        if inc.status != "resolved":
            inc.actions = run_playbook(inc)
        db.commit()
        return {
            "incident_id": inc.id,
            "status": inc.status,
            "healing_validated": inc.healing_validated,
            "actions": inc.actions,
        }
    finally:
        db.close()


@app.post("/heal_all")
def heal_all(user: User = Depends(require_role("analyst", "admin"))):
    db = SessionLocal()
    try:
        rows = db.query(Incident).filter(Incident.status != "resolved").all()
        for inc in rows:
            inc.actions = run_playbook(inc)
        db.commit()
        return {"healed": len(rows)}
    finally:
        db.close()


@app.get("/report/{incident_id}")
def report(incident_id: int, user: User = Depends(get_current_user)):
    buf = build_pdf(incident_id)
    if buf is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=incident_{incident_id}.pdf"
        },
    )


@app.post("/demo/generate", dependencies=[Depends(require_role("analyst", "admin"))])
def demo_generate(body: GenerateIn):
    db = SessionLocal()
    try:
        made = generate_events(db, body.count)
        return {"generated": made, "hosts": HOSTS}
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# PDF report
# --------------------------------------------------------------------------- #
def build_pdf(incident_id: int):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import simpleSplit
    from reportlab.pdfgen import canvas

    db = SessionLocal()
    try:
        inc = db.query(Incident).filter_by(id=incident_id).first()
    finally:
        db.close()
    if inc is None:
        return None

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4
    y = H - 60

    c.setFont("Helvetica-Bold", 18)
    c.drawString(48, y, "Self-Healing SOC - Incident Report")
    y -= 14
    c.setFont("Helvetica", 9)
    c.drawString(48, y, "Generated by SHS Agent v2 (demo, synthetic data only)")
    y -= 28

    c.setFont("Helvetica-Bold", 11)
    c.drawString(48, y, f"Incident #{inc.id}: {inc.title}")
    y -= 18
    c.setFont("Helvetica", 10)
    lines = [
        f"Created:   {inc.created_at}",
        f"Hostname:  {inc.hostname}",
        f"Type:      {inc.event_type}",
        f"MITRE ATT&CK: {inc.mitre_id} - {inc.mitre_name}",
        f"Risk:      {inc.risk_score} ({inc.risk_band.upper()})",
        f"Status:    {inc.status}   Validated: {'yes' if inc.healing_validated else 'no'}",
        f"Closed:    {inc.closed_at or '-'}",
    ]
    for ln in lines:
        c.drawString(56, y, ln)
        y -= 15

    y -= 8
    c.setFont("Helvetica-Bold", 11)
    c.drawString(48, y, "Analysis / Explanation")
    y -= 14
    c.setFont("Helvetica", 9)
    db2 = SessionLocal()
    try:
        ev = db2.query(Event).filter_by(id=inc.event_id).first()
    finally:
        db2.close()
    expl = ev.explanation if ev and ev.explanation else "(no analysis stored)"
    for seg in simpleSplit(expl, "Helvetica", 9, W - 110):
        c.drawString(56, y, seg)
        y -= 12

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(48, y, "Simulated Response Timeline")
    y -= 14
    c.setFont("Helvetica", 9)
    for a in inc.actions or []:
        row = f"[{str(a.get('time',''))[11:19]}] {a.get('phase','')}: {a.get('action','')} - {a.get('detail','')} ({a.get('result','')})"
        for seg in simpleSplit(row, "Helvetica", 9, W - 110):
            c.drawString(56, y, seg)
            y -= 12
        if y < 70:
            c.showPage()
            y = H - 60
            c.setFont("Helvetica", 9)

    c.setFont("Helvetica-Oblique", 8)
    c.drawString(48, 40, "DISCLAIMER: all events/healing are simulated. No real systems were modified.")
    c.showPage()
    c.save()
    buf.seek(0)
    return buf


# --------------------------------------------------------------------------- #
# Dashboard (single-page app served at /dashboard)
# --------------------------------------------------------------------------- #
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>Self-Healing SOC Dashboard</title>
<style>
:root{--bg:#0b1220;--panel:#121a2b;--line:#22304a;--txt:#dbe4f3;--dim:#8ea0bd;
--acc:#4da3ff;--ok:#37c978;--warn:#ffb84d;--bad:#ff5d5d;}
*{box-sizing:border-box;font-family:'Segoe UI',Arial,sans-serif}
body{margin:0;background:var(--bg);color:var(--txt)}
header{display:flex;align-items:center;gap:14px;padding:12px 20px;background:var(--panel);
border-bottom:1px solid var(--line);flex-wrap:wrap}
header h1{font-size:17px;margin:0;color:var(--acc)}
header .who{color:var(--dim);font-size:13px}
button{background:#1d2a44;color:var(--txt);border:1px solid var(--line);
padding:7px 13px;border-radius:7px;cursor:pointer;font-size:13px}
button:hover{border-color:var(--acc)}
button.primary{background:var(--acc);border-color:var(--acc);color:#04121f;font-weight:600}
main{padding:18px 20px;max-width:1250px;margin:auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px}
.card .k{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:24px;font-weight:700;margin-top:5px}
table{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
th{background:#182338;text-align:left;padding:9px 10px;color:var(--dim);
font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
td{padding:8px 10px;border-top:1px solid var(--line)}
.pill{padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600;display:inline-block}
.p-low,.p-resolved{background:#10321f;color:var(--ok)}
.p-medium,.p-contained{background:#332a12;color:var(--warn)}
.p-high,.p-open{background:#3a1616;color:#ff8484}
.p-critical{background:#57121f;color:#ff5d5d}
.p-healed{background:#33301a;color:#ffd76a}
.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.tabs button.on{background:var(--acc);color:#04121f;font-weight:600;border-color:var(--acc)}
.bar{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
.view{display:none}.view.on{display:block}
.timeline{list-style:none;margin:8px 0 0;padding:0;font-size:12.5px;color:var(--dim)}
.timeline li{padding:3px 0;border-left:2px solid var(--line);padding-left:10px;margin-left:6px}
.muted{color:var(--dim)}
input{background:#0e1626;border:1px solid var(--line);color:var(--txt);
padding:8px 10px;border-radius:7px;font-size:13px;width:220px}
.login-wrap{max-width:380px;margin:90px auto;background:var(--panel);
border:1px solid var(--line);border-radius:14px;padding:26px}
.login-wrap h2{margin:0 0 4px;color:var(--acc)}
.login-wrap p{color:var(--dim);font-size:13px;margin:0 0 16px}
.login-wrap input{width:100%;margin-bottom:10px}
.err{color:var(--bad);font-size:12.5px;min-height:16px;margin-bottom:6px}
.toast{position:fixed;bottom:18px;right:18px;background:var(--panel);color:var(--txt);
border:1px solid var(--acc);border-radius:9px;padding:10px 15px;font-size:13px;
display:none;z-index:9}
select{background:#0e1626;border:1px solid var(--line);color:var(--txt);
padding:8px;border-radius:7px;font-size:13px}
</style>
</head>
<body>
<div class="login-wrap" id="loginView">
  <h2>Self-Healing SOC</h2>
  <p>Sign in to the Security Operations Center</p>
  <div class="err" id="loginErr"></div>
  <input id="u" placeholder="Username" value="analyst"/>
  <input id="p" type="password" placeholder="Password" value="Analyst@12345"/>
  <button class="primary" style="width:100%" onclick="doLogin()">Sign In</button>
</div>

<div id="appView" style="display:none">
<header>
  <h1>Self-Healing SOC</h1><span class="who" id="who"></span>
  <div class="bar">
    <button onclick="genTraffic()">Generate Traffic</button>
    <button onclick="runAnalyze()">Analyze</button>
    <button onclick="healAll()">Heal All</button>
    <button onclick="loadAll(true)">Refresh</button>
    <button onclick="logout()">Logout</button>
  </div>
</header>
<main>
<div class="tabs">
  <button class="on" data-v="overview" onclick="show('overview',this)">Overview</button>
  <button data-v="events" onclick="show('events',this)">Events</button>
  <button data-v="alerts" onclick="show('alerts',this)">Alerts</button>
  <button data-v="incidents" onclick="show('incidents',this)">Incidents</button>
  <button data-v="reports" onclick="show('reports',this)">Reports</button>
</div>

<div class="view on" id="v-overview">
  <div class="cards" id="cards"></div>
  <h3 class="muted">Latest incidents</h3>
  <table id="miniInc"><thead><tr><th>#</th><th>Title</th><th>Risk</th><th>Status</th></tr></thead><tbody></tbody></table>
</div>

<div class="view" id="v-events">
  <table><thead><tr><th>ID</th><th>Time</th><th>Host</th><th>Type</th><th>Analyzed</th><th>Risk</th></tr></thead>
  <tbody id="evBody"></tbody></table>
</div>

<div class="view" id="v-alerts">
  <table><thead><tr><th>ID</th><th>Time</th><th>Host</th><th>Type</th><th>MITRE</th><th>Risk</th><th>Explanation</th></tr></thead>
  <tbody id="alBody"></tbody></table>
</div>

<div class="view" id="v-incidents"><div id="incWrap"></div></div>

<div class="view" id="v-reports">
  <div class="card" style="max-width:520px">
    <div class="k">Download PDF incident report</div>
    <div style="display:flex;gap:8px;margin-top:10px">
      <select id="repSel" style="flex:1"></select>
      <button class="primary" onclick="dlPdf()">Download PDF</button>
    </div>
    <p class="muted" style="font-size:12px">Reports include MITRE mapping, explainable-AI summary and the simulated healing timeline.</p>
  </div>
</div>
</main>
</div>
<div class="toast" id="toast"></div>

<script>
let TOKEN=null, ROLE=null;
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pill=b=>`<span class="pill p-${esc(b)}">${esc(b)}</span>`;
function toast(m){const t=$('toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2600);}
async function api(path,opt={}){
  opt.headers=Object.assign({},opt.headers||{},{Authorization:'Bearer '+TOKEN,'Content-Type':'application/json'});
  const r=await fetch(path,opt);
  if(r.status===401){logout();throw new Error('session expired');}
  if(!r.ok){const e=await r.json().catch(()=>({detail:r.statusText}));throw new Error(e.detail||r.statusText);}
  return r.json();
}
async function doLogin(){
  $('loginErr').textContent='';
  try{
    const r=await fetch('/token',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:$('u').value,password:$('p').value})});
    if(!r.ok){const e=await r.json().catch(()=>({}));$('loginErr').textContent=e.detail||'Login failed';return;}
    const d=await r.json();TOKEN=d.access_token;ROLE=d.role;
    $('loginView').style.display='none';$('appView').style.display='block';
    $('who').textContent=d.username+' ('+ROLE+')';
    document.querySelectorAll('.bar button').forEach(b=>{
      if(['Generate Traffic','Analyze','Heal All'].includes(b.textContent)&&ROLE==='viewer')b.style.display='none';});
    await loadAll(true);
  }catch(e){$('loginErr').textContent='Network error: '+e.message;}
}
function logout(){TOKEN=null;$('appView').style.display='none';$('loginView').style.display='block';}
function show(v,btn){document.querySelectorAll('.view').forEach(x=>x.classList.remove('on'));
  $('v-'+v).classList.add('on');
  document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('on'));btn.classList.add('on');}
async function genTraffic(){try{const d=await api('/demo/generate',{method:'POST',body:JSON.stringify({count:18})});toast(d.generated+' events generated');await loadAll();}catch(e){toast(e.message);}}
async function runAnalyze(){try{const d=await api('/analyze',{method:'POST'});toast(d.alerts+' alerts, '+d.incidents_created+' incidents');await loadAll();}catch(e){toast(e.message);}}
async function healAll(){try{const d=await api('/heal_all',{method:'POST'});toast(d.healed+' incidents healed');await loadAll();}catch(e){toast(e.message);}}
async function healOne(id){try{await api('/incidents/'+id+'/heal',{method:'POST'});toast('Incident #'+id+' resolved');await loadAll();}catch(e){toast(e.message);}}
async function dlPdf(){const id=$('repSel').value;if(!id)return toast('No incident selected');
  try{const r=await fetch('/report/'+id,{headers:{Authorization:'Bearer '+TOKEN}});
  if(!r.ok)throw new Error(await r.text());
  const b=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='incident_'+id+'.pdf';a.click();toast('Report downloaded');}catch(e){toast('PDF error: '+e.message);}}
function fmt(t){return (t||'').replace('T',' ').slice(0,19);}
function renderCards(ev,al,inc){
  const open=inc.filter(i=>i.status!=='resolved').length;
  const avg=ev.length?Math.round(ev.reduce((s,e)=>s+(e.risk_score||0),0)/ev.length):0;
  $('cards').innerHTML=[
    ['Events',ev.length],['High+ Alerts',al.filter(a=>['high','critical'].includes(a.risk_band)).length],
    ['Open Incidents',open],['Resolved',inc.length-open],['Avg Risk',avg]
  ].map(([k,v])=>`<div class="card"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');
  $('miniInc').querySelector('tbody').innerHTML=
    inc.slice(0,6).map(i=>`<tr><td>${i.id}</td><td>${esc(i.title)}</td><td>${pill(i.risk_band)} ${i.risk_score}</td><td>${pill(i.status)}</td></tr>`).join('');
}
function renderEvents(ev){
  $('evBody').innerHTML=ev.slice(0,60).map(e=>`<tr><td>${e.id}</td><td>${fmt(e.ts)}</td><td>${esc(e.hostname)}</td><td>${esc(e.event_type)}</td><td>${e.analyzed?'Yes':'No'}</td><td>${e.risk_score!=null?pill(e.risk_band)+' '+e.risk_score:'-'}</td></tr>`).join('');
}
function renderAlerts(al){
  $('alBody').innerHTML=al.map(a=>`<tr><td>${a.id}</td><td>${fmt(a.ts)}</td><td>${esc(a.hostname)}</td><td>${esc(a.event_type)}</td><td><b>${esc(a.mitre_id||'-')}</b> ${esc(a.mitre_name||'')}</td><td>${pill(a.risk_band)} ${a.risk_score}</td><td class="muted">${esc(a.explanation||'')}</td></tr>`).join('');
}
function renderIncidents(inc){
  const canAct=ROLE!=='viewer';
  $('incWrap').innerHTML=inc.map(i=>`
   <div class="card" style="margin-bottom:12px">
     <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
       <b>#${i.id}</b><span>${esc(i.title)}</span>
       <span><b>${esc(i.mitre_id||'')}</b> ${esc(i.mitre_name||'')}</span>
       ${pill(i.risk_band)} ${i.risk_score}
       ${pill(i.status)}
       ${i.healing_validated?'<span class="pill p-resolved">healing validated</span>':''}
       ${canAct&&i.status!=='resolved'?`<button onclick="healOne(${i.id})" style="margin-left:auto">Heal Now</button>`:''}
     </div>
     <ul class="timeline">${(i.actions||[]).map(a=>`<li>[${esc(String(a.time).slice(11,19))}] <b>${esc(a.phase)}</b> ${esc(a.action)} - ${esc(a.detail)} (${esc(a.result)})</li>`).join('')||'<li class="muted">No response executed yet.</li>'}</ul>
   </div>`).join('')||'<p class="muted">No incidents yet. Click Analyze.</p>';
}
function fillReports(inc){
  $('repSel').innerHTML=inc.map(i=>`<option value="${i.id}">#${i.id} ${esc(i.title)}</option>`).join('');
}
async function loadAll(toastIt){
  try{
    const [ev,al,inc]=await Promise.all([api('/events?limit=100'),api('/alerts'),api('/incidents')]);
    renderCards(ev,al,inc);renderEvents(ev);renderAlerts(al);renderIncidents(inc);fillReports(inc);
    if(toastIt)toast('Dashboard refreshed');
  }catch(e){if(TOKEN)toast(e.message);}
}
</script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


@app.get("/")
def root():
    return {"service": "self-healing-soc-demo", "dashboard": "/dashboard"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
