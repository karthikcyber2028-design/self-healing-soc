# Architecture

## Pipeline

```
┌──────────────────────┐
│  Endpoint Agents     │  EDGE-01 / EDGE-02 / EDGE-03 (benign telemetry, 5s)
└──────────┬───────────┘
           │ POST /api/events
           ▼
┌──────────────────────┐
│  Event Ingestion API │  FastAPI · SQLAlchemy
└──────────┬───────────┘
           ▼
┌──────────────────────┐    ┌───────────────────────────────┐
│  Rule Detection      │    │  ML Anomaly Detection         │
│  severity + type     │    │  Isolation Forest             │
└──────────┬───────────┘    └───────────────┬───────────────┘
           └──────────────┬─────────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  Explainable Risk Scoring    │  z-score feature attribution
           │  + MITRE ATT&CK Mapping      │  T1110 T1046 T1059 T1204 T1041
           └──────────────┬───────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  Decision Engine             │  risk ≥ 65 → incident (≥85 critical)
           └──────────────┬───────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  Simulated Response Engine   │  containment recorded as SIMULATION ONLY
           └──────────────┬───────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  Healing & Validation        │  pending → contained → healing → validated → resolved
           └──────────────┬───────────────┘
                          ▼
           Timeline · Audit Logs · Knowledge Store  ↺ learning loop
```

## Components

| Component | Location | Responsibility |
|---|---|---|
| Auth + RBAC | `backend/app/routers/auth.py`, `backend/app/security.py` | PBKDF2 password hashing, JWT HS256 (8h), roles viewer/analyst/admin |
| Event ingestion | `backend/app/routers/soc.py` | POST/GET events |
| Detection | `backend/app/ml/scoring.py` | Isolation Forest anomaly score, weighted risk formula, explainability |
| Threat mapping | `backend/app/mitre.py` | event type → MITRE ATT&CK technique |
| Decision engine | `backend/app/routers/soc.py` | incident creation thresholds, timeline entries |
| Response/healing | `backend/app/routers/soc.py` | simulated containment → healing → validation state machine |
| Reports | `backend/app/routers/reports.py` | ReportLab PDF per incident with timeline |
| Dashboard | `frontend/src/App.jsx` | login, stats cards, chart, events/incidents tables, actions |
| Mobile | `mobile_app/lib/main.dart` | Flutter client: login, overview, events, incidents |

## Security controls

- JWT authentication on all mutating endpoints; RBAC (`viewer` read-only).
- PBKDF2-HMAC-SHA256 (180k iterations) password storage; no plaintext.
- Full audit log of logins, analyses and simulated responses.
- Human-in-the-loop boundary: response is analyst-triggered and simulation-only.
- No arbitrary command execution anywhere in the codebase.

## Data model

- **User** — username, password_hash, role, active
- **Event** — endpoint, event_type, source_ip, severity, 4 features, analyzed, risk_score, explanation, mitre_technique
- **Incident** — event_id, title, status, priority, risk_score, response_status, healing_status
- **Timeline** — per-incident actor/action/detail audit trail
- **AuditLog** — global user action log

## MITRE ATT&CK mapping

| Event type | Technique | Name | Tactic |
|---|---|---|---|
| brute_force | T1110 | Brute Force | Credential Access |
| port_scan | T1046 | Network Service Scanning | Discovery |
| suspicious_process | T1059 | Command and Scripting Interpreter | Execution |
| malware | T1204 | User Execution | Execution |
| data_exfiltration | T1041 | Exfiltration Over C2 Channel | Exfiltration |
