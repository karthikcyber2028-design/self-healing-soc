# 🛡 Self-Healing SOC Agent

**AI-Powered Self-Healing Security Operations Center for Automated Threat Detection and Incident Recovery**

Final-year cybersecurity project implementing the full self-healing loop:

```
Detect → Analyze → Respond → Learn → Heal
```

> ⚠️ **Safety invariant:** all automated response actions are recorded **simulations only**.
> Nothing is executed against real hosts, firewalls, accounts, or processes. Defensive/educational project.

## Architecture

```
3 Endpoint Agents (EDGE-01/02/03)
        │  telemetry
        ▼
Event Ingestion API ──► Rule Detection + ML Anomaly Detection (Isolation Forest)
        │                          │
        │                 Explainable Risk Scoring + MITRE ATT&CK Mapping
        ▼                          ▼
   Decision Engine ──► Incident Creation (risk ≥ 50, critical ≥ 80)
        ▼
Simulated Response Engine ──► Healing / Validation ──► Resolved
        ▼
Timeline · Audit Logs · Knowledge Store ↺ Learning Loop
```

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI · SQLAlchemy · PyJWT (RBAC) |
| Database | PostgreSQL (Docker) or SQLite (local/Render) |
| ML | scikit-learn Isolation Forest + explainability |
| Threat intel | MITRE ATT&CK technique mapping |
| Reports | ReportLab PDF incident reports |
| Dashboard | React 19 + Vite + Recharts (dark SOC UI) |
| Mobile | Flutter (Android & iOS) |
| ML training | Google Colab notebook (`colab/`) |
| Deployment | Docker Compose · Render |

## Live demo (Render)

The full project is configured to deploy as a single web service on Render
(`render.yaml` + root `main.py` + `render_build.sh`). It builds the React dashboard
and serves both the dashboard and the FastAPI API from one URL.

```
GET /            → React SOC dashboard (SPA)
GET /dashboard   → dashboard alias
GET /docs        → Swagger UI (API docs)
GET /health      → health check
```

Demo logins:

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@12345` |
| Analyst | `analyst` | `Analyst@12345` |
| Viewer | `viewer` | `Viewer@12345` |

### Deploy to Render

1. Connect the GitHub repo: **self-healing-soc**.
2. Render detects `render.yaml` automatically (Python, free plan).
3. Build command: `./render_build.sh` · Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
4. Open your app URL. First build takes a few minutes.

## Quick start (Docker)

```bash
docker compose up --build
```

- Dashboard → http://localhost:5173
- API → http://localhost:8000 · Docs → http://localhost:8000/docs

## Quick start (no Docker)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

```bash
# second terminal — dashboard
cd frontend
npm install
npm run dev            # http://localhost:5173
```

## Run the demo flow

```bash
# terminals 1..3 — endpoint agents
python endpoint_agent/agent.py --name EDGE-01 --url http://localhost:8000

# terminal 4 — generate synthetic attacks (safe)
python attack_simulator/simulate.py --events 50
```

Then in the dashboard (login as `analyst`): press **Analyze** on events → incidents are
created with risk scores + MITRE mapping → press **Simulate response** → containment,
healing, validation run → incident resolves → download the **PDF report**.

## Risk model

```
risk = min(100, 0.55·severity_base + 0.30·event_type_bonus + 0.45·ML_anomaly)
```

Features vector: `failed_logins`, `unique_ports`, `process_spawns`, `network_rate`.
Incident at risk ≥ 50; priority `critical` at ≥ 80.
Healing state machine: `pending → healing → validated → resolved`.

## Train a stronger model (Google Colab)

1. Open `colab/self_healing_soc_ml_training.ipynb` in Colab.
2. Upload a dataset CSV (CIC-IDS2017 / UNSW-NB15 — see `datasets/README.md`).
3. Train → download `soc_model.joblib` → place it in `backend/app/ml/soc_model.joblib`.
4. The backend automatically prefers the trained model over its built-in baseline.

## Project layout

```
self-healing-soc/
├── backend/              FastAPI app (auth/RBAC, events, incidents, reports, ML, MITRE)
├── frontend/             React SOC dashboard
├── mobile_app/           Flutter client (Android + iOS)
├── endpoint_agent/       benign telemetry agents EDGE-01/02/03
├── attack_simulator/     safe synthetic event generator
├── colab/                Colab ML training notebook
├── datasets/             dataset preparation pipeline
├── docs/                 architecture guide
├── main.py               Render entry point (API + SPA)
├── render.yaml           Render deployment config
├── render_build.sh       Render build command
└── docker-compose.yml    PostgreSQL + backend + frontend
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [PROJECT_GUIDE.md](PROJECT_GUIDE.md).
