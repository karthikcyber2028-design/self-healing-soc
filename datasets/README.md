# Datasets

The SOC ML model uses 4 features:

| Feature | Meaning |
|---|---|
| `failed_logins` | failed login attempts in the window |
| `unique_ports` | unique destination ports touched |
| `process_spawns` | processes spawned on the endpoint |
| `network_rate` | outbound network flow rate (bytes/s) |

## Pipeline

1. Download an open cybersecurity dataset, e.g.
   - **CIC-IDS2017** (Canadian Institute for Cybersecurity) — check license terms
   - **UNSW-NB15** — check license terms
2. Normalize column names to the 4 features above (`datasets/prepare.py` maps common aliases).
3. Run:
   ```bash
   python datasets/prepare.py cic_ids_2017_part1.csv cic_ids_2017_part2.csv --out datasets/soc_training.csv
   ```
4. Train with the Colab notebook `colab/self_healing_soc_ml_training.ipynb`
   (or locally: IsolationForest, contamination≈0.10).
5. Export the trained artifact as `soc_model.joblib` containing
   `{"model": <IsolationForest>, "features": [...]}` and copy it to
   `backend/app/ml/soc_model.joblib`. The backend automatically prefers the trained
   model and falls back to its built-in baseline.

> ⚠️ Respect dataset licenses; both CIC-IDS2017 and UNSW-NB15 require attribution and have usage restrictions.
