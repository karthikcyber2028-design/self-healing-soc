import json
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ["failed_logins", "unique_ports", "process_spawns", "network_rate"]

SEVERITY_BASE = {"low": 15, "medium": 35, "high": 60, "critical": 82}
EVENT_BONUS = {
    "brute_force": 20,
    "port_scan": 18,
    "suspicious_process": 22,
    "malware": 30,
    "data_exfiltration": 35,
}

MODEL_PATH = Path(os.getenv("SOC_MODEL_PATH", Path(__file__).resolve().parent / "soc_model.joblib"))
BASELINE_MEAN = np.array([2.0, 4.0, 6.0, 300.0])
BASELINE_STD = np.array([1.5, 3.0, 4.0, 250.0])

_trained = None


def _load_trained():
    global _trained, BASELINE_MEAN, BASELINE_STD
    if _trained is not None:
        return _trained
    if MODEL_PATH.exists():
        try:
            payload = joblib.load(MODEL_PATH)
            model = payload["model"] if isinstance(payload, dict) else payload
            features = payload.get("features", FEATURES) if isinstance(payload, dict) else FEATURES
            _trained = (model, list(features))
            return _trained
        except Exception:
            pass
    model = IsolationForest(contamination=0.20, random_state=42)
    normal = np.random.default_rng(42).normal(
        loc=np.array([1.0, 3.0, 4.0, 200.0]), scale=BASELINE_STD * 0.5, size=(400, 4)
    )
    model.fit(normal)
    _trained = (model, FEATURES)
    return _trained


def vector(event) -> np.ndarray:
    return np.array([[event.failed_logins, event.unique_ports, event.process_spawns, event.network_rate]])


def anomaly_score(values: np.ndarray) -> float:
    model, features = _load_trained()
    ordered = values[:, [FEATURES.index(f) for f in features]]
    decision = float(model.decision_function(ordered)[0])
    return max(0.0, min(100.0, 50.0 - 120.0 * decision))


def explain(values: np.ndarray) -> str:
    z = (values[0] - BASELINE_MEAN) / BASELINE_STD
    ranked = sorted(zip(FEATURES, z), key=lambda kv: kv[1], reverse=True)
    parts = [
        f"{name.replace('_', ' ')} is unusually high ({int(values[0][i])})"
        for i, (name, score) in enumerate(ranked[:3])
        if score > 1.5
    ]
    if not parts:
        top = ranked[0]
        parts = [f"{top[0].replace('_', ' ')} at {int(values[0][FEATURES.index(top[0])])} is the dominant signal"]
    return "; ".join(parts)


def score(event) -> dict:
    values = vector(event)
    ml_score = anomaly_score(values)
    base = SEVERITY_BASE.get(event.severity, 15)
    bonus = EVENT_BONUS.get(event.event_type, 0)
    risk = min(100.0, 0.40 * base + 0.25 * bonus + 0.35 * ml_score)
    explanation = explain(values)
    reasons = {"severity_base": base, "event_bonus": bonus, "ml_anomaly": round(ml_score, 1)}
    return {
        "risk_score": round(risk, 1),
        "ml_anomaly": round(ml_score, 1),
        "explanation": f"{explanation}. Risk composition: {json.dumps(reasons)}",
    }
