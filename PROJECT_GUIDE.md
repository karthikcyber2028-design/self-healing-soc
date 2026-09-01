# Final-Year Project Guide

**Suggested title:** *AI-Powered Self-Healing Security Operations Center (SOC) Agent for Automated Threat Detection and Incident Recovery*

## Modules (16)

1. Introduction to SOC operations & the self-healing concept
2. System architecture & threat model
3. Event ingestion API design
4. Rule-based detection
5. Machine-learning anomaly detection (Isolation Forest)
6. Explainable AI risk scoring
7. MITRE ATT&CK technique mapping
8. Decision engine & incident prioritization
9. Automated response simulation & safety boundaries
10. Self-healing workflow: containment → healing → validation → recovery
11. Knowledge store, timeline & audit logging
12. JWT authentication & role-based access control
13. SOC dashboard visualization
14. Mobile SOC client (Flutter)
15. Model training on public cybersecurity datasets (Colab)
16. Evaluation, metrics & future work

## Demo scenarios

| Scenario | Steps |
|---|---|
| A — Brute force | run simulator → analyze `brute_force` event → T1110 mapping → high-risk incident → simulate response |
| B — Port scan | `port_scan` event → T1046 → medium/high incident |
| C — Suspicious process | `suspicious_process` → T1059 execution mapping |
| D — Data exfiltration | `data_exfiltration` → T1041 → critical priority |

## Academic extensions

- Train on **CIC-IDS2017 / UNSW-NB15** via the Colab notebook; report precision/recall/F1/FPR
- Add SHAP for deeper explainability
- Prometheus/Grafana metrics export; MTTD/MTTR measurement
- Reinforcement-learning response policy (simulation)
- Named Cloudflare Tunnel or cloud deployment for the live demo

## Suggested thesis chapters (12)

1. Introduction  2. Literature Review  3. Requirements  4. Architecture Design
5. Implementation — Backend  6. Implementation — Detection & ML  7. Implementation — Response/Healing
8. Implementation — Dashboard & Mobile  9. Dataset & Model Training  10. Testing & Results
11. Security, Ethics & Limitations  12. Conclusion & Future Work

## Public demo link (temporary)

```bash
docker compose up --build
cloudflared tunnel --url http://localhost:5173
# → https://<random>.trycloudflare.com   (share this as your demo link)
```
