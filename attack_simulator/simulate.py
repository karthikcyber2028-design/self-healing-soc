import argparse
import random

import requests

ATTACK_PATTERNS = {
    "brute_force": dict(severity="high", failed_logins=random.randint(12, 60), unique_ports=2,
                        process_spawns=3, network_rate=800.0,
                        message="multiple failed logins from single source"),
    "port_scan": dict(severity="medium", failed_logins=0, unique_ports=random.randint(40, 200),
                      process_spawns=1, network_rate=1500.0,
                      message="rapid connection attempts across many ports"),
    "suspicious_process": dict(severity="high", failed_logins=1, unique_ports=6,
                               process_spawns=random.randint(25, 90), network_rate=600.0,
                               message="unusual process tree spawned after login"),
    "malware": dict(severity="critical", failed_logins=2, unique_ports=10,
                    process_spawns=random.randint(40, 120), network_rate=2500.0,
                    message="known-bad hash executed on host"),
    "data_exfiltration": dict(severity="critical", failed_logins=0, unique_ports=4,
                              process_spawns=8, network_rate=random.randint(9000, 40000),
                              message="large outbound transfer to external IP"),
}

NORMAL = dict(event_type="login", severity="low", failed_logins=0, unique_ports=2,
              process_spawns=2, network_rate=120.0, message="routine activity")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe synthetic SOC event generator (simulation only)"
    )
    parser.add_argument("--events", type=int, default=30)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--attack-ratio", type=float, default=0.45)
    args = parser.parse_args()

    endpoints = ["EDGE-01", "EDGE-02", "EDGE-03"]
    created = 0
    for _ in range(args.events):
        if random.random() < args.attack_ratio:
            event_type = random.choice(list(ATTACK_PATTERNS))
            fields = ATTACK_PATTERNS[event_type]
        else:
            event_type = NORMAL["event_type"]
            fields = NORMAL
        payload = {
            "endpoint": random.choice(endpoints),
            "source_ip": f"10.0.{random.randint(0, 5)}.{random.randint(2, 250)}",
            **fields,
            "event_type": event_type,
        }
        try:
            r = requests.post(f"{args.url}/api/events", json=payload, timeout=5)
            if r.ok:
                created += 1
                print(f"+ {payload['endpoint']:8s} {event_type:20s} severity={fields['severity']}")
        except requests.RequestException as exc:
            print(f"backend unreachable: {exc}")
            break

    print(f"\nCreated {created}/{args.events} events at {args.url}")


if __name__ == "__main__":
    main()
