import argparse
import socket
import time
import uuid

import requests

BENIGN_TYPES = ["login", "login", "login", "suspicious_process"]


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def post_event(url: str, name: str) -> None:
    payload = {
        "endpoint": name,
        "event_type": BENIGN_TYPES[int(time.time()) % len(BENIGN_TYPES)],
        "source_ip": local_ip(),
        "severity": "low",
        "message": f"benign telemetry heartbeat {uuid.uuid4().hex[:8]}",
        "failed_logins": 0,
        "unique_ports": int(time.time() % 5) + 1,
        "process_spawns": int(time.time() % 7),
        "network_rate": float(50 + (int(time.time()) % 200)),
    }
    try:
        r = requests.post(f"{url}/api/events", json=payload, timeout=5)
        print(f"[{name}] {r.status_code} {payload['event_type']}")
    except requests.RequestException as exc:
        print(f"[{name}] backend unreachable: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Self-Healing SOC benign endpoint agent")
    parser.add_argument("--name", default="EDGE-01")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()

    print(f"Endpoint agent {args.name} -> {args.url} every {args.interval}s")
    while True:
        post_event(args.url, args.name)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
