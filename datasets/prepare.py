import argparse
from pathlib import Path

import pandas as pd

COLUMN_ALIASES = {
    "failed_logins": ["login_attempts", "failed_login_attempts", "failed_logins", "count_failed"],
    "unique_ports": ["dst_port", "destination_port", "dst_ports", "service_port"],
    "process_spawns": ["process_count", "proc_count", "processes"],
    "network_rate": ["flow_bytes_s", "bytes_per_second", "network_rate", "flow_duration_bytes"],
}

LABEL_ALIASES = ["label", "class", "attack_cat", "attack_type", "category"]


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    rename = {}
    for target, aliases in COLUMN_ALIASES.items():
        if target not in df.columns:
            for alias in aliases:
                if alias in df.columns:
                    rename[alias] = target
                    break
    df = df.rename(columns=rename)

    label = next((c for c in LABEL_ALIASES if c in df.columns), None)
    if label is not None:
        df = df.rename(columns={label: "label"})

    missing = [f for f in COLUMN_ALIASES if f not in df.columns]
    if missing:
        raise SystemExit(f"Missing required feature columns after normalization: {missing}")

    for col in COLUMN_ALIASES:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    if "label" not in df.columns:
        df["label"] = "unknown"

    return df[[*COLUMN_ALIASES, "label"]]


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare SOC training CSV")
    parser.add_argument("inputs", nargs="+", help="CSV files (e.g. CIC-IDS2017 / UNSW-NB15)")
    parser.add_argument("--out", default="datasets/soc_training.csv")
    args = parser.parse_args()

    frames = [normalize(pd.read_csv(path)) for path in args.inputs]
    combined = pd.concat(frames, ignore_index=True)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(out_path, index=False)
    print(f"Wrote {len(combined)} rows to {out_path}")
    print(combined.head())


if __name__ == "__main__":
    main()
