#!/usr/bin/env python3
"""Rank unusual identity-resource access events with graph and time features."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

REQUIRED = ["timestamp", "user", "resource", "source_ip", "action"]


def analyze(frame: pd.DataFrame, contamination: float, seed: int) -> dict[str, Any]:
    missing = [column for column in REQUIRED if column not in frame.columns]
    if missing:
        raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")
    data = frame[REQUIRED].copy()
    data["parsed_time"] = pd.to_datetime(data["timestamp"], utc=True, errors="coerce")
    data = data.dropna(subset=["parsed_time", "user", "resource", "source_ip"])
    if len(data) < 10:
        raise ValueError("at least 10 valid events are required")
    data["edge"] = data["user"].astype(str) + "→" + data["resource"].astype(str)
    data["user_degree"] = data.groupby("user")["resource"].transform("nunique")
    data["resource_degree"] = data.groupby("resource")["user"].transform("nunique")
    data["ip_fanout"] = data.groupby("source_ip")["user"].transform("nunique")
    data["ip_resource_fanout"] = data.groupby("source_ip")["resource"].transform("nunique")
    data["new_edge"] = (~data["edge"].duplicated()).astype(float)
    data["new_ip_user"] = (~(data["source_ip"].astype(str) + "→" + data["user"].astype(str)).duplicated()).astype(float)
    data["hour"] = data["parsed_time"].dt.hour
    data["after_hours"] = ((data["hour"] < 6) | (data["hour"] >= 22)).astype(float)
    data["hour_sin"] = np.sin(2 * np.pi * data["hour"] / 24)
    data["hour_cos"] = np.cos(2 * np.pi * data["hour"] / 24)
    feature_names = ["user_degree", "resource_degree", "ip_fanout", "ip_resource_fanout", "new_edge", "new_ip_user", "after_hours", "hour_sin", "hour_cos"]
    matrix = data[feature_names].to_numpy(dtype=float)
    model = IsolationForest(n_estimators=250, contamination=contamination, random_state=seed, n_jobs=1)
    model.fit(matrix)
    data["anomaly"] = model.predict(matrix) == -1
    data["anomaly_score"] = -model.decision_function(matrix)
    ranked = data.sort_values("anomaly_score", ascending=False).head(20)
    anomalies = []
    for _, row in ranked.iterrows():
        if not bool(row["anomaly"]):
            continue
        anomalies.append({"timestamp": row["timestamp"], "user": row["user"], "resource": row["resource"], "source_ip": row["source_ip"], "action": row["action"], "anomaly_score": round(float(row["anomaly_score"]), 5), "after_hours": bool(row["after_hours"]), "new_edge": bool(row["new_edge"])})
    warnings = []
    if data["user"].nunique() < 5 or data["resource"].nunique() < 5:
        warnings.append("small graph vocabulary can make relative anomaly scores unstable")
    if data["after_hours"].mean() > 0.5:
        warnings.append("more than half of events occur after hours; the time feature may dominate")
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "method": "isolation_forest_on_temporal_graph_features", "design": {"contamination": contamination, "features": feature_names}, "graph": {"events": int(len(data)), "users": int(data["user"].nunique()), "resources": int(data["resource"].nunique()), "source_ips": int(data["source_ip"].nunique()), "unique_edges": int(data["edge"].nunique())}, "summary": {"anomalies": int(data["anomaly"].sum()), "anomaly_rate": round(float(data["anomaly"].mean()), 4), "after_hours_events": int(data["after_hours"].sum())}, "anomalies": anomalies, "warnings": warnings}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 0 < args.contamination < 0.5:
        parser.error("--contamination must be between 0 and 0.5")
    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")
    try:
        report = analyze(pd.read_csv(args.input), args.contamination, args.seed)
    except ValueError as error:
        parser.error(str(error))
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
