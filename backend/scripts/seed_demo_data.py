#!/usr/bin/env python3
"""
scripts/seed_demo_data.py

Uploads the files in sample_logs/ through the running API so the
dashboard is populated for a demo, then trains the anomaly model on them
and scores them. Requires the backend to be up and an admin user seeded
(scripts/seed_admin.py). Safe to run more than once: logs and findings
that already exist are skipped.

Usage (from project root, with compose running):
  docker compose exec backend python scripts/seed_demo_data.py

Or locally:
  python scripts/seed_demo_data.py --base-url http://localhost:8000
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import httpx

#: (file in sample_logs/, source_type, source_host)
SAMPLE_MAP = [
    ("linux_auth.log", "linux", "linux-web01"),
    ("windows_sample.json", "windows", "win-dc01"),
    ("firewall_sample.log", "firewall", "fw-edge01"),
    ("web_access.log", "web_server", "apache-web02"),
]


def find_sample_dir() -> Path:
    candidates = [
        Path("/sample_logs"),  # docker-compose mount
        Path(__file__).resolve().parents[2] / "sample_logs",  # repository layout
    ]
    for path in candidates:
        if path.is_dir():
            return path
    raise FileNotFoundError("sample_logs directory not found")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed demo logs into the SIEM API")
    parser.add_argument("--base-url", default=os.getenv("API_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--username", default=os.getenv("SEED_ADMIN_USERNAME", "admin"))
    parser.add_argument("--password", default=os.getenv("SEED_ADMIN_PASSWORD", "ChangeMe123!"))
    args = parser.parse_args()

    sample_dir = find_sample_dir()
    api = f"{args.base_url.rstrip('/')}/api/v1"

    with httpx.Client(timeout=120.0) as client:
        login = client.post(f"{api}/auth/login", json={"username": args.username, "password": args.password})
        if login.status_code != 200:
            print(f"Login failed: {login.status_code} {login.text}", file=sys.stderr)
            return 1
        client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"

        failures = 0
        for filename, source_type, host in SAMPLE_MAP:
            path = sample_dir / filename
            if not path.exists():
                print(f"MISSING {path}", file=sys.stderr)
                failures += 1
                continue
            with path.open("rb") as handle:
                response = client.post(
                    f"{api}/logs/upload",
                    data={"source_type": source_type, "source_host": host},
                    files={"file": (filename, handle, "text/plain")},
                )
            if response.status_code != 201:
                print(f"FAIL {filename}: {response.status_code} {response.text}", file=sys.stderr)
                failures += 1
                continue
            body = response.json()
            print(
                f"OK   {filename}: accepted={body['accepted']} "
                f"rejected={body['rejected']} duplicates={body['duplicates']}"
            )

        train = client.post(f"{api}/ml/train", params={"days": 1})
        if train.status_code == 201:
            print(f"ML model trained: {train.json()['version']} on {train.json()['n_samples']} entities")
            score = client.post(f"{api}/ml/predict", params={"minutes": 60})
            if score.status_code == 200:
                print(f"ML scoring: {score.json()['detections_found']} new anomaly detection(s)")
        else:
            print(f"ML training skipped: {train.status_code} {train.text[:200]}")

        summary = client.get(f"{api}/analytics/summary").json()
        print(
            f"Totals: {summary['total_logs']} logs, {summary['threats_detected']} detections, "
            f"{summary['active_incidents']} active incidents"
        )

    print("Demo seed complete." if not failures else f"Demo seed finished with {failures} failure(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
