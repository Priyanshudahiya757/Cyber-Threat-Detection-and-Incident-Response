#!/usr/bin/env python3
"""
scripts/seed_demo_data.py

Uploads all sample_logs into the running API so the dashboard is populated
for mentor demos. Requires the backend to be up and an admin user seeded.

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

SAMPLE_MAP = [
    ("linux_auth.log", "linux", "linux-web01"),
    ("windows_sample.json", "windows", "win-dc01"),
    ("firewall_sample.log", "firewall", "fw-edge01"),
    ("web_access.log", "web_server", "apache-web02"),
]


def find_sample_dir() -> Path:
    candidates = [
        Path("/sample_logs"),
        Path(__file__).resolve().parents[2] / "sample_logs",
        Path.cwd() / "sample_logs",
        Path.cwd().parent / "sample_logs",
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
    base = args.base_url.rstrip("/")

    with httpx.Client(timeout=120.0) as client:
        login = client.post(
            f"{base}/api/v1/auth/login",
            json={"username": args.username, "password": args.password},
        )
        if login.status_code != 200:
            print(f"Login failed: {login.status_code} {login.text}", file=sys.stderr)
            return 1

        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        for filename, source_type, host in SAMPLE_MAP:
            path = sample_dir / filename
            if not path.exists():
                print(f"SKIP missing {path}")
                continue
            with path.open("rb") as fh:
                files = {"file": (filename, fh, "application/octet-stream")}
                data = {"source_type": source_type, "source_host": host}
                resp = client.post(
                    f"{base}/api/v1/logs/upload",
                    headers=headers,
                    data=data,
                    files=files,
                )
            if resp.status_code not in (200, 201):
                print(f"FAIL {filename}: {resp.status_code} {resp.text}")
            else:
                body = resp.json()
                print(
                    f"OK  {filename}: accepted={body.get('accepted')} "
                    f"rejected={body.get('rejected')} duplicates={body.get('duplicates')}"
                )

        # Optional: train ML if enough data
        train = client.post(f"{base}/api/v1/ml/train?days=7", headers=headers)
        if train.status_code in (200, 201):
            print(f"ML train OK: {train.json().get('version')}")
        else:
            print(f"ML train skipped/failed: {train.status_code} {train.text[:200]}")

        dets = client.get(f"{base}/api/v1/detections?limit=5", headers=headers)
        incs = client.get(f"{base}/api/v1/incidents?limit=5", headers=headers)
        print(f"Detections: {dets.json().get('count') if dets.status_code == 200 else 'n/a'}")
        print(f"Incidents: {incs.json().get('count') if incs.status_code == 200 else 'n/a'}")

    print("Demo seed complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
