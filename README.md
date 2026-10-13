# Cyber Threat Detection and Incident Response

A lightweight SIEM (Security Information and Event Management) platform. It
ingests security logs from four kinds of sources, detects attacks with a rule
engine and a machine-learning anomaly model, raises alerts, and groups related
findings into incidents that analysts investigate and resolve.

**Stack:** FastAPI · React + TypeScript · MongoDB · Elasticsearch · scikit-learn · Docker Compose

---

## Contents

1. [What it does](#1-what-it-does)
2. [Architecture](#2-architecture)
3. [Quick start](#3-quick-start)
4. [Demo walkthrough](#4-demo-walkthrough)
5. [Detection](#5-detection)
6. [Users, roles and security](#6-users-roles-and-security)
7. [Alert delivery](#7-alert-delivery)
8. [Configuration](#8-configuration)
9. [API overview](#9-api-overview)
10. [Development and tests](#10-development-and-tests)
11. [Project structure](#11-project-structure)
12. [Troubleshooting](#12-troubleshooting)
13. [Known limitations](#13-known-limitations)

---

## 1. What it does

| Capability | Details |
|---|---|
| **Log ingestion** | Upload Linux auth logs, Windows Security events (JSON), firewall logs, or web server access logs. Each is parsed, normalized to one schema, de-duplicated, and stored in Elasticsearch. |
| **Rule-based detection** | Eight rules mapped to MITRE ATT&CK: SSH brute force, Windows failed logins, port scan, SQL injection, XSS, directory traversal, privilege escalation, suspicious admin login. |
| **AI anomaly detection** | An Isolation Forest learns normal behaviour per source IP and flags outliers, with a risk score and an explanation of which signals were unusual. |
| **Alerting** | High and critical findings raise alerts, shown in the UI and optionally sent to email, Discord, or Telegram. |
| **Incident response** | Related detections are correlated into one incident (`INC-1001`, …) with a status workflow, analyst assignment, and an investigation timeline. |
| **Dashboard and analytics** | Live counts, a 24-hour threat timeline, severity mix, detections by type, and most active source IPs. |
| **Administration** | User management with two roles, live tuning of rule thresholds, model retraining, and an audit log of security-relevant actions. |

---

## 2. Architecture

```text
                 ┌──────────────────────────── Browser ────────────────────────────┐
                 │  React app (served by nginx, which also proxies /api → backend)  │
                 └───────────────────────────────┬──────────────────────────────────┘
                                                 │ REST + JWT
┌────────────────────────────────────────────────▼─────────────────────────────────────────────┐
│ FastAPI backend                                                                               │
│                                                                                               │
│  Upload ─► Parser ─► Normalizer ─► De-duplicate ─► Elasticsearch (logs)                       │
│  (linux / windows / firewall / web)                    │                                      │
│                                                        ▼                                      │
│                              new logs + recent stored logs (context window)                   │
│                                        │                         │                            │
│                                  Rule engine              Isolation Forest                    │
│                                        └────────────┬────────────┘                            │
│                                                     ▼                                         │
│                                    Detections (stored once, by fingerprint)                   │
│                                        │                         │                            │
│                                     Alerts ──► email / Discord / Telegram                     │
│                                        │                                                      │
│                                 Incident correlator ──► Incidents (workflow + timeline)       │
│                                                                                               │
│  MongoDB: users, detections, alerts, incidents, rule settings, upload history                 │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

Design points worth knowing:

- **Detection is attached to ingestion as a callback**, so the ingestion code
  has no dependency on the detection code.
- **Parsers, rules, ML models and alert channels are each a small class behind
  a common interface.** Adding a new one means adding one class and
  registering it.
- **Attacks split across uploads are still detected.** A new upload is
  evaluated together with stored logs from the preceding minutes
  (`DETECTION_LOOKBACK_MINUTES`).
- **Nothing is reported twice.** Each detection has a fingerprint of its rule,
  entity and evidence; re-running detection over the same logs stores nothing
  new. A repeat alert for the same entity and threat is suppressed for
  `ALERT_COOLDOWN_MINUTES`.

---

## 3. Quick start

### Prerequisites

- **Docker Desktop** (includes Docker Compose v2)
- About **8 GB of RAM** available to Docker — Elasticsearch is the heavy part

### Steps

Run these from the project folder.

**1. Create the backend settings file.**

```powershell
Copy-Item backend/.env.example backend/.env
```

**2. Set a real `JWT_SECRET_KEY` in `backend/.env`.** The backend refuses to
start with the placeholder. Generate one in PowerShell:

```powershell
$b = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
-join ($b | ForEach-Object { $_.ToString('x2') })
```

(or, with Python: `python -c "import secrets; print(secrets.token_hex(32))"`)

Paste the result as the value of `JWT_SECRET_KEY`. While you are there, change
`SEED_ADMIN_PASSWORD` if anyone else will be able to reach the app.

**3. Build and start everything.**

```powershell
docker compose up -d --build
docker compose ps
```

The first run takes several minutes. Wait until `backend` shows as healthy.

**4. Create the admin account and load the demo data.**

```powershell
docker compose exec backend python scripts/seed_admin.py
docker compose exec backend python scripts/seed_demo_data.py
```

**5. Open the app.**

| What | Where |
|---|---|
| Web app | http://localhost:5173 |
| Interactive API docs | http://localhost:8000/docs |
| Readiness check | http://localhost:8000/health/ready |

Log in with the admin account from `backend/.env` (by default `admin` /
`ChangeMe123!`), then change the password under **Settings**.

### Everyday commands

```powershell
docker compose logs -f backend      # follow backend logs
docker compose up -d --build        # rebuild after changing code
docker compose down                 # stop; data is kept
docker compose down -v              # stop and DELETE all stored data
docker compose --profile tools up -d   # also start Kibana on http://localhost:5601
```

### Sharing a temporary public demo link

```powershell
cloudflared tunnel --url http://localhost:5173
```

Change the admin password first: anyone with the link can reach the login page.

---

## 4. Demo walkthrough

`seed_demo_data.py` uploads the four files in [sample_logs/](sample_logs/),
trains the anomaly model on them, and scores them. Together they trigger
every detection rule.

1. **Dashboard** — 44 logs, 10 detections, 10 active incidents, and the charts.
2. **Live Monitoring** — search the stored logs. Try `"Failed password"` or
   an IP such as `203.0.113.50`. The search box in the top bar lands here too.
3. **Threat Detection** — rule findings with severity, confidence and MITRE
   technique; acknowledge alerts on the right. **Re-run rules** rescans the
   last 24 hours and reports only what is new.
4. **AI Anomaly Detection** — the port scanner `198.51.100.77` is flagged with
   the reasons why. **Evaluate on labeled dataset** shows precision, recall
   and F1 against 200 labeled samples.
5. **Incident Management** — open an incident, assign it, add a note, resolve
   and close it. Every step appears in its timeline.
6. **Detection Rules** — as admin, press **Tune** on SSH Brute Force and change
   the threshold; it applies immediately.
7. **Upload Logs** — upload a file from `sample_logs/` again with the same
   host name and see it recognised as duplicates.
8. **User Management** — create an analyst, then sign in as them to see the
   reduced permissions.

| Sample file | Source type | What it contains |
|---|---|---|
| `linux_auth.log` | Linux | SSH brute force, sudo to root, an off-hours root login |
| `windows_sample.json` | Windows | Failed logons, a new account, privileged logon |
| `firewall_sample.log` | Firewall | A port scan across ten ports |
| `web_access.log` | Web Server | SQL injection, XSS, directory traversal |

---

## 5. Detection

### Rules

| Rule | Fires when | MITRE ATT&CK | Tunable settings |
|---|---|---|---|
| SSH Brute Force | Repeated failed SSH logins from one IP in a short window | T1110 | `threshold`, `window_seconds` |
| Windows Failed Login | Repeated Windows logon failures (4625) from one IP | T1110.001 | `threshold`, `window_seconds` |
| Port Scan | One IP denied on many distinct ports of one host | T1046 | `distinct_port_threshold`, `window_seconds` |
| SQL Injection | Request matches SQL injection signatures | T1190 | — |
| XSS | Request matches cross-site scripting signatures | T1059.007 | — |
| Directory Traversal | Request tries to escape the web root | T1083 | — |
| Privilege Escalation | sudo to root, or Windows account/group changes | T1548 | — |
| Suspicious Admin Login | Privileged account logs in outside business hours | T1078 | `privileged_accounts`, `business_hours_start`, `business_hours_end` |

Admins change settings and enable or disable rules on the **Detection Rules**
page. Changes apply to the running engine and are saved, so they survive
restarts.

### Anomaly model

For each source IP the model looks at eight features: failed logins,
successful logins, total events, distinct event types, distinct destination
ports, distinct destination IPs, average response size, and the share of
events outside business hours.

- **Training** (admin) uses logs ingested in the last 7 days and needs at
  least 5 distinct source IPs. Each training run creates a new model version;
  older versions are kept.
- **Risk score** runs from 0 to 100, with 50 at the model's anomaly boundary
  and 100 matching the most anomalous IP seen in training. The scale is fixed
  when the model is trained, so scores are comparable between runs.
- **Explanation** names the features furthest above the training baseline,
  for example `distinct_dest_ports=10 (3.9σ above normal)`.
- **Evaluation** on the labeled dataset in [ml/datasets/](ml/datasets/)
  currently gives 90% precision and 90% recall.

---

## 6. Users, roles and security

| Action | Admin | SOC Analyst |
|---|:-:|:-:|
| View dashboard, logs, detections, alerts, incidents | ✔ | ✔ |
| Upload logs, re-run rules, score with the ML model | ✔ | ✔ |
| Work incidents (assign, note, change status), acknowledge alerts | ✔ | ✔ |
| Enable, disable or tune detection rules | ✔ | |
| Train the anomaly model | ✔ | |
| Manage users, reset passwords, send test alerts | ✔ | |

Security measures built in:

- **Passwords** are stored as bcrypt hashes and must be at least 8 characters
  with a letter and a digit.
- **Login lockout:** 5 failed attempts lock a username for 15 minutes.
- **Sessions** use a short-lived access token and a single-use refresh token.
  Signing out revokes the refresh token; changing or resetting a password
  signs out every existing session for that account.
- **Accounts are disabled, not deleted,** so incident history stays intact. An
  admin cannot disable or demote their own account, which guarantees one
  admin always remains.
- **Uploads** are limited by size (25 MB), file extension and encoding.
- **Audit log:** logins, user changes, rule changes, alerts and incident
  actions are written to `logs/audit.log` inside the backend container.
- **Network exposure:** only the web app is published on the network.
  MongoDB, Elasticsearch, Kibana and the API docs listen on `localhost` only.

---

## 7. Alert delivery

Every high or critical alert is shown in the app. To also send them
elsewhere, fill in the relevant variables in `backend/.env` and restart the
backend (`docker compose up -d backend`):

| Channel | Variables |
|---|---|
| Email | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO` (a JSON list, e.g. `["soc@example.com"]`) |
| Discord | `DISCORD_WEBHOOK_URL` |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |

**Settings → Alert delivery** shows which channels are configured, and lets an
admin send a test alert to confirm they work.

---

## 8. Configuration

All backend settings live in `backend/.env`; [backend/.env.example](backend/.env.example)
documents every one. The most relevant:

| Variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET_KEY` | — | **Required.** Token signing key, at least 32 characters. |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | 60 | Access token lifetime |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | 7 | Refresh token lifetime |
| `LOGIN_MAX_FAILED_ATTEMPTS` | 5 | Failed logins before lockout |
| `LOGIN_LOCKOUT_MINUTES` | 15 | Lockout duration |
| `DETECTION_LOOKBACK_MINUTES` | 10 | Stored logs evaluated alongside a new upload |
| `ALERT_COOLDOWN_MINUTES` | 30 | Suppression period for repeat alerts |
| `MAX_UPLOAD_FILE_SIZE_MB` | 25 | Upload size limit |
| `SEED_ADMIN_*` | admin / ChangeMe123! | First admin account, used by the seed scripts |

Docker Compose sets `MONGO_URI`, `ELASTIC_HOST`, `APP_ENV=production` and
`DEBUG=false` for the backend container itself.

---

## 9. API overview

Base path `/api/v1`. Full interactive documentation: http://localhost:8000/docs

| Area | Endpoints |
|---|---|
| Sessions | `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/change-password`, `GET /auth/me` |
| Users (admin) | `GET /users`, `POST /users`, `PATCH /users/{username}`, `POST /users/{username}/reset-password`, `GET /users/assignable` |
| Logs | `POST /logs/upload`, `POST /logs/ingest`, `GET /logs/search`, `GET /logs/batches` |
| Detections | `GET /detections`, `POST /detections/run` |
| Alerts | `GET /alerts`, `POST /alerts/{id}/acknowledge`, `GET /alerts/channels`, `POST /alerts/test` |
| Anomaly model | `POST /ml/train`, `POST /ml/predict`, `GET /ml/models`, `POST /ml/evaluate` |
| Incidents | `GET /incidents`, `GET /incidents/{ref}`, `PATCH .../status`, `PATCH .../assign`, `POST .../notes` |
| Rules | `GET /rules`, `PATCH /rules/{rule_name}` |
| Analytics | `GET /analytics/summary`, `/top-ips`, `/severity-distribution`, `/threat-timeline`, `/attack-types`, `/recent-events` |
| Health | `GET /health`, `GET /health/ready` |

---

## 10. Development and tests

### Run the tests

```powershell
docker compose exec backend python -m pytest
```

The backend suite needs no running database: MongoDB is replaced by an
in-memory fake and Elasticsearch calls are stubbed.

### Work on the code without rebuilding containers

Start only the databases, then run the backend and frontend on your machine
(requires Python 3.12 and Node.js 22):

```powershell
docker compose up -d mongo elasticsearch

# Backend — in backend/.env set:
#   MONGO_URI=mongodb://localhost:27017
#   ELASTIC_HOST=http://localhost:9200
#   ML_MODEL_DIR=../ml/models
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/seed_admin.py
uvicorn app.main:app --reload --port 8000

# Frontend — in a second terminal
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api to the backend
```

Frontend checks: `npm run typecheck`, `npm run lint`, `npm run build`.

---

## 11. Project structure

```text
├── backend/
│   ├── app/
│   │   ├── api/v1/        REST endpoints, one file per area
│   │   ├── core/          settings, JWT and passwords, role checks, login lockout, logging
│   │   ├── db/            MongoDB and Elasticsearch access
│   │   ├── models/        request, response and storage schemas
│   │   ├── ingestion/     parsers, normalizer, ingestion pipeline
│   │   ├── detection/     rule engine and rules, ML model, alert generation, detection service
│   │   ├── alerts/        delivery channels (email, Discord, Telegram) and dispatcher
│   │   ├── incidents/     detection-to-incident correlation and incident workflow
│   │   └── main.py        application entry point
│   ├── scripts/           seed_admin.py, seed_demo_data.py
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── api/           HTTP client, endpoint paths, token storage
│   │   ├── services/      one module per backend area
│   │   ├── features/      one folder per page
│   │   ├── components/    layout and shared UI components
│   │   ├── routes/        routing and access guards
│   │   ├── lib/           formatting and error helpers
│   │   └── types/         TypeScript types mirroring the API
│   └── nginx.conf         serves the built app and proxies /api
├── elasticsearch/mappings/   index mapping for stored logs
├── ml/datasets/              labeled evaluation dataset and its generator
├── ml/models/                trained model versions (created at runtime)
├── sample_logs/              demo log files
└── docker-compose.yml
```

---

## 12. Troubleshooting

| Symptom | What to try |
|---|---|
| `Cannot connect to the Docker daemon` | Start Docker Desktop and wait until it is ready. |
| Backend keeps restarting | `docker compose logs backend`. Usually `JWT_SECRET_KEY` is still the placeholder or shorter than 32 characters. |
| Frontend container does not start | It waits for the backend to be healthy — fix the backend first. |
| Login fails | Run `seed_admin.py`; check you are typing `SEED_ADMIN_PASSWORD` from `backend/.env`. |
| "Too many failed attempts" | The username is locked for 15 minutes after 5 wrong passwords. |
| Dashboard is empty | Run `seed_demo_data.py`. The dashboard counts logs ingested in the last 24 hours. |
| Model training says it needs more source IPs | Ingest more logs first; training needs 5 distinct source IPs from the last 7 days. |
| Elasticsearch unhealthy or out of memory | Give Docker more memory (8 GB or more) and restart it. |
| Everyone was signed out after a restart | `JWT_SECRET_KEY` changed. Keep it stable. |

Start again from scratch, deleting all stored data:

```powershell
docker compose down -v
docker compose up -d --build
docker compose exec backend python scripts/seed_admin.py
docker compose exec backend python scripts/seed_demo_data.py
```

---

## 13. Known limitations

This is a final-year project built to demonstrate how a SIEM works, not a
hardened production product.

- **Single node.** MongoDB and Elasticsearch run without authentication or
  replication; they are reachable from `localhost` only.
- **Batch ingestion.** Logs arrive by upload or API call; there is no agent
  that streams them from hosts in real time.
- **Signature-based web rules** can be evaded by obfuscation the patterns do
  not cover. The anomaly model is the complement, not a guarantee.
- **The anomaly model profiles source IPs only,** not users or hosts, and is
  only as good as the logs it was trained on.
- **Linux syslog lines carry no year,** so the year is inferred from the
  current date.
- **Browser sessions** keep tokens in web storage, which is simpler than
  cookies but readable by any script injected into the page.
