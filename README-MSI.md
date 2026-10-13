# Cyber Threat Detection and Incident Response Dashboard

Lightweight SIEM-style platform for **log ingestion**, **rule-based + AI threat detection**, and **SOC incident response**.

Stack: **FastAPI** · **React (TypeScript)** · **MongoDB** · **Elasticsearch** · **Docker Compose**

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Project location](#2-project-location)
3. [Recommended: run with Docker Compose](#3-recommended-run-with-docker-compose)
4. [First-time setup checklist](#4-first-time-setup-checklist)
5. [Seed admin user and demo data](#5-seed-admin-user-and-demo-data)
6. [Access URLs and default login](#6-access-urls-and-default-login)
7. [Demo walkthrough](#7-demo-walkthrough)
8. [Useful Docker commands](#8-useful-docker-commands)
9. [Optional: run locally without Docker (dev)](#9-optional-run-locally-without-docker-dev)
10. [Environment variables](#10-environment-variables)
11. [API overview](#11-api-overview)
12. [Tests](#12-tests)
13. [Project structure](#13-project-structure)
14. [Troubleshooting](#14-troubleshooting)

---

## Find files quickly

| Need | Open |
|---|---|
| Start whole app | `docker-compose.yml` |
| Backend API entry | `backend/app/main.py` |
| Detection rules | `backend/app/detection/rules/` |
| ML detection | `backend/app/detection/ml/` |
| Incident workflow | `backend/app/incidents/` |
| Log parsers | `backend/app/ingestion/parsers/` |
| Backend tests | `backend/tests/` |
| Frontend pages | `frontend/src/features/` |
| API client code | `frontend/src/api/` |
| Architecture and launch docs | `docs/` |
| Demo attack logs | `sample_logs/` |
| PPT, PDF, submission assets | `deliverables/` |

---

## 1. Prerequisites

| Tool | Version (recommended) | Purpose |
|------|------------------------|---------|
| **Docker Desktop** | Latest stable | Runs MongoDB, Elasticsearch, backend, frontend |
| **Docker Compose** | v2 (bundled with Docker Desktop) | Orchestrates services |
| **Git** | Any recent | Optional, if cloning |
| **8 GB+ RAM** | — | Elasticsearch needs heap; 512 MB configured in Compose |

Optional (only for non-Docker local backend/frontend):

- Python **3.12+**
- Node.js **20+** / **22+** and npm

---

## 2. Project location

All application code and `docker-compose.yml` live in this workspace root:

```text
cyber threat detection/
```

Open a terminal in this workspace before running any commands below:

```bash
cd "C:\Users\pd177\OneDrive\Desktop\cyber threat detection"
```

---

## 3. Recommended: run with Docker Compose

This is the **supported** way to run the full stack (MongoDB + Elasticsearch + API + UI).

### Step A — Create backend environment file

```bash
cp backend/.env.example backend/.env
```

Generate a JWT secret and put it in `backend/.env`:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Edit `backend/.env` and set at least:

```env
JWT_SECRET_KEY=<paste-generated-secret-here>
SEED_ADMIN_USERNAME=admin
SEED_ADMIN_EMAIL=admin@example.com
SEED_ADMIN_PASSWORD=ChangeMe123!
```

> Compose overrides `MONGO_URI` and `ELASTIC_HOST` to the Docker service names (`mongo`, `elasticsearch`). Keep the example values for Docker runs.

### Step B — (Optional) Frontend env

```bash
cp frontend/.env.example frontend/.env
```

Recommended contents for Docker / Vite proxy:

```env
VITE_API_BASE_URL=/api/v1
VITE_BACKEND_ORIGIN=http://backend:8000
VITE_USE_MOCKS_FOR_UNIMPLEMENTED=false
```

Compose already sets these for the frontend container; a local `frontend/.env` helps if you run Vite on the host later.

### Step C — Start the stack

From workspace root:

```bash
docker compose up -d --build
```

First run may take several minutes (image pulls + builds).

### Step D — Wait until healthy

```bash
docker compose ps
```

You should see roughly:

| Service | Container | Port |
|---------|-----------|------|
| mongo | `siem-mongo` | `27017` |
| elasticsearch | `siem-elasticsearch` | `9200` |
| kibana (optional) | `siem-kibana` | `5601` |
| backend | `siem-backend` | `8000` |
| frontend | `siem-frontend` | `5173` |

Check API liveness:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/health/ready
```

---

## 4. First-time setup checklist

After containers are up:

1. [ ] `backend/.env` exists with a real `JWT_SECRET_KEY`
2. [ ] `docker compose ps` shows backend + frontend running
3. [ ] `/health` returns `ok`
4. [ ] Admin user seeded (next section)
5. [ ] Demo logs seeded (next section)
6. [ ] Login works at http://localhost:5173

---

## 5. Seed admin user and demo data

### Create the first admin account

```bash
docker compose exec backend python scripts/seed_admin.py
```

Uses `SEED_ADMIN_*` from `backend/.env` (defaults: `admin` / `ChangeMe123!`).

### Populate dashboard with sample attacks

Uploads Windows / Linux / firewall / web sample logs, runs detection, creates incidents:

```bash
docker compose exec backend python scripts/seed_demo_data.py
```

Or from the host (with stack running):

```bash
# requires: pip install httpx
python3 backend/scripts/seed_demo_data.py --base-url http://localhost:8000
```

Sample files are under `sample_logs/`:

- `linux_auth.log` — SSH brute force / sudo
- `windows_sample.json` — Windows auth events
- `firewall_sample.log` — port scan style denies
- `web_access.log` — SQLi, XSS, traversal

---

## 6. Access URLs and default login

| Resource | URL |
|----------|-----|
| **SOC Dashboard (UI)** | http://localhost:5173 |
| **API docs (Swagger)** | http://localhost:8000/docs |
| **API health** | http://localhost:8000/health |
| **API readiness** | http://localhost:8000/health/ready |
| **Kibana** (optional) | http://localhost:5601 |
| **Elasticsearch** | http://localhost:9200 |
| **MongoDB** | `localhost:27017` |

**Default login** (after seed):

| Field | Value |
|-------|--------|
| Username | `admin` |
| Password | `ChangeMe123!` |

Change `SEED_ADMIN_PASSWORD` before production or shared demos.

---

## 7. Demo walkthrough

1. Open http://localhost:5173 and log in.
2. **Dashboard** — cards (logs, threats, incidents, critical alerts, AI anomalies) and charts.
3. **Upload Logs** — upload a file from `sample_logs/` with matching source type.
4. **Live Monitoring** — search normalized logs in Elasticsearch.
5. **Threat Detection** — rule hits and alerts; optional “Re-run rules”.
6. **Anomaly Detection** (admin) — Train model → Score window → Evaluate.
7. **Incidents** — open `INC-*`, assign analyst, add notes, resolve/close.
8. **Detection Rules** (admin) — enable/disable rules without redeploy.
9. **Analytics** — severity, attack types, top IPs.

End-to-end pipeline:

```text
Upload log → Parse → Normalize → Elasticsearch
    → Rule engine + AI → Detections / Alerts
    → Incident correlator → Dashboard / Analytics
```

---

## 8. Useful Docker commands

```bash
# Status
docker compose ps

# Logs (follow)
docker compose logs -f backend
docker compose logs -f frontend

# Restart one service
docker compose restart backend

# Rebuild after dependency changes
docker compose up -d --build

# Stop stack (keep data volumes)
docker compose stop

# Stop and remove containers (volumes kept)
docker compose down

# Stop and wipe Mongo + ES data (destructive)
docker compose down -v
```

---

## 9. Optional: run locally without Docker (dev)

Use this only if you want hot-reload outside containers. You still need **MongoDB** and **Elasticsearch** (easiest: start only infra with Compose).

### 9.1 Start databases only

```bash
cd "C:\Users\pd177\OneDrive\Desktop\cyber threat detection"
docker compose up -d mongo elasticsearch
```

### 9.2 Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Point `.env` at host-exposed DB ports:

```env
MONGO_URI=mongodb://localhost:27017
ELASTIC_HOST=http://localhost:9200
JWT_SECRET_KEY=<your-secret>
```

```bash
python scripts/seed_admin.py
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 9.3 Frontend

```bash
cd frontend
npm install
cp .env.example .env
```

```env
VITE_API_BASE_URL=/api/v1
VITE_BACKEND_ORIGIN=http://localhost:8000
VITE_USE_MOCKS_FOR_UNIMPLEMENTED=false
```

```bash
npm run dev
```

UI: http://localhost:5173 (Vite proxies `/api` and `/health` to the backend).

### 9.4 Frontend production build check

```bash
cd frontend
npm run typecheck
npm run build
```

---

## 10. Environment variables

### Backend (`backend/.env`)

| Variable | Meaning |
|----------|---------|
| `MONGO_URI` / `MONGO_DB_NAME` | Mongo connection |
| `ELASTIC_HOST` / `ELASTIC_LOG_INDEX_PREFIX` | Elasticsearch |
| `JWT_SECRET_KEY` | **Required** — signing key for tokens |
| `CORS_ORIGINS` | Allowed frontend origins |
| `SEED_ADMIN_*` | Bootstrap admin for `seed_admin.py` |
| `ML_MODEL_DIR` | Where trained models are stored |
| `MAX_UPLOAD_FILE_SIZE_MB` | Upload size limit |

### Frontend (`frontend/.env`)

| Variable | Meaning |
|----------|---------|
| `VITE_API_BASE_URL` | API prefix (default `/api/v1`) |
| `VITE_BACKEND_ORIGIN` | Proxy target for Vite / Compose |
| `VITE_USE_MOCKS_FOR_UNIMPLEMENTED` | Keep `false` for live APIs |

---

## 11. API overview

Base path: `/api/v1`

| Area | Examples |
|------|----------|
| Auth | `POST /auth/login`, `GET /auth/me`, `POST /auth/register` (admin) |
| Logs | `POST /logs/upload`, `GET /logs/search`, `GET /logs/batches` |
| Detections | `GET /detections`, `GET /detections/alerts`, `POST /detections/run` |
| ML | `POST /ml/train`, `POST /ml/predict`, `POST /ml/evaluate` |
| Incidents | `GET /incidents`, `PATCH /incidents/{ref}/status`, `.../assign`, `.../notes` |
| Analytics | `GET /analytics/summary`, `/top-ips`, `/severity-distribution`, … |
| Rules | `GET /rules`, `PATCH /rules/{rule_name}` (admin) |

Interactive docs: http://localhost:8000/docs

---

## 12. Tests

Inside the backend container (recommended — same deps as runtime):

```bash
docker compose exec backend python -m pytest tests/ -v
```

Or on the host with a venv + `requirements.txt` installed:

```bash
cd backend
python -m pytest tests/ -v
```

---

## 13. Project structure

```text
cyber-threat-dashboard/
├── backend/
│   ├── app/
│   │   ├── api/v1/           # REST routers
│   │   ├── core/             # config, JWT, RBAC, logging
│   │   ├── db/               # Mongo + Elasticsearch repositories
│   │   ├── ingestion/        # parsers, normalizer, pipeline
│   │   ├── detection/        # rules, ML, alerting
│   │   ├── incidents/        # correlator + service
│   │   └── main.py           # FastAPI entrypoint
│   ├── scripts/
│   │   ├── seed_admin.py
│   │   └── seed_demo_data.py
│   ├── tests/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/              # Axios client + endpoints
│   │   ├── features/         # pages (dashboard, logs, incidents, …)
│   │   ├── services/         # API service layer
│   │   └── routes/
│   ├── Dockerfile
│   └── package.json
├── elasticsearch/mappings/   # ES index mapping template
├── ml/datasets/              # labeled ML evaluation data
├── ml/models/                # trained artifacts (runtime)
├── sample_logs/              # demo log fixtures
├── docs/architecture.md
└── docker-compose.yml
```

---

## 14. Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `Cannot connect to the Docker daemon` | Start **Docker Desktop**, wait until it is ready, retry |
| Backend stuck / port 8000 busy | `docker compose down` then `docker compose up -d`; check nothing else binds `8000` |
| Frontend loads but API fails | Confirm backend is up: `curl localhost:8000/health`; check `VITE_BACKEND_ORIGIN` |
| Login fails | Run `seed_admin.py`; verify `SEED_ADMIN_PASSWORD` matches what you type |
| Empty dashboard | Run `seed_demo_data.py`; hard-refresh the UI |
| Elasticsearch OOM / unhealthy | Increase Docker memory (8 GB+); restart `elasticsearch` |
| `JWT` / auth errors after rebuild | Ensure `JWT_SECRET_KEY` in `backend/.env` did not change unexpectedly |
| Compose build slow first time | Normal — base images + pip/npm install; later starts are faster |

Reset everything (including DB data):

```bash
docker compose down -v
docker compose up -d --build
docker compose exec backend python scripts/seed_admin.py
docker compose exec backend python scripts/seed_demo_data.py
```

---

## License / academic use

Developed as a B.Tech final-year project demonstration platform. Change default credentials before any shared or public deployment.
