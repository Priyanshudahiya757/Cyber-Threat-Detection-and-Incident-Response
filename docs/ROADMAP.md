# Project completion roadmap

## Scope

Deliver demonstrable SOC dashboard: ingest logs, detect threats, create incidents, record analyst actions. Suitable academic demo or controlled internal environment; not hardened internet-facing SIEM.

## Completion phases

1. **Environment** — install Docker Desktop, start Linux engine, create `backend/.env` from `.env.example`, set unique 32+ character JWT secret. Do not use sample admin password outside local demo.
2. **Verification** — run backend tests, frontend typecheck/lint/build, validate `docker compose config --quiet`.
3. **Deployment** — run `docker compose up -d --build`; wait for MongoDB and Elasticsearch health checks; validate `/health` and `/health/ready`.
4. **Demo data** — seed admin and sample logs. Confirm dashboard, detections, incidents, analytics, ML score flow.
5. **Security review** — production values, mock data disabled, restricted CORS, protected `.env`, changed bootstrap credentials.
6. **Presentation** — demonstrate ingest-to-incident flow; prepare architecture, limitations, test evidence, future work.

## Acceptance criteria

- API liveness and readiness pass.
- Admin signs in with non-default password.
- Sample logs produce normalized logs and detections.
- At least one detection produces alert and correlated incident.
- Analyst can assign, note, resolve, close incident.
- Backend tests and frontend typecheck, lint, production build pass.
- Submission excludes secrets, caches, logs, installed dependencies.

## Launch commands

Run from project root after Docker Desktop starts:

```powershell
Copy-Item backend/.env.example backend/.env
# Edit backend/.env: unique JWT_SECRET_KEY and strong admin password.
docker compose up -d --build
docker compose ps
docker compose exec backend python scripts/seed_admin.py
docker compose exec backend python scripts/seed_demo_data.py
```

Open `http://localhost:5173`; use `http://localhost:8000/docs` for API evidence. `docker compose down` stops app but keeps named-volume data.
