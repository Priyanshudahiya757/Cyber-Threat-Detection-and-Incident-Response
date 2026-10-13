# Cyber Threat Detection — Workspace

## Main application

The working application is here:

```text
backend/
frontend/
```

**Complete usage and technical guide:**
[`docs/PROJECT_USER_AND_TECHNICAL_GUIDE.txt`](docs/PROJECT_USER_AND_TECHNICAL_GUIDE.txt)

Additional planning and release checks:
[`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md).

### Quick start

```powershell
Copy-Item backend/.env.example backend/.env
# Edit backend/.env: set a unique 32+ character JWT_SECRET_KEY and strong
# SEED_ADMIN_PASSWORD before sharing the application.

docker compose up -d --build
docker compose ps
docker compose exec backend python scripts/seed_admin.py
docker compose exec backend python scripts/seed_demo_data.py
```

Open `http://localhost:5173` to log in. API docs are available at
`http://localhost:8000/docs`; readiness is checked at `http://localhost:8000/health/ready`.

Free temporary public demo URL:

```powershell
cloudflared tunnel --url http://localhost:5173
```

Keep Docker Desktop and the tunnel process running while sharing the generated URL.

Stop services without deleting database data:

```powershell
docker compose down
```


### Other files in this folder

| Path | Purpose |
|------|---------|
| `Cyber_Threat_Detection_Incident_Response_Dashboard.pptx` | Project presentation |
| `Seminar Ppt .pptx` | College PPT template |
| `ppt-prompt.txt` | Prompt used to generate the presentation |
| `.agents/` | Cursor agent skills (not part of the runtime app) |
| `docs/PROJECT_USER_AND_TECHNICAL_GUIDE.txt` | Full setup, login, feature, API, technology, deployment, and troubleshooting guide |
