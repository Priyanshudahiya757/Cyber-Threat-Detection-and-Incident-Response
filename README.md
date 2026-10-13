# Cyber Threat Detection — Workspace

## Main application

The working application is here:

```text
backend/
frontend/
```

**Installation, Docker, seeding, demo, and troubleshooting instructions** are documented in
[`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md).

### Quick start

```bash
Copy-Item backend/.env.example backend/.env
# Set JWT_SECRET_KEY in backend/.env

docker compose up -d --build
docker compose exec backend python scripts/seed_admin.py
docker compose exec backend python scripts/seed_demo_data.py
```


### Other files in this folder

| Path | Purpose |
|------|---------|
| `Cyber_Threat_Detection_Incident_Response_Dashboard.pptx` | Project presentation |
| `Seminar Ppt .pptx` | College PPT template |
| `ppt-prompt.txt` | Prompt used to generate the presentation |
| `.agents/` | Cursor agent skills (not part of the runtime app) |
