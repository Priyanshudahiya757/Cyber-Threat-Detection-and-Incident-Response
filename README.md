# Cyber Threat Detection — Workspace

## Main application

The working application is here:

```text
cyber-threat-dashboard-full/cyber-threat-dashboard/
```

**Full installation, Docker, seeding, demo, and troubleshooting instructions:**

→ **[cyber-threat-dashboard-full/cyber-threat-dashboard/README.md](cyber-threat-dashboard-full/cyber-threat-dashboard/README.md)**

### Quick start

```bash
cd cyber-threat-dashboard-full/cyber-threat-dashboard
cp backend/.env.example backend/.env
# Set JWT_SECRET_KEY in backend/.env

docker compose up -d --build
docker compose exec backend python scripts/seed_admin.py
docker compose exec backend python scripts/seed_demo_data.py
```

- UI: http://localhost:5173  
- API docs: http://localhost:8000/docs  
- Login: `admin` / `ChangeMe123!` (after seed)

### Other files in this folder

| Path | Purpose |
|------|---------|
| `Cyber_Threat_Detection_Incident_Response_Dashboard.pptx` | Project presentation |
| `Seminar Ppt .pptx` | College PPT template |
| `ppt-prompt.txt` | Prompt used to generate the presentation |
| `.agents/` | Cursor agent skills (not part of the runtime app) |
