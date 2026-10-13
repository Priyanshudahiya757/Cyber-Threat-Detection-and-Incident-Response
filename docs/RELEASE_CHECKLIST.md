# Release checklist

## Before launch

- [ ] Docker Desktop running; at least 8 GB available memory.
- [ ] `backend/.env` local only; never commit or submit it.
- [ ] `JWT_SECRET_KEY` unique and at least 32 characters.
- [ ] `SEED_ADMIN_PASSWORD` changed from `ChangeMe123!`.
- [ ] `APP_ENV=production`, `DEBUG=false`, CORS only trusted UI URLs.
- [ ] `VITE_USE_MOCKS_FOR_UNIMPLEMENTED=false`.

## Verification

- [ ] `docker compose config --quiet`
- [ ] `docker compose up -d --build`
- [ ] `docker compose ps` shows healthy dependencies/running app services.
- [ ] `curl http://localhost:8000/health`
- [ ] `curl http://localhost:8000/health/ready`
- [ ] `docker compose exec backend python -m pytest tests -v`
- [ ] `docker compose exec frontend npm run typecheck`
- [ ] `docker compose exec frontend npm run lint`
- [ ] `docker compose exec frontend npm run build`

## Submission package

- [ ] Include source, `.env.example`, docs, sample logs, architecture, PPT.
- [ ] Exclude `.env`, virtual environments, `node_modules`, `dist`, logs, Python caches, runtime ML artifacts.
- [ ] State project is local academic/SOC demo, not public production service.
