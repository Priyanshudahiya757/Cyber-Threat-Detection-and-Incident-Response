"""
app/main.py

Purpose:
    FastAPI application entrypoint. Wires together:
      - Startup/shutdown lifecycle (Mongo + Elasticsearch connections)
      - CORS for the React frontend
      - All v1 API routers
      - Global exception handling for a consistent error response shape

Run locally:
    uvicorn app.main:app --reload --port 8000

Connects to:
    - Every api/v1/*.py router
    - db/mongo.py + db/elastic.py for connection lifecycle
    - core/config.py + core/logging_config.py for settings/logging setup
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import alerts, analytics, auth, detections, incidents, logs, ml, rules, users
from app.core.config import settings
from app.core.logging_config import get_logger, setup_logging
from app.db.elastic import close_elastic_connection, connect_to_elastic, get_es_client
from app.db.mongo import close_mongo_connection, connect_to_mongo, ensure_indexes, get_db, get_rule_configs
from app.detection.engine import default_rule_engine
from app.detection.service import handle_ingested_logs
from app.ingestion.pipeline import default_pipeline

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.APP_ENV}]")
    connect_to_mongo()
    await ensure_indexes()
    try:
        await connect_to_elastic()
    except Exception as exc:
        # Don't crash the whole API if ES is briefly unavailable at boot
        # (e.g. docker-compose race condition) — log loudly instead.
        logger.error(f"Elasticsearch connection failed at startup: {exc}")

    # Detection is attached to ingestion as a callback, so the ingestion
    # package never has to import the detection package.
    default_pipeline.register_on_ingested_callback(handle_ingested_logs)

    try:
        default_rule_engine.apply_persisted_state(await get_rule_configs())
    except Exception as exc:
        logger.warning(f"Could not restore saved rule configuration: {exc}")

    yield

    logger.info("Shutting down...")
    close_mongo_connection()
    await close_elastic_connection()


app = FastAPI(
    title=settings.APP_NAME,
    description="Lightweight SIEM platform: log ingestion, rule-based + ML threat "
    "detection, alerting, and SOC incident response.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    debug=settings.DEBUG,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


for module in (auth, users, logs, detections, ml, rules, alerts, incidents, analytics):
    app.include_router(module.router, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["Health"])
async def health_check():
    """Basic liveness probe. Does not check downstream DB health (see /health/ready)."""
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION, "env": settings.APP_ENV}


@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """Readiness probe — verifies MongoDB and Elasticsearch are reachable."""
    checks = {"mongodb": "unreachable", "elasticsearch": "unreachable"}

    try:
        await get_db().command("ping")
        checks["mongodb"] = "ok"
    except Exception as exc:
        logger.warning(f"Readiness: MongoDB check failed: {exc}")

    try:
        if await get_es_client().ping():
            checks["elasticsearch"] = "ok"
    except Exception as exc:
        logger.warning(f"Readiness: Elasticsearch check failed: {exc}")

    ready = all(value == "ok" for value in checks.values())
    return JSONResponse(
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "ready" if ready else "degraded", "version": settings.APP_VERSION, "checks": checks},
    )
