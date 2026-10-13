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

from app.api.v1 import analytics, auth, detections, incidents, logs, ml, rules
from app.core.config import settings
from app.core.logging_config import get_logger, setup_logging
from app.db.elastic import close_elastic_connection, connect_to_elastic, get_es_client
from app.db.mongo import close_mongo_connection, connect_to_mongo, ensure_indexes, get_db, get_rule_configs
from app.detection.engine import default_rule_engine, handle_ingested_logs
from app.ingestion.pipeline import default_pipeline

setup_logging()
logger = get_logger(__name__)


async def _load_persisted_rule_config() -> None:
    """Apply enabled/disabled state from MongoDB onto the live RuleEngine."""
    try:
        configs = await get_rule_configs()
        for cfg in configs:
            default_rule_engine.set_rule_enabled(cfg["rule_name"], bool(cfg.get("enabled", True)))
        if configs:
            logger.info(f"Loaded {len(configs)} persisted rule config(s)")
    except Exception as exc:
        logger.warning(f"Could not load rule configs: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} [{settings.APP_ENV}]")
    connect_to_mongo()
    await ensure_indexes()
    try:
        await connect_to_elastic()
    except Exception as exc:
        # Don't crash the whole API if ES is briefly unavailable at boot
        # (e.g. docker-compose race condition) — log loudly instead.
        logger.error(f"Elasticsearch connection failed at startup: {exc}")

    # Wire Phase 3 detection into Phase 2 ingestion without ingestion
    # importing detection directly (Dependency Inversion — see
    # ingestion/pipeline.py's OnIngestedCallback docstring).
    default_pipeline.register_on_ingested_callback(handle_ingested_logs)
    logger.info("Rule-based detection engine wired to ingestion pipeline")

    await _load_persisted_rule_config()

    yield

    logger.info("Shutting down...")
    close_mongo_connection()
    await close_elastic_connection()


app = FastAPI(
    title=settings.APP_NAME,
    description="Lightweight SIEM platform: log ingestion, rule-based + ML threat "
    "detection, and SOC incident response.",
    version="0.1.0",
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


app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(logs.router, prefix=settings.API_V1_PREFIX)
app.include_router(incidents.router, prefix=settings.API_V1_PREFIX)
app.include_router(analytics.router, prefix=settings.API_V1_PREFIX)
app.include_router(rules.router, prefix=settings.API_V1_PREFIX)
app.include_router(detections.router, prefix=settings.API_V1_PREFIX)
app.include_router(ml.router, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["Health"])
async def health_check():
    """Basic liveness probe. Does not check downstream DB health (see /health/ready)."""
    return {"status": "ok", "app": settings.APP_NAME, "env": settings.APP_ENV}


@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """Readiness probe — verifies MongoDB and Elasticsearch are reachable."""
    checks = {"mongodb": "unknown", "elasticsearch": "unknown"}

    try:
        await get_db().command("ping")
        checks["mongodb"] = "ok"
    except Exception as exc:
        checks["mongodb"] = f"error: {exc}"

    try:
        es = get_es_client()
        if await es.ping():
            checks["elasticsearch"] = "ok"
        else:
            checks["elasticsearch"] = "unreachable"
    except Exception as exc:
        checks["elasticsearch"] = f"error: {exc}"

    ready = checks["mongodb"] == "ok" and checks["elasticsearch"] == "ok"
    return JSONResponse(
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "ready" if ready else "degraded", "checks": checks},
    )
