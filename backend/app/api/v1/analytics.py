"""
app/api/v1/analytics.py

Purpose:
    Aggregation endpoints that power the Dashboard and Threat Analytics
    pages. Combines Elasticsearch log aggregations with MongoDB
    detection/incident/alert counts.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.core.dependencies import get_current_user
from app.core.logging_config import get_logger
from app.db import elastic, mongo
from app.models.incident_schema import IncidentStatus
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/analytics", tags=["Dashboard Analytics"])
logger = get_logger(__name__)


async def _safe_es(coro, default):
    try:
        return await coro
    except Exception as exc:
        logger.warning(f"analytics: Elasticsearch query failed: {exc}")
        return default


@router.get("/summary")
async def dashboard_summary(
    hours: int = Query(default=24, ge=1, le=168),
    current_user: UserInDB = Depends(get_current_user),
):
    log_total = await _safe_es(elastic.count_logs(hours=hours), 0)
    sources = await _safe_es(elastic.count_distinct_sources(hours=hours), 0)

    threats = await mongo.count_detections()
    ai_anomalies = await mongo.count_detections(engine="ml")
    active = await mongo.count_incidents(
        statuses=[IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]
    )
    critical_alerts = await mongo.count_alerts(severity="critical")

    return {
        "total_logs": log_total,
        "threats_detected": threats,
        "active_incidents": active,
        "critical_alerts": critical_alerts,
        "ai_anomalies": ai_anomalies,
        "log_sources": sources,
    }


@router.get("/top-ips")
async def top_attacking_ips(
    top_n: int = Query(default=10, ge=1, le=50),
    hours: int = Query(default=24, ge=1, le=168),
    current_user: UserInDB = Depends(get_current_user),
):
    ips = await _safe_es(elastic.aggregate_top_ips(top_n=top_n, hours=hours), [])
    return {"items": ips, "count": len(ips)}


@router.get("/severity-distribution")
async def severity_distribution(
    hours: int = Query(default=24, ge=1, le=168),
    current_user: UserInDB = Depends(get_current_user),
):
    raw = await _safe_es(elastic.aggregate_severity_counts(hours=hours), {})
    return {
        "low": raw.get("low", 0),
        "medium": raw.get("medium", 0),
        "high": raw.get("high", 0),
        "critical": raw.get("critical", 0),
    }


@router.get("/threat-timeline")
async def threat_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    current_user: UserInDB = Depends(get_current_user),
):
    points = await mongo.aggregate_detection_timeline(hours=hours)
    return {"items": points, "count": len(points)}


@router.get("/attack-types")
async def attack_types(
    limit: int = Query(default=10, ge=1, le=50),
    current_user: UserInDB = Depends(get_current_user),
):
    items = await mongo.aggregate_threat_types(limit=limit)
    return {"items": items, "count": len(items)}


@router.get("/recent-events")
async def recent_events(
    limit: int = Query(default=15, ge=1, le=100),
    current_user: UserInDB = Depends(get_current_user),
):
    detections = await mongo.list_detections(limit=limit)
    for d in detections:
        d["_id"] = str(d["_id"])
    return {"events": detections, "count": len(detections)}
