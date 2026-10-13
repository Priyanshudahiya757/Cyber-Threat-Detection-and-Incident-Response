"""
app/api/v1/analytics.py

Purpose:
    Aggregation endpoints that power the Dashboard and Analytics pages.
    Combines Elasticsearch log aggregations with MongoDB
    detection/incident/alert counts. If Elasticsearch is unreachable the
    log-based figures fall back to empty values so the rest of the
    dashboard still loads.
"""
from typing import Any, Awaitable, TypeVar

from fastapi import APIRouter, Depends, Query

from app.core.dependencies import get_current_user
from app.core.logging_config import get_logger
from app.db import elastic, mongo
from app.models.incident_schema import IncidentStatus
from app.models.log_schema import Severity
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/analytics", tags=["Dashboard Analytics"], dependencies=[Depends(get_current_user)])
logger = get_logger(__name__)

T = TypeVar("T")

_HOURS = Query(default=24, ge=1, le=168, description="Look at logs ingested in the last N hours")


async def _safe_es(query: Awaitable[T], default: Any) -> T:
    try:
        return await query
    except Exception as exc:
        logger.warning(f"analytics: Elasticsearch query failed: {exc}")
        return default


@router.get("/summary")
async def dashboard_summary(hours: int = _HOURS):
    sources = await _safe_es(elastic.aggregate_source_counts(hours=hours), {})
    return {
        "total_logs": await _safe_es(elastic.count_logs(hours=hours), 0),
        "log_sources": len(sources),
        "logs_by_source": sources,
        "threats_detected": await mongo.count_detections(),
        "ai_anomalies": await mongo.count_detections(engine="ml"),
        "active_incidents": await mongo.count_incidents(
            statuses=[IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]
        ),
        "critical_alerts": await mongo.count_alerts(severity=Severity.CRITICAL.value),
        "unacknowledged_alerts": await mongo.count_alerts(acknowledged=False),
    }


@router.get("/top-ips")
async def top_source_ips(top_n: int = Query(default=10, ge=1, le=50), hours: int = _HOURS):
    ips = await _safe_es(elastic.aggregate_top_ips(top_n=top_n, hours=hours), [])
    return {"items": ips, "count": len(ips)}


@router.get("/severity-distribution")
async def severity_distribution(hours: int = _HOURS):
    counts = await _safe_es(elastic.aggregate_severity_counts(hours=hours), {})
    return {severity.value: counts.get(severity.value, 0) for severity in Severity}


@router.get("/threat-timeline")
async def threat_timeline(hours: int = _HOURS):
    points = await mongo.aggregate_detection_timeline(hours=hours)
    return {"items": points, "count": len(points)}


@router.get("/attack-types")
async def attack_types(limit: int = Query(default=10, ge=1, le=50)):
    items = await mongo.aggregate_threat_types(limit=limit)
    return {"items": items, "count": len(items)}


@router.get("/recent-events")
async def recent_events(limit: int = Query(default=15, ge=1, le=100)):
    detections = await mongo.list_detections(limit=limit)
    return {"events": detections, "count": len(detections)}
