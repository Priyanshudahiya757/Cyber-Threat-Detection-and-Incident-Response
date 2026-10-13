"""
app/detection/service.py

Purpose:
    The one place that turns logs into stored findings. Both detection
    engines (rules and ML) and every trigger (automatic after ingestion,
    manual re-scan from the UI) go through the same three steps here:

        1. assemble the window of logs to evaluate
        2. run an engine over it
        3. record_detections(): store new findings, raise alerts,
           correlate into incidents

    Cross-batch detection: a freshly ingested batch is evaluated together
    with already-stored logs from the minutes just before it, so an attack
    whose events arrive in separate uploads is still recognised. Only
    findings that involve at least one new log are kept, and stored
    findings are de-duplicated by fingerprint, so nothing is reported twice.

Connects to:
    - main.py registers handle_ingested_logs as the ingestion pipeline's callback
    - api/v1/detections.py and api/v1/ml.py call the scan_* functions
    - db/elastic.py supplies log windows; db/mongo.py stores detections
    - detection/alerting.py and incidents/correlator.py act on new findings
"""
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Literal

from app.core.config import settings
from app.core.logging_config import get_logger
from app.db import elastic, mongo
from app.detection.alerting import generate_alerts
from app.detection.engine import default_rule_engine
from app.detection.ml.prediction_service import default_prediction_service
from app.incidents.correlator import correlate_detections
from app.models.detection_schema import DetectionEngine, DetectionEvent
from app.models.log_schema import NormalizedLog

logger = get_logger(__name__)

#: Upper bound on stored logs pulled in as context for one ingested batch.
CONTEXT_LOG_LIMIT = 5_000


@dataclass
class DetectionOutcome:
    """What a detection run produced, for API responses and logging."""
    logs_scanned: int = 0
    detections: List[DetectionEvent] = field(default_factory=list)
    alerts_generated: int = 0


async def record_detections(detections: List[DetectionEvent]) -> DetectionOutcome:
    """
    Store the detections that are new, then alert on and correlate exactly
    those. Alerting and correlation failures are logged, not raised: the
    findings are already safely stored.
    """
    new = await mongo.save_detections(detections)
    outcome = DetectionOutcome(detections=new)
    if not new:
        return outcome

    try:
        outcome.alerts_generated = len(await generate_alerts(new))
    except Exception as exc:
        logger.error(f"record_detections: alert generation failed: {exc}")

    try:
        await correlate_detections(new)
    except Exception as exc:
        logger.error(f"record_detections: incident correlation failed: {exc}")

    return outcome


def _to_logs(documents: List[dict]) -> List[NormalizedLog]:
    logs: List[NormalizedLog] = []
    for doc in documents:
        try:
            logs.append(NormalizedLog(**doc))
        except Exception as exc:
            logger.warning(f"Skipping stored log that no longer matches the schema: {exc}")
    return logs


async def _context_logs(new_logs: List[NormalizedLog]) -> List[NormalizedLog]:
    """Stored logs from the lookback period before (and during) the new batch's event-time span."""
    if settings.DETECTION_LOOKBACK_MINUTES <= 0:
        return []

    timestamps = [log.timestamp for log in new_logs]
    try:
        result = await elastic.search_logs(
            start_time=min(timestamps) - timedelta(minutes=settings.DETECTION_LOOKBACK_MINUTES),
            end_time=max(timestamps),
            size=CONTEXT_LOG_LIMIT,
        )
    except Exception as exc:
        logger.warning(f"Context lookup failed; evaluating the new batch on its own: {exc}")
        return []

    new_ids = {log.log_id for log in new_logs}
    return [log for log in _to_logs(result["results"]) if log.log_id not in new_ids]


async def handle_ingested_logs(new_logs: List[NormalizedLog]) -> None:
    """
    Post-ingestion hook: run both detection engines over the new batch
    plus its stored context, and record findings that involve new logs.
    The engines are independent — an ML failure never blocks rule
    detections.
    """
    if not new_logs:
        return

    window = await _context_logs(new_logs) + new_logs
    new_ids = {log.log_id for log in new_logs}
    new_source_ips = {log.source_ip for log in new_logs if log.source_ip}

    detections = [d for d in default_rule_engine.run(window) if new_ids.intersection(d.evidence_log_ids)]

    try:
        ml_detections = default_prediction_service.predict(window)
    except Exception as exc:
        logger.error(f"handle_ingested_logs: ML prediction failed, continuing with rule detections only: {exc}")
        ml_detections = []
    detections.extend(d for d in ml_detections if d.entity.value in new_source_ips)

    await record_detections(detections)


async def _recently_ingested(minutes: int, limit: int) -> List[NormalizedLog]:
    """Logs received by the platform in the last `minutes`, whatever their event timestamps."""
    now = mongo.utcnow()
    result = await elastic.search_logs(
        start_time=now - timedelta(minutes=minutes),
        end_time=now,
        time_field="ingested_at",
        size=limit,
    )
    return _to_logs(result["results"])


async def scan_recent_logs(
    engine: Literal[DetectionEngine.RULE, DetectionEngine.ML], minutes: int
) -> DetectionOutcome:
    """Manually re-run one engine over everything ingested in the last `minutes`."""
    logs = await _recently_ingested(minutes, limit=elastic.MAX_RESULT_WINDOW)

    if engine == DetectionEngine.RULE:
        detections = default_rule_engine.run(logs)
    else:
        detections = default_prediction_service.predict(logs)

    outcome = await record_detections(detections)
    outcome.logs_scanned = len(logs)
    return outcome


async def training_logs(days: int) -> List[NormalizedLog]:
    """Logs ingested in the last `days`, used as the ML training set."""
    return await _recently_ingested(days * 24 * 60, limit=elastic.MAX_RESULT_WINDOW)


def summarize(outcome: DetectionOutcome) -> Dict[str, object]:
    """JSON-ready form of a DetectionOutcome shared by the manual scan endpoints."""
    return {
        "logs_scanned": outcome.logs_scanned,
        "detections_found": len(outcome.detections),
        "alerts_generated": outcome.alerts_generated,
        "detections": [d.model_dump() for d in outcome.detections],
    }
