"""
app/ingestion/normalizer.py

Purpose:
    Single point of translation from ParsedEvent (source-specific,
    produced by parsers/*.py) to NormalizedLog (canonical schema,
    consumed by everything downstream: Elasticsearch, rule engine, ML
    feature extraction). Isolating this mapping here means the canonical
    schema can evolve without touching parser internals, and severity
    defaulting logic lives in exactly one place instead of being
    duplicated across four parsers.

    Deterministic log_id: computed as a SHA-256 hash of
    (source_type, source_host, raw_log, timestamp). This is what makes
    ingestion idempotent — re-uploading the same file twice produces the
    same log_ids, so indexing into Elasticsearch (which uses log_id as
    the document _id) overwrites rather than duplicates. This is the
    core of the duplicate-detection requirement.

Connects to:
    - ingestion/pipeline.py calls normalize() for every ParsedEvent
    - Produces app.models.log_schema.NormalizedLog instances
"""
import hashlib
from datetime import timezone
from typing import Optional

from app.ingestion.parsers.base_parser import ParsedEvent
from app.models.log_schema import NormalizedLog, Severity, SourceType


def compute_log_id(source_type: SourceType, source_host: Optional[str], raw_log: str, timestamp_iso: str) -> str:
    """
    Deterministic content hash used as both NormalizedLog.log_id and the
    Elasticsearch document _id. Same inputs always produce the same ID,
    which is what makes re-ingestion of identical content a no-op update
    rather than a duplicate document.
    """
    key = f"{source_type}|{source_host or ''}|{raw_log}|{timestamp_iso}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _ensure_utc(ts):
    """Attach UTC if the parser produced a naive datetime (common for syslog)."""
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def normalize(event: ParsedEvent, source_type: SourceType, source_host: Optional[str] = None) -> NormalizedLog:
    """
    Convert a single ParsedEvent into a canonical NormalizedLog.

    Severity resolution order:
      1. event.severity_hint from the parser, if it's a valid Severity value
      2. Severity.LOW as a safe default (rules/ML may still flag it later;
         "low" here only describes the raw log record, not any detection
         verdict about it)
    """
    severity = _resolve_severity(event.severity_hint)
    ts = _ensure_utc(event.timestamp)
    timestamp_iso = ts.isoformat()

    log_id = compute_log_id(source_type, source_host, event.raw_log, timestamp_iso)

    return NormalizedLog(
        log_id=log_id,
        source_type=source_type,
        source_host=source_host,
        event_category=event.event_category,
        event_type=event.event_type,
        severity=severity,
        user=event.user,
        source_ip=event.source_ip,
        dest_ip=event.dest_ip,
        dest_port=event.dest_port,
        raw_log=event.raw_log,
        parsed_fields=event.parsed_fields,
        timestamp=ts,
    )


def _resolve_severity(severity_hint: Optional[str]) -> Severity:
    if severity_hint is None:
        return Severity.LOW
    try:
        return Severity(severity_hint)
    except ValueError:
        return Severity.LOW
