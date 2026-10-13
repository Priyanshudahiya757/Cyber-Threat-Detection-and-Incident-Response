"""
app/db/elastic.py

Purpose:
    Owns the Elasticsearch connection and exposes the log repository
    functions (bulk-index logs, search logs, run aggregations for the
    dashboard/analytics pages). Like db/mongo.py, nothing outside this
    file should import the `elasticsearch` client directly.

Index strategy:
    Logs are written to a daily index, security-logs-YYYY.MM.DD, and
    queried through the security-logs-* pattern. This keeps individual
    indices small and makes retention policies easy to bolt on later.

Time fields:
    Every log has two timestamps. `timestamp` is when the event happened
    according to the source; `ingested_at` is when this platform received
    it. Investigation views filter on `timestamp`. Operational views
    ("what arrived recently") filter on `ingested_at`, so a log file that
    is uploaded days after it was written still shows up.

Connects to:
    - ingestion/pipeline.py -> check_existing_log_ids / bulk_index_logs
    - detection/service.py -> search_logs to assemble detection windows
    - api/v1/analytics.py -> aggregations
    - api/v1/logs.py -> search_logs (live monitoring / investigation view)
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from elasticsearch import AsyncElasticsearch, helpers

from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.log_schema import NormalizedLog

logger = get_logger(__name__)

_es_client: Optional[AsyncElasticsearch] = None

INDEX_PREFIX = settings.ELASTIC_LOG_INDEX_PREFIX
INDEX_PATTERN = f"{INDEX_PREFIX}-*"

#: Elasticsearch's default index.max_result_window.
MAX_RESULT_WINDOW = 10_000

TimeField = Literal["timestamp", "ingested_at"]

#: Locations of the index mapping: repository layout, then the docker-compose mount.
_MAPPING_CANDIDATES = [
    Path(__file__).resolve().parents[3] / "elasticsearch" / "mappings" / "security_logs_mapping.json",
    Path("/elasticsearch/mappings/security_logs_mapping.json"),
]


def _today_index() -> str:
    return f"{INDEX_PREFIX}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


def get_es_client() -> AsyncElasticsearch:
    if _es_client is None:
        raise RuntimeError("Elasticsearch not initialized. Call connect_to_elastic() at startup.")
    return _es_client


async def connect_to_elastic() -> None:
    global _es_client
    auth = None
    if settings.ELASTIC_USERNAME and settings.ELASTIC_PASSWORD:
        auth = (settings.ELASTIC_USERNAME, settings.ELASTIC_PASSWORD)

    _es_client = AsyncElasticsearch(
        hosts=[settings.ELASTIC_HOST],
        basic_auth=auth,
        verify_certs=settings.ELASTIC_VERIFY_CERTS,
    )
    await _ensure_index_template()
    logger.info(f"Connected to Elasticsearch at {settings.ELASTIC_HOST}")


async def close_elastic_connection() -> None:
    global _es_client
    if _es_client:
        await _es_client.close()
        logger.info("Elasticsearch connection closed")


async def _ensure_index_template() -> None:
    """
    Registers an index template so every daily security-logs-* index
    automatically gets the correct mapping (see
    elasticsearch/mappings/security_logs_mapping.json) without needing
    to create each index by hand.
    """
    mapping_path = next((p for p in _MAPPING_CANDIDATES if p.is_file()), None)
    if mapping_path is None:
        logger.warning("ES mapping file not found, skipping index template setup")
        return

    mapping_body = json.loads(mapping_path.read_text(encoding="utf-8"))
    template = {
        "index_patterns": [INDEX_PATTERN],
        "template": {"mappings": mapping_body["mappings"], "settings": mapping_body.get("settings", {})},
    }
    await get_es_client().indices.put_index_template(name=f"{INDEX_PREFIX}-template", body=template)


def _received_within(hours: int) -> Dict[str, Any]:
    """Query clause for logs ingested in the last `hours` hours."""
    return {"range": {"ingested_at": {"gte": f"now-{hours}h"}}}


# --------------------------------------------------------------------------
# Log repository
# --------------------------------------------------------------------------

async def bulk_index_logs(logs: List[NormalizedLog]) -> Dict[str, int]:
    index_name = _today_index()
    actions = [
        {"_index": index_name, "_id": log.log_id, "_source": json.loads(log.model_dump_json())}
        for log in logs
    ]
    # refresh="wait_for": return only once the logs are searchable. Detection,
    # de-duplication and model training all read back what was just written.
    success, errors = await helpers.async_bulk(
        get_es_client(), actions, raise_on_error=False, refresh="wait_for"
    )
    return {"accepted": success, "rejected": len(errors)}


async def check_existing_log_ids(log_ids: List[str]) -> set:
    """
    Returns the subset of `log_ids` that already exist in Elasticsearch,
    searched across ALL daily indices via a terms query on the keyword
    `log_id` field.

    This is deliberately a search, not a per-index `exists()`/mget call:
    log_id is a deterministic content hash (see ingestion/normalizer.py),
    but the daily index a document lives in depends on when it was
    originally ingested. A log re-uploaded on a later date would land in
    a *different* day's index, so relying on same-index _id uniqueness
    alone would miss cross-day duplicates.
    """
    if not log_ids:
        return set()

    existing: set = set()
    client = get_es_client()
    try:
        for start in range(0, len(log_ids), MAX_RESULT_WINDOW):
            chunk = log_ids[start : start + MAX_RESULT_WINDOW]
            result = await client.search(
                index=INDEX_PATTERN,
                body={"query": {"terms": {"log_id": chunk}}, "_source": False, "size": len(chunk)},
                ignore_unavailable=True,
            )
            existing.update(hit["_id"] for hit in result["hits"]["hits"])
    except Exception as exc:
        logger.warning(f"check_existing_log_ids: search failed, assuming no duplicates: {exc}")
    return existing


async def search_logs(
    query: Optional[str] = None,
    source_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    time_field: TimeField = "timestamp",
    size: int = 50,
    from_: int = 0,
) -> Dict[str, Any]:
    filters: List[Dict[str, Any]] = []
    if query:
        # simple_query_string never raises on malformed input, unlike
        # query_string — analysts paste raw payloads full of operators.
        filters.append(
            {"simple_query_string": {"query": query, "fields": ["raw_log"], "default_operator": "and"}}
        )
    if source_type:
        filters.append({"term": {"source_type": source_type}})
    if severity:
        filters.append({"term": {"severity": severity}})
    if source_ip:
        filters.append({"term": {"source_ip": source_ip}})
    if start_time or end_time:
        time_range: Dict[str, Any] = {}
        if start_time:
            time_range["gte"] = start_time.isoformat()
        if end_time:
            time_range["lte"] = end_time.isoformat()
        filters.append({"range": {time_field: time_range}})

    body = {
        "query": {"bool": {"must": filters}} if filters else {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "track_total_hits": True,
    }

    result = await get_es_client().search(
        index=INDEX_PATTERN, body=body, size=size, from_=from_, ignore_unavailable=True
    )
    return {
        "total": result["hits"]["total"]["value"],
        "results": [hit["_source"] for hit in result["hits"]["hits"]],
    }


# --------------------------------------------------------------------------
# Dashboard aggregations
# --------------------------------------------------------------------------

async def _aggregate(hours: int, aggs: Dict[str, Any]) -> Dict[str, Any]:
    result = await get_es_client().search(
        index=INDEX_PATTERN,
        body={"query": _received_within(hours), "aggs": aggs, "size": 0},
        ignore_unavailable=True,
    )
    return result.get("aggregations", {})


async def aggregate_top_ips(top_n: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
    aggs = await _aggregate(hours, {"top_ips": {"terms": {"field": "source_ip", "size": top_n}}})
    buckets = aggs.get("top_ips", {}).get("buckets", [])
    return [{"ip": b.get("key_as_string", b["key"]), "count": b["doc_count"]} for b in buckets]


async def aggregate_severity_counts(hours: int = 24) -> Dict[str, int]:
    aggs = await _aggregate(hours, {"by_severity": {"terms": {"field": "severity"}}})
    return {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}


async def aggregate_source_counts(hours: int = 24) -> Dict[str, int]:
    aggs = await _aggregate(hours, {"by_source": {"terms": {"field": "source_type"}}})
    return {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])}


async def count_logs(hours: int = 24) -> int:
    result = await get_es_client().count(
        index=INDEX_PATTERN, body={"query": _received_within(hours)}, ignore_unavailable=True
    )
    return int(result.get("count", 0))
