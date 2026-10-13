"""
app/db/elastic.py

Purpose:
    Owns the Elasticsearch connection and exposes the log repository
    functions (index a log, search logs, run aggregations for the
    dashboard/analytics pages). Like db/mongo.py, nothing outside this
    file should import the `elasticsearch` client directly.

    IMPORTANT (per architecture decision): this module is written behind
    a narrow interface (index_log, bulk_index_logs, search_logs,
    aggregate_top_ips, ...) specifically so it can be swapped for a
    Mongo-backed implementation later without changing any caller in
    ingestion/ or api/v1/analytics.py.

Index strategy:
    Logs are written to a daily index: security-logs-YYYY.MM.DD, aliased
    under `security-logs` for querying. This keeps individual indices
    small and makes retention/ILM policies easy to bolt on later.

Connects to:
    - ingestion/pipeline.py -> index_log / bulk_index_logs
    - api/v1/analytics.py -> search_logs, aggregate_top_ips, aggregate_severity
    - api/v1/logs.py -> search_logs (live monitoring / investigation view)
"""
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from elasticsearch import AsyncElasticsearch, helpers

from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.log_schema import NormalizedLog

logger = get_logger(__name__)

_es_client: Optional[AsyncElasticsearch] = None

INDEX_ALIAS = settings.ELASTIC_LOG_INDEX_PREFIX  # "security-logs"


def _resolve_mapping_path() -> Optional[str]:
    """
    Resolve the ES mapping JSON across local, Docker, and compose mounts.
    """
    candidates = [
        os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "elasticsearch", "mappings", "security_logs_mapping.json"
        ),
        "/elasticsearch/mappings/security_logs_mapping.json",
        os.path.join(os.getcwd(), "elasticsearch", "mappings", "security_logs_mapping.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


MAPPING_PATH = _resolve_mapping_path() or os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "elasticsearch", "mappings", "security_logs_mapping.json"
)


def _today_index() -> str:
    return f"{INDEX_ALIAS}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


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
    client = get_es_client()
    try:
        with open(MAPPING_PATH, "r") as f:
            mapping_body = json.load(f)
    except FileNotFoundError:
        logger.warning(f"ES mapping file not found at {MAPPING_PATH}, skipping template setup")
        return

    template = {
        "index_patterns": [f"{INDEX_ALIAS}-*"],
        "template": {"mappings": mapping_body["mappings"], "settings": mapping_body.get("settings", {})},
    }
    await client.indices.put_index_template(name=f"{INDEX_ALIAS}-template", body=template)


# --------------------------------------------------------------------------
# Log repository
# --------------------------------------------------------------------------

async def index_log(log: NormalizedLog) -> str:
    client = get_es_client()
    doc = json.loads(log.model_dump_json())
    await client.index(index=_today_index(), id=log.log_id, document=doc)
    return log.log_id


async def bulk_index_logs(logs: List[NormalizedLog]) -> Dict[str, int]:
    client = get_es_client()
    index_name = _today_index()

    actions = [
        {"_index": index_name, "_id": log.log_id, "_source": json.loads(log.model_dump_json())}
        for log in logs
    ]
    success, errors = await helpers.async_bulk(client, actions, raise_on_error=False)
    return {"accepted": success, "rejected": len(errors)}


async def search_logs(
    query: Optional[str] = None,
    source_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    size: int = 50,
    from_: int = 0,
) -> Dict[str, Any]:
    client = get_es_client()

    must: List[Dict[str, Any]] = []
    if query:
        must.append({"query_string": {"query": query, "default_field": "raw_log"}})
    if source_type:
        must.append({"term": {"source_type": source_type}})
    if severity:
        must.append({"term": {"severity": severity}})
    if source_ip:
        must.append({"term": {"source_ip": source_ip}})
    if start_time or end_time:
        range_filter: Dict[str, Any] = {}
        if start_time:
            range_filter["gte"] = start_time.isoformat()
        if end_time:
            range_filter["lte"] = end_time.isoformat()
        must.append({"range": {"timestamp": range_filter}})

    body = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    result = await client.search(index=f"{INDEX_ALIAS}-*", body=body, size=size, from_=from_)
    hits = result["hits"]["hits"]
    return {
        "total": result["hits"]["total"]["value"],
        "results": [h["_source"] for h in hits],
    }


async def aggregate_top_ips(field: str = "source_ip", top_n: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
    client = get_es_client()
    body = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"top_ips": {"terms": {"field": field, "size": top_n}}},
        "size": 0,
    }
    result = await client.search(index=f"{INDEX_ALIAS}-*", body=body)
    buckets = result["aggregations"]["top_ips"]["buckets"]
    return [{"ip": b["key"], "count": b["doc_count"]} for b in buckets]


async def check_existing_log_ids(log_ids: List[str]) -> set:
    """
    Returns the subset of `log_ids` that already exist in Elasticsearch,
    searched across ALL daily indices (security-logs-*) via a terms query
    on the keyword `log_id` field.

    This is deliberately a search, not a per-index `exists()`/mget call:
    log_id is a deterministic content hash (see ingestion/normalizer.py),
    but the daily index a document lives in depends on when it was
    originally ingested. A log re-uploaded on a later date would land in
    a *different* day's index, so relying on same-index _id uniqueness
    alone would miss cross-day duplicates. Searching by field across the
    index pattern catches those correctly.
    """
    if not log_ids:
        return set()

    client = get_es_client()
    body = {
        "query": {"terms": {"log_id": log_ids}},
        "_source": False,
        "size": len(log_ids),
    }
    try:
        result = await client.search(index=f"{INDEX_ALIAS}-*", body=body)
    except Exception as exc:
        # If no indices exist yet (fresh deployment), ES returns a 404 for
        # the index pattern rather than an empty result set. Treat that as
        # "nothing exists yet" rather than propagating the error.
        logger.warning(f"check_existing_log_ids: search failed, assuming no duplicates: {exc}")
        return set()

    return {hit["_id"] for hit in result["hits"]["hits"]}


async def aggregate_severity_counts(hours: int = 24) -> Dict[str, int]:
    client = get_es_client()
    body = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"by_severity": {"terms": {"field": "severity"}}},
        "size": 0,
    }
    result = await client.search(index=f"{INDEX_ALIAS}-*", body=body)
    buckets = result["aggregations"]["by_severity"]["buckets"]
    return {b["key"]: b["doc_count"] for b in buckets}


async def count_logs(hours: Optional[int] = None) -> int:
    """Total log documents, optionally scoped to a recent time window."""
    client = get_es_client()
    # Prefer ingested_at for "recent" windows so demo fixtures with older
    # event timestamps still appear on the dashboard after upload.
    if hours is not None:
        body: Dict[str, Any] = {
            "query": {
                "bool": {
                    "should": [
                        {"range": {"ingested_at": {"gte": f"now-{hours}h"}}},
                        {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        }
    else:
        body = {"query": {"match_all": {}}}
    try:
        result = await client.count(index=f"{INDEX_ALIAS}-*", body=body)
        return int(result.get("count", 0))
    except Exception as exc:
        logger.warning(f"count_logs failed: {exc}")
        return 0


async def count_distinct_sources(hours: int = 24) -> int:
    client = get_es_client()
    body = {
        "query": {
            "bool": {
                "should": [
                    {"range": {"ingested_at": {"gte": f"now-{hours}h"}}},
                    {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {"sources": {"cardinality": {"field": "source_type"}}},
        "size": 0,
    }
    try:
        result = await client.search(index=f"{INDEX_ALIAS}-*", body=body)
        return int(result["aggregations"]["sources"]["value"])
    except Exception as exc:
        logger.warning(f"count_distinct_sources failed: {exc}")
        return 0
