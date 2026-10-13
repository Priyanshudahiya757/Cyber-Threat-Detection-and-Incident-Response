"""
app/models/log_schema.py

Purpose:
    The canonical log schema. Every parser in ingestion/parsers/ (Windows,
    Linux, firewall, web server) must produce a NormalizedLog, regardless
    of how different the raw formats are. This is the contract that makes
    rule-based detection and ML feature extraction source-agnostic — they
    only ever read NormalizedLog fields, never raw log text.

Connects to:
    - ingestion/normalizer.py builds these from parser output
    - db/elastic.py indexes these into Elasticsearch (see
      elasticsearch/mappings/security_logs_mapping.json for the index shape
      this schema must stay in sync with)
    - detection/rules/*.py and detection/ml/feature_extraction.py consume these
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    FIREWALL = "firewall"
    WEB_SERVER = "web_server"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    WEB_ATTACK = "web_attack"
    SYSTEM = "system"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NormalizedLog(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid4()))
    source_type: SourceType
    source_host: Optional[str] = None
    event_category: EventCategory
    event_type: str = Field(..., description="e.g. failed_login, port_scan, sql_injection")
    severity: Severity = Severity.LOW

    user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None

    raw_log: str = Field(..., description="Original untouched log line, kept for audit/evidence")
    parsed_fields: Dict[str, Any] = Field(default_factory=dict)

    timestamp: datetime = Field(..., description="Event time as reported by the source")
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


class LogUploadResponse(BaseModel):
    accepted: int
    rejected: int
    duplicates: int = 0
    errors: list[str] = Field(default_factory=list)
    log_ids: list[str] = Field(default_factory=list)
    batch_id: Optional[str] = None


class IngestionBatch(BaseModel):
    """
    Metadata record for a single ingestion request (file upload or JSON
    ingest), persisted in MongoDB's `ingestion_batches` collection. This
    is the audit trail answering "when was this data ingested, by whom,
    from what, and with what outcome" — useful both for the SOC dashboard
    and for a B.Tech viva demo of the ingestion pipeline's traceability.
    """
    batch_id: str
    source_type: SourceType
    source_host: Optional[str] = None
    filename: Optional[str] = None
    uploaded_by: str
    total_records: int
    accepted: int
    rejected: int
    duplicates: int
    errors: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}
