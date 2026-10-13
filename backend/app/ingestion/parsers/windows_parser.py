"""
app/ingestion/parsers/windows_parser.py

Purpose:
    Parses Windows Security Event Logs exported as JSON (the realistic
    ingestion path for a student project — real .evtx binaries require
    pywin32/python-evtx and a Windows host or a native library; JSON
    export via `Get-WinEvent | ConvertTo-Json` or Winlogbeat's JSON output
    is what a real deployment would forward anyway). Accepts either a
    JSON array of event objects or newline-delimited JSON (one object
    per line, matching Winlogbeat's default output shape).

    Recognized Event IDs (mapped to canonical event_type):
      4624 - successful_login
      4625 - failed_login
      4672 - privileged_logon   (special privileges assigned to new logon)
      4720 - account_created
      4728 - group_membership_added

Connects to:
    - Registered in ingestion/pipeline.py under SourceType.WINDOWS
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.logging_config import get_logger
from app.ingestion.parsers.base_parser import BaseLogParser, LogParsingError, ParsedEvent
from app.models.log_schema import EventCategory, SourceType

logger = get_logger(__name__)

_EVENT_ID_MAP: Dict[int, Dict[str, str]] = {
    4624: {"event_type": "successful_login", "category": EventCategory.AUTHENTICATION, "severity": "low"},
    4625: {"event_type": "failed_login", "category": EventCategory.AUTHENTICATION, "severity": "medium"},
    4672: {"event_type": "privileged_logon", "category": EventCategory.SYSTEM, "severity": "medium"},
    4720: {"event_type": "account_created", "category": EventCategory.SYSTEM, "severity": "medium"},
    4728: {"event_type": "group_membership_added", "category": EventCategory.SYSTEM, "severity": "high"},
}

_DEFAULT_MAPPING = {"event_type": "windows_event", "category": EventCategory.SYSTEM, "severity": "low"}


class WindowsEventLogParser(BaseLogParser):
    """Parser for Windows Security Event Logs exported as JSON."""

    source_type = SourceType.WINDOWS

    def parse(self, raw_content: str, source_host: Optional[str] = None) -> List[ParsedEvent]:
        records = self._load_records(raw_content)
        events: List[ParsedEvent] = []

        for idx, record in enumerate(records):
            if not isinstance(record, dict):
                logger.debug(f"WindowsEventLogParser: record {idx} is not a JSON object, skipping")
                continue
            event = self._parse_record(record, idx)
            if event is not None:
                events.append(event)

        logger.debug(f"WindowsEventLogParser: parsed {len(events)} events from {len(records)} records")
        return events

    def _load_records(self, raw_content: str) -> List[Dict[str, Any]]:
        stripped = raw_content.strip()
        if not stripped:
            return []

        # Try a single JSON array first (our sample_logs/windows_sample.json shape).
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Fall back to newline-delimited JSON (Winlogbeat-style).
        records: List[Dict[str, Any]] = []
        for line_no, line in enumerate(stripped.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning(f"WindowsEventLogParser: skipping unparseable JSON on line {line_no}")

        if not records:
            raise LogParsingError("Windows log content is neither a valid JSON array nor NDJSON")

        return records

    def _parse_record(self, record: Dict[str, Any], idx: int) -> Optional[ParsedEvent]:
        try:
            event_id = int(record["EventID"])
        except (KeyError, TypeError, ValueError):
            logger.debug(f"WindowsEventLogParser: record {idx} has a missing or non-numeric EventID, skipping")
            return None

        mapping = _EVENT_ID_MAP.get(event_id, _DEFAULT_MAPPING)

        timestamp = self._parse_timestamp(record.get("TimeCreated"))
        if timestamp is None:
            logger.warning(f"WindowsEventLogParser: record {idx} has missing/invalid TimeCreated, skipping")
            return None

        parsed_fields = {
            k: v
            for k, v in record.items()
            if k not in {"EventID", "TimeCreated", "TargetUserName", "IpAddress", "Computer"}
        }
        parsed_fields["event_id"] = event_id

        return ParsedEvent(
            event_category=mapping["category"],
            event_type=mapping["event_type"],
            user=record.get("TargetUserName"),
            source_ip=record.get("IpAddress"),
            raw_log=json.dumps(record, default=str),
            parsed_fields=parsed_fields,
            timestamp=timestamp,
            severity_hint=mapping["severity"],
        )

    @staticmethod
    def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            # Handles both "...Z" and explicit offsets.
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
