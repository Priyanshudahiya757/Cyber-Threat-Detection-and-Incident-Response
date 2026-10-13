"""
app/ingestion/parsers/web_parser.py

Purpose:
    Parses Apache/Nginx access logs in the standard Combined Log Format:

        203.0.113.77 - - [18/Jul/2026:10:05:02 +0000] "GET /product?id=1 HTTP/1.1" 500 512 "-" "python-requests/2.31"

    Deliberately does NOT attempt to classify SQL injection / XSS /
    directory traversal here — that's threat *detection*, not log
    *parsing*, and belongs in detection/rules/ where it can be
    tuned, tested, and MITRE-mapped independently of ingestion. This
    parser's only job is to extract structured fields (IP, path, status,
    method, user agent) accurately so those rules have something to scan.

Connects to:
    - Registered in ingestion/pipeline.py under SourceType.WEB_SERVER
    - detection/rules/sql_injection.py, xss.py, directory_traversal.py scan
      the `raw_log` / `parsed_fields.path` this parser produces
"""
import re
from datetime import datetime
from typing import List, Optional

from app.core.logging_config import get_logger
from app.ingestion.parsers.base_parser import BaseLogParser, ParsedEvent
from app.models.log_schema import EventCategory, SourceType

logger = get_logger(__name__)

_COMBINED_LOG_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<http_version>[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class WebServerLogParser(BaseLogParser):
    """Parser for Apache/Nginx access logs (Combined Log Format)."""

    source_type = SourceType.WEB_SERVER

    def parse(self, raw_content: str, source_host: Optional[str] = None) -> List[ParsedEvent]:
        events: List[ParsedEvent] = []

        for line_no, line in enumerate(raw_content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            match = _COMBINED_LOG_RE.search(line)
            if not match:
                logger.debug(f"WebServerLogParser: line {line_no} did not match Combined Log Format, skipping")
                continue

            try:
                timestamp = datetime.strptime(match.group("ts"), _TS_FORMAT)
            except ValueError:
                logger.warning(f"WebServerLogParser: could not parse timestamp on line {line_no}")
                continue

            status = int(match.group("status"))
            size_raw = match.group("size")
            size = int(size_raw) if size_raw != "-" else 0

            events.append(
                ParsedEvent(
                    event_category=EventCategory.NETWORK,
                    event_type="http_request",
                    source_ip=match.group("ip"),
                    raw_log=line,
                    parsed_fields={
                        "method": match.group("method"),
                        "path": match.group("path"),
                        "http_version": match.group("http_version"),
                        "status_code": status,
                        "response_size_bytes": size,
                        "referrer": match.group("referrer"),
                        "user_agent": match.group("user_agent"),
                    },
                    timestamp=timestamp,
                    severity_hint="medium" if status >= 500 else ("low" if status < 400 else "low"),
                )
            )

        logger.debug(f"WebServerLogParser: parsed {len(events)} events")
        return events
