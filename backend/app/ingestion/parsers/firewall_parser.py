"""
app/ingestion/parsers/firewall_parser.py

Purpose:
    Parses firewall logs in the ALLOW/DENY line format used in
    sample_logs/firewall_sample.log:

        2026-07-18 11:03:10 DENY TCP 198.51.100.23:40011 -> 10.0.0.100:21 SYN

    This format is a reasonable stand-in for pfSense/iptables-style
    connection logs. Real deployments would add an adapter for whichever
    concrete firewall vendor is in use (pfSense CSV, Cisco ASA syslog,
    etc.) as an additional parser — the pipeline doesn't care which one
    is active, only that it's registered under SourceType.FIREWALL.

Connects to:
    - Registered in ingestion/pipeline.py under SourceType.FIREWALL
"""
import re
from datetime import datetime
from typing import List, Optional

from app.core.logging_config import get_logger
from app.ingestion.parsers.base_parser import BaseLogParser, ParsedEvent
from app.models.log_schema import EventCategory, SourceType

logger = get_logger(__name__)

_FIREWALL_LINE_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>ALLOW|DENY)\s+(?P<protocol>\w+)\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s*->\s*"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)\s+(?P<flags>\S+)"
)


class FirewallLogParser(BaseLogParser):
    """Parser for ALLOW/DENY firewall connection logs."""

    source_type = SourceType.FIREWALL

    def parse(self, raw_content: str, source_host: Optional[str] = None) -> List[ParsedEvent]:
        events: List[ParsedEvent] = []

        for line_no, line in enumerate(raw_content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            match = _FIREWALL_LINE_RE.search(line)
            if not match:
                logger.debug(f"FirewallLogParser: line {line_no} did not match expected format, skipping")
                continue

            try:
                timestamp = datetime.strptime(match.group("ts"), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                logger.warning(f"FirewallLogParser: could not parse timestamp on line {line_no}")
                continue

            action = match.group("action")
            event_type = "connection_denied" if action == "DENY" else "connection_allowed"

            events.append(
                ParsedEvent(
                    event_category=EventCategory.NETWORK,
                    event_type=event_type,
                    source_ip=match.group("src_ip"),
                    dest_ip=match.group("dst_ip"),
                    dest_port=int(match.group("dst_port")),
                    raw_log=line,
                    parsed_fields={
                        "protocol": match.group("protocol"),
                        "src_port": match.group("src_port"),
                        "action": action,
                        "flags": match.group("flags"),
                    },
                    timestamp=timestamp,
                    severity_hint="low" if action == "DENY" else "low",
                )
            )

        logger.debug(f"FirewallLogParser: parsed {len(events)} events")
        return events
