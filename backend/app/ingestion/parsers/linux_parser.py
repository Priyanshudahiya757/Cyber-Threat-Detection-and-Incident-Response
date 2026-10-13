"""
app/ingestion/parsers/linux_parser.py

Purpose:
    Parses Linux syslog-style auth logs (e.g. /var/log/auth.log). Handles
    the common sshd and sudo message formats seen in sample_logs/linux_auth.log.

    Recognized patterns:
      - "Failed password for [invalid user] <user> from <ip> port <port> ssh2"
      - "Accepted password for <user> from <ip> port <port> ssh2"
      - "sudo: <user> : ... USER=<target_user> ; COMMAND=<command>"

    Unrecognized lines are skipped (logged at DEBUG), not rejected outright —
    a syslog file mixes many subsystems and this parser only cares about
    auth-relevant ones; everything else is out of scope by design, not a
    parsing failure.

Connects to:
    - Registered in ingestion/pipeline.py under SourceType.LINUX
"""
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from app.core.logging_config import get_logger
from app.ingestion.parsers.base_parser import BaseLogParser, ParsedEvent
from app.models.log_schema import EventCategory, SourceType

logger = get_logger(__name__)

# Standard syslog timestamps carry no year (e.g. "Jul 18 09:12:03"), so the
# year is inferred at parse time — see _parse_syslog_timestamp.
_SYSLOG_TS_RE = r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

_FAILED_PASSWORD_RE = re.compile(
    _SYSLOG_TS_RE
    + r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for"
    + r"(?:\s+invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

_ACCEPTED_PASSWORD_RE = re.compile(
    _SYSLOG_TS_RE
    + r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted password for\s+(?P<user>\S+)"
    + r"\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

_SUDO_RE = re.compile(
    _SYSLOG_TS_RE
    + r"\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:.*USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)"
)


def _parse_syslog_timestamp(ts_str: str) -> datetime:
    """
    Syslog format has no year; assume current year. Whitespace between
    month/day can be single or double space depending on day-of-month
    padding, so we normalize before strptime.
    """
    normalized = re.sub(r"\s+", " ", ts_str.strip())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    parsed = datetime.strptime(f"{now.year} {normalized}", "%Y %b %d %H:%M:%S")
    if parsed > now + timedelta(days=1):
        # A date that would lie in the future was logged last year
        # (e.g. a "Dec 30" line read in January).
        parsed = parsed.replace(year=now.year - 1)
    return parsed


class LinuxAuthLogParser(BaseLogParser):
    """Parser for Linux syslog/auth.log (sshd + sudo events)."""

    source_type = SourceType.LINUX

    def parse(self, raw_content: str, source_host: Optional[str] = None) -> List[ParsedEvent]:
        events: List[ParsedEvent] = []

        for line_no, line in enumerate(raw_content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            event = self._parse_line(line, line_no)
            if event is not None:
                events.append(event)

        logger.debug(f"LinuxAuthLogParser: parsed {len(events)} events from {len(raw_content.splitlines())} lines")
        return events

    def _parse_line(self, line: str, line_no: int) -> Optional[ParsedEvent]:
        if match := _FAILED_PASSWORD_RE.search(line):
            return self._build_login_event(match, line, event_type="failed_login", severity_hint="medium")

        if match := _ACCEPTED_PASSWORD_RE.search(line):
            return self._build_login_event(match, line, event_type="successful_login", severity_hint="low")

        if match := _SUDO_RE.search(line):
            return self._build_sudo_event(match, line)

        logger.debug(f"LinuxAuthLogParser: line {line_no} did not match any known pattern, skipping")
        return None

    def _build_login_event(self, match: re.Match, raw_line: str, event_type: str, severity_hint: str) -> Optional[ParsedEvent]:
        try:
            timestamp = _parse_syslog_timestamp(match.group("ts"))
        except ValueError:
            logger.warning(f"LinuxAuthLogParser: could not parse timestamp in line: {raw_line}")
            return None

        return ParsedEvent(
            event_category=EventCategory.AUTHENTICATION,
            event_type=event_type,
            user=match.group("user"),
            source_ip=match.group("ip"),
            raw_log=raw_line,
            parsed_fields={"host": match.group("host"), "port": match.group("port")},
            timestamp=timestamp,
            severity_hint=severity_hint,
        )

    def _build_sudo_event(self, match: re.Match, raw_line: str) -> Optional[ParsedEvent]:
        try:
            timestamp = _parse_syslog_timestamp(match.group("ts"))
        except ValueError:
            logger.warning(f"LinuxAuthLogParser: could not parse timestamp in line: {raw_line}")
            return None

        return ParsedEvent(
            event_category=EventCategory.SYSTEM,
            event_type="privilege_command",
            user=match.group("user"),
            raw_log=raw_line,
            parsed_fields={
                "host": match.group("host"),
                "target_user": match.group("target_user"),
                "command": match.group("command").strip(),
            },
            timestamp=timestamp,
            severity_hint="medium" if match.group("target_user") == "root" else "low",
        )
