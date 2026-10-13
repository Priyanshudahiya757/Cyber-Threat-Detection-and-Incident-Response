"""
tests/test_parsers.py

Purpose:
    Unit tests for each source-specific parser. These are pure logic
    tests — no database, no mocking required — which is exactly the
    point of separating parsing from storage (Single Responsibility):
    parser correctness can be verified in isolation.
"""
import json

import pytest

from app.ingestion.parsers.firewall_parser import FirewallLogParser
from app.ingestion.parsers.linux_parser import LinuxAuthLogParser
from app.ingestion.parsers.web_parser import WebServerLogParser
from app.ingestion.parsers.windows_parser import WindowsEventLogParser
from app.models.log_schema import EventCategory


class TestLinuxAuthLogParser:
    def setup_method(self):
        self.parser = LinuxAuthLogParser()

    def test_parses_failed_password(self):
        line = "Jul 18 09:12:03 web01 sshd[14231]: Failed password for root from 192.168.1.20 port 51422 ssh2"
        events = self.parser.parse(line)

        assert len(events) == 1
        event = events[0]
        assert event.event_type == "failed_login"
        assert event.event_category == EventCategory.AUTHENTICATION
        assert event.user == "root"
        assert event.source_ip == "192.168.1.20"
        assert event.severity_hint == "medium"

    def test_parses_invalid_user_failed_password(self):
        line = "Jul 18 09:12:13 web01 sshd[14231]: Failed password for invalid user oracle from 192.168.1.20 port 51432 ssh2"
        events = self.parser.parse(line)

        assert len(events) == 1
        assert events[0].user == "oracle"

    def test_parses_accepted_password(self):
        line = "Jul 18 09:14:22 web01 sshd[14300]: Accepted password for deploy from 10.0.0.5 port 44210 ssh2"
        events = self.parser.parse(line)

        assert len(events) == 1
        assert events[0].event_type == "successful_login"
        assert events[0].severity_hint == "low"

    def test_parses_sudo_command(self):
        line = "Jul 18 09:20:01 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
        events = self.parser.parse(line)

        assert len(events) == 1
        assert events[0].event_type == "privilege_command"
        assert events[0].user == "deploy"
        assert events[0].parsed_fields["target_user"] == "root"
        assert events[0].severity_hint == "medium"

    def test_skips_unrecognized_lines(self):
        line = "Jul 18 09:20:01 web01 kernel: some unrelated kernel message"
        events = self.parser.parse(line)
        assert events == []

    def test_skips_blank_lines(self):
        events = self.parser.parse("\n\n   \n")
        assert events == []

    def test_brute_force_pattern_produces_multiple_events(self):
        content = "\n".join(
            [
                f"Jul 18 09:12:0{i} web01 sshd[1423{i}]: Failed password for root from 192.168.1.20 port 5142{i} ssh2"
                for i in range(5)
            ]
        )
        events = self.parser.parse(content)
        assert len(events) == 5
        assert all(e.source_ip == "192.168.1.20" for e in events)


class TestWindowsEventLogParser:
    def setup_method(self):
        self.parser = WindowsEventLogParser()

    def test_parses_json_array(self):
        records = [
            {
                "EventID": 4625,
                "TimeCreated": "2026-07-18T09:40:11Z",
                "Computer": "DC01.corp.local",
                "TargetUserName": "Administrator",
                "IpAddress": "203.0.113.44",
                "LogonType": 3,
            }
        ]
        events = self.parser.parse(json.dumps(records))

        assert len(events) == 1
        assert events[0].event_type == "failed_login"
        assert events[0].user == "Administrator"
        assert events[0].source_ip == "203.0.113.44"
        assert events[0].severity_hint == "medium"

    def test_maps_successful_login(self):
        records = [
            {
                "EventID": 4624,
                "TimeCreated": "2026-07-18T09:41:02Z",
                "TargetUserName": "jsmith",
                "IpAddress": "10.0.0.12",
            }
        ]
        events = self.parser.parse(json.dumps(records))
        assert events[0].event_type == "successful_login"

    def test_unmapped_event_id_uses_default(self):
        records = [{"EventID": 9999, "TimeCreated": "2026-07-18T09:41:02Z"}]
        events = self.parser.parse(json.dumps(records))
        assert events[0].event_type == "windows_event"

    def test_missing_event_id_is_skipped(self):
        records = [{"TimeCreated": "2026-07-18T09:41:02Z"}]
        events = self.parser.parse(json.dumps(records))
        assert events == []

    def test_missing_timestamp_is_skipped(self):
        records = [{"EventID": 4624}]
        events = self.parser.parse(json.dumps(records))
        assert events == []

    def test_ndjson_format_supported(self):
        content = "\n".join(
            [
                json.dumps({"EventID": 4625, "TimeCreated": "2026-07-18T09:40:11Z", "TargetUserName": "a"}),
                json.dumps({"EventID": 4625, "TimeCreated": "2026-07-18T09:40:12Z", "TargetUserName": "b"}),
            ]
        )
        events = self.parser.parse(content)
        assert len(events) == 2


class TestFirewallLogParser:
    def setup_method(self):
        self.parser = FirewallLogParser()

    def test_parses_deny_line(self):
        line = "2026-07-18 11:03:10 DENY TCP 198.51.100.23:40011 -> 10.0.0.100:21 SYN"
        events = self.parser.parse(line)

        assert len(events) == 1
        event = events[0]
        assert event.event_type == "connection_denied"
        assert event.source_ip == "198.51.100.23"
        assert event.dest_ip == "10.0.0.100"
        assert event.dest_port == 21
        assert event.parsed_fields["protocol"] == "TCP"

    def test_parses_allow_line(self):
        line = "2026-07-18 11:00:01 ALLOW TCP 10.0.0.5:51000 -> 10.0.0.100:443 SYN"
        events = self.parser.parse(line)
        assert events[0].event_type == "connection_allowed"

    def test_port_scan_pattern_produces_multiple_distinct_ports(self):
        content = "\n".join(
            [
                f"2026-07-18 11:03:1{i} DENY TCP 198.51.100.23:4001{i} -> 10.0.0.100:{20+i} SYN"
                for i in range(6)
            ]
        )
        events = self.parser.parse(content)
        ports = {e.dest_port for e in events}
        assert len(ports) == 6

    def test_malformed_line_skipped(self):
        events = self.parser.parse("this is not a firewall log line")
        assert events == []


class TestWebServerLogParser:
    def setup_method(self):
        self.parser = WebServerLogParser()

    def test_parses_benign_request(self):
        line = '192.168.1.15 - - [18/Jul/2026:10:02:11 +0000] "GET /index.html HTTP/1.1" 200 5231 "-" "Mozilla/5.0"'
        events = self.parser.parse(line)

        assert len(events) == 1
        event = events[0]
        assert event.source_ip == "192.168.1.15"
        assert event.parsed_fields["method"] == "GET"
        assert event.parsed_fields["path"] == "/index.html"
        assert event.parsed_fields["status_code"] == 200

    def test_parses_sql_injection_attempt_path(self):
        line = (
            '203.0.113.77 - - [18/Jul/2026:10:05:02 +0000] '
            '"GET /product?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 512 "-" "python-requests/2.31"'
        )
        events = self.parser.parse(line)

        assert len(events) == 1
        assert "OR" in events[0].parsed_fields["path"]
        assert events[0].parsed_fields["status_code"] == 500

    def test_dash_size_treated_as_zero(self):
        line = '198.51.100.9 - - [18/Jul/2026:10:11:20 +0000] "GET /../../../../etc/passwd HTTP/1.1" 400 - "-" "curl/8.4.0"'
        events = self.parser.parse(line)
        assert events[0].parsed_fields["response_size_bytes"] == 0

    def test_malformed_line_skipped(self):
        events = self.parser.parse("not a valid access log line")
        assert events == []


class TestSampleLogFixtures:
    """
    Sanity-check each parser against the real fixture files in
    sample_logs/, which is what the demo seed script uploads.
    Confirms parsers handle full multi-line files, not just single lines.
    """

    SAMPLE_LOGS_DIR = "../../sample_logs"

    def _read_fixture(self, filename: str) -> str:
        import os

        path = os.path.join(os.path.dirname(__file__), self.SAMPLE_LOGS_DIR, filename)
        with open(path, "r") as f:
            return f.read()

    def test_linux_sample_file(self):
        content = self._read_fixture("linux_auth.log")
        events = LinuxAuthLogParser().parse(content)
        assert len(events) >= 10
        assert any(e.event_type == "failed_login" for e in events)
        assert any(e.event_type == "successful_login" for e in events)

    def test_windows_sample_file(self):
        content = self._read_fixture("windows_sample.json")
        events = WindowsEventLogParser().parse(content)
        assert len(events) == 6
        assert any(e.event_type == "failed_login" for e in events)

    def test_firewall_sample_file(self):
        content = self._read_fixture("firewall_sample.log")
        events = FirewallLogParser().parse(content)
        assert len(events) == 13
        denied = [e for e in events if e.event_type == "connection_denied"]
        assert len(denied) == 10

    def test_web_sample_file(self):
        content = self._read_fixture("web_access.log")
        events = WebServerLogParser().parse(content)
        assert len(events) == 10
