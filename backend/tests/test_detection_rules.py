"""
tests/test_detection_rules.py

Purpose:
    Unit tests for each detection rule, verified in isolation (pure
    logic over NormalizedLog lists — no database required, matching the
    same testability pattern as tests/test_parsers.py). Each test class
    covers: the rule firing on a genuine attack pattern, the rule NOT
    firing on benign/insufficient data, and the MITRE/severity/confidence
    metadata being populated correctly.
"""
from datetime import datetime, timedelta

from app.detection.rules.directory_traversal import DirectoryTraversalRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.privilege_escalation import PrivilegeEscalationRule
from app.detection.rules.sql_injection import SQLInjectionRule
from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.detection.rules.suspicious_admin_login import SuspiciousAdminLoginRule
from app.detection.rules.windows_failed_login import WindowsFailedLoginRule
from app.detection.rules.xss import XSSRule
from app.models.log_schema import EventCategory, NormalizedLog, Severity, SourceType

BASE_TIME = datetime(2026, 7, 18, 12, 0, 0)


def make_log(**overrides) -> NormalizedLog:
    defaults = dict(
        source_type=SourceType.LINUX,
        event_category=EventCategory.AUTHENTICATION,
        event_type="failed_login",
        raw_log="raw",
        timestamp=BASE_TIME,
    )
    defaults.update(overrides)
    return NormalizedLog(**defaults)


class TestSSHBruteForceRule:
    def setup_method(self):
        self.rule = SSHBruteForceRule()

    def test_fires_above_threshold(self):
        logs = [
            make_log(
                source_ip="192.168.1.20",
                user="root",
                timestamp=BASE_TIME + timedelta(seconds=i * 2),
            )
            for i in range(5)
        ]
        detections = self.rule.evaluate(logs)

        assert len(detections) == 1
        d = detections[0]
        assert d.rule_name == "ssh_brute_force"
        assert d.mitre_technique.startswith("T1110")
        assert d.entity.value == "192.168.1.20"
        assert d.severity in {Severity.HIGH, Severity.CRITICAL}
        assert len(d.evidence_log_ids) == 5

    def test_does_not_fire_below_threshold(self):
        logs = [make_log(source_ip="192.168.1.20") for _ in range(2)]
        assert self.rule.evaluate(logs) == []

    def test_ignores_non_linux_logs(self):
        logs = [
            make_log(source_type=SourceType.WINDOWS, source_ip="192.168.1.20")
            for _ in range(5)
        ]
        assert self.rule.evaluate(logs) == []

    def test_ignores_successful_logins(self):
        logs = [
            make_log(event_type="successful_login", source_ip="192.168.1.20")
            for _ in range(5)
        ]
        assert self.rule.evaluate(logs) == []

    def test_different_ips_evaluated_independently(self):
        logs = [make_log(source_ip="10.0.0.1") for _ in range(2)] + [
            make_log(source_ip="10.0.0.2") for _ in range(2)
        ]
        assert self.rule.evaluate(logs) == []  # neither IP alone hits threshold


class TestWindowsFailedLoginRule:
    def setup_method(self):
        self.rule = WindowsFailedLoginRule()

    def test_fires_above_threshold(self):
        logs = [
            make_log(
                source_type=SourceType.WINDOWS,
                source_ip="203.0.113.44",
                user="Administrator",
                timestamp=BASE_TIME + timedelta(seconds=i * 2),
            )
            for i in range(3)
        ]
        detections = self.rule.evaluate(logs)
        assert len(detections) == 1
        assert detections[0].mitre_technique.startswith("T1110")

    def test_does_not_fire_for_linux(self):
        logs = [make_log(source_type=SourceType.LINUX, source_ip="203.0.113.44") for _ in range(5)]
        assert self.rule.evaluate(logs) == []


class TestPortScanRule:
    def setup_method(self):
        self.rule = PortScanRule()

    def test_fires_on_many_distinct_ports(self):
        logs = [
            make_log(
                source_type=SourceType.FIREWALL,
                event_category=EventCategory.NETWORK,
                event_type="connection_denied",
                source_ip="198.51.100.23",
                dest_ip="10.0.0.100",
                dest_port=20 + i,
                timestamp=BASE_TIME + timedelta(seconds=i),
            )
            for i in range(6)
        ]
        detections = self.rule.evaluate(logs)
        assert len(detections) == 1
        assert detections[0].mitre_technique.startswith("T1046")
        assert detections[0].entity.value == "198.51.100.23"

    def test_does_not_fire_on_single_port_repeated(self):
        logs = [
            make_log(
                source_type=SourceType.FIREWALL,
                event_type="connection_denied",
                source_ip="198.51.100.23",
                dest_ip="10.0.0.100",
                dest_port=22,
                timestamp=BASE_TIME + timedelta(seconds=i),
            )
            for i in range(6)
        ]
        assert self.rule.evaluate(logs) == []

    def test_ignores_allowed_connections(self):
        logs = [
            make_log(
                source_type=SourceType.FIREWALL,
                event_type="connection_allowed",
                source_ip="198.51.100.23",
                dest_ip="10.0.0.100",
                dest_port=20 + i,
            )
            for i in range(6)
        ]
        assert self.rule.evaluate(logs) == []


class TestSQLInjectionRule:
    def setup_method(self):
        self.rule = SQLInjectionRule()

    def test_fires_on_union_select(self):
        log = make_log(
            source_type=SourceType.WEB_SERVER,
            event_category=EventCategory.NETWORK,
            event_type="http_request",
            source_ip="203.0.113.77",
            parsed_fields={"path": "/product?id=1' UNION SELECT username,password FROM users--"},
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1
        assert detections[0].severity == Severity.CRITICAL
        assert detections[0].mitre_technique.startswith("T1190")

    def test_fires_on_boolean_tautology(self):
        log = make_log(
            source_type=SourceType.WEB_SERVER,
            parsed_fields={"path": "/product?id=1' OR '1'='1"},
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1

    def test_does_not_fire_on_benign_request(self):
        log = make_log(source_type=SourceType.WEB_SERVER, parsed_fields={"path": "/index.html"})
        assert self.rule.evaluate([log]) == []

    def test_url_encoded_payload_detected(self):
        log = make_log(
            source_type=SourceType.WEB_SERVER,
            parsed_fields={"path": "/product?id=1%27%20OR%20%271%27=%271"},
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1


class TestXSSRule:
    def setup_method(self):
        self.rule = XSSRule()

    def test_fires_on_script_tag(self):
        log = make_log(
            source_type=SourceType.WEB_SERVER,
            parsed_fields={"path": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"},
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1
        assert detections[0].mitre_technique.startswith("T1059")

    def test_fires_on_event_handler_injection(self):
        log = make_log(
            source_type=SourceType.WEB_SERVER,
            parsed_fields={"path": "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E"},
        )
        assert len(self.rule.evaluate([log])) == 1

    def test_does_not_fire_on_benign_request(self):
        log = make_log(source_type=SourceType.WEB_SERVER, parsed_fields={"path": "/about.html"})
        assert self.rule.evaluate([log]) == []


class TestDirectoryTraversalRule:
    def setup_method(self):
        self.rule = DirectoryTraversalRule()

    def test_fires_on_traversal_sequence(self):
        log = make_log(
            source_type=SourceType.WEB_SERVER,
            parsed_fields={"path": "/../../../../etc/passwd"},
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1
        assert detections[0].mitre_technique.startswith("T1083")

    def test_does_not_fire_on_normal_path(self):
        log = make_log(source_type=SourceType.WEB_SERVER, parsed_fields={"path": "/products/123"})
        assert self.rule.evaluate([log]) == []


class TestPrivilegeEscalationRule:
    def setup_method(self):
        self.rule = PrivilegeEscalationRule()

    def test_fires_on_root_sudo_command(self):
        log = make_log(
            event_category=EventCategory.SYSTEM,
            event_type="privilege_command",
            user="deploy",
            parsed_fields={"target_user": "root", "command": "systemctl restart nginx"},
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1
        assert detections[0].mitre_technique.startswith("T1548")
        assert detections[0].entity.value == "deploy"

    def test_does_not_fire_for_non_root_target(self):
        log = make_log(
            event_type="privilege_command",
            user="deploy",
            parsed_fields={"target_user": "www-data", "command": "ls"},
        )
        assert self.rule.evaluate([log]) == []

    def test_fires_on_windows_group_membership_change(self):
        log = make_log(
            source_type=SourceType.WINDOWS,
            event_type="group_membership_added",
            user="jsmith",
            parsed_fields={"event_id": 4728},
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1
        assert detections[0].severity == Severity.HIGH


class TestSuspiciousAdminLoginRule:
    def setup_method(self):
        self.rule = SuspiciousAdminLoginRule()

    def test_fires_on_off_hours_admin_login(self):
        log = make_log(
            event_type="successful_login",
            user="root",
            timestamp=datetime(2026, 7, 18, 2, 15, 0),  # 2:15 AM
        )
        detections = self.rule.evaluate([log])
        assert len(detections) == 1
        assert detections[0].mitre_technique.startswith("T1078")

    def test_does_not_fire_during_business_hours(self):
        log = make_log(
            event_type="successful_login",
            user="root",
            timestamp=datetime(2026, 7, 18, 14, 0, 0),  # 2 PM
        )
        assert self.rule.evaluate([log]) == []

    def test_does_not_fire_for_non_privileged_account(self):
        log = make_log(
            event_type="successful_login",
            user="jsmith",
            timestamp=datetime(2026, 7, 18, 2, 15, 0),
        )
        assert self.rule.evaluate([log]) == []
