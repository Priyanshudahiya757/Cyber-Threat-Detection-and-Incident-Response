"""
tests/test_detection_engine.py

Purpose:
    Tests RuleEngine orchestration: running multiple rules, isolating a
    misbehaving rule, and the enable/disable configuration surface —
    independent of any individual rule's detection logic (that's covered
    in test_detection_rules.py).
"""
from datetime import datetime, timedelta

import pytest

from app.detection.engine import RuleEngine, handle_ingested_logs
from app.detection.rules.base_rule import BaseRule
from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.models.detection_schema import DetectionEvent, DetectionEngine as EngineType, Entity, EntityType
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


class _AlwaysFiresRule(BaseRule):
    rule_name = "always_fires"
    description = "Test rule that always produces one detection."
    mitre_technique = "T0000 - Test"

    def evaluate(self, logs):
        return [
            DetectionEvent(
                engine=EngineType.RULE,
                rule_name=self.rule_name,
                confidence=0.9,
                severity=Severity.HIGH,
                entity=Entity(type=EntityType.IP, value="1.2.3.4"),
                evidence_log_ids=[logs[0].log_id] if logs else [],
                explanation="test",
            )
        ]


class _BrokenRule(BaseRule):
    rule_name = "broken_rule"
    description = "Test rule that always raises."
    mitre_technique = "T0000 - Test"

    def evaluate(self, logs):
        raise RuntimeError("simulated rule bug")


class TestRuleEngine:
    def test_runs_all_registered_rules(self):
        engine = RuleEngine(rules=[_AlwaysFiresRule()])
        detections = engine.run([make_log()])
        assert len(detections) == 1
        assert detections[0].rule_name == "always_fires"

    def test_broken_rule_does_not_block_other_rules(self):
        engine = RuleEngine(rules=[_BrokenRule(), _AlwaysFiresRule()])
        detections = engine.run([make_log()])
        assert len(detections) == 1
        assert detections[0].rule_name == "always_fires"

    def test_empty_log_batch_returns_no_detections(self):
        engine = RuleEngine(rules=[_AlwaysFiresRule()])
        assert engine.run([]) == []

    def test_disabled_rule_does_not_run(self):
        rule = _AlwaysFiresRule()
        engine = RuleEngine(rules=[rule])
        engine.set_rule_enabled("always_fires", False)
        assert engine.run([make_log()]) == []

    def test_set_rule_enabled_returns_false_for_unknown_rule(self):
        engine = RuleEngine(rules=[_AlwaysFiresRule()])
        assert engine.set_rule_enabled("nonexistent", False) is False

    def test_default_engine_loads_all_eight_rules(self):
        engine = RuleEngine()  # uses _default_rules()
        rule_names = {r.rule_name for r in engine.list_rules()}
        assert rule_names == {
            "ssh_brute_force",
            "windows_failed_login",
            "port_scan",
            "sql_injection",
            "xss",
            "directory_traversal",
            "privilege_escalation",
            "suspicious_admin_login",
        }

    def test_real_rule_integration_end_to_end(self):
        """Sanity check: a real rule (not a test double) fires through the engine."""
        engine = RuleEngine(rules=[SSHBruteForceRule()])
        logs = [
            make_log(source_ip="192.168.1.20", timestamp=BASE_TIME + timedelta(seconds=i * 2))
            for i in range(5)
        ]
        detections = engine.run(logs)
        assert len(detections) == 1
        assert detections[0].rule_name == "ssh_brute_force"


@pytest.mark.asyncio
class TestHandleIngestedLogs:
    async def test_persists_detections_and_generates_alerts(self, monkeypatch):
        saved_detections = []
        generated_alerts = []

        async def fake_save_detections(detections):
            saved_detections.extend(detections)

        async def fake_generate_alerts(detections):
            generated_alerts.extend(detections)
            return detections

        monkeypatch.setattr("app.db.mongo.save_detections", fake_save_detections)
        monkeypatch.setattr("app.detection.alerting.generate_alerts", fake_generate_alerts)

        logs = [
            make_log(source_ip="192.168.1.20", timestamp=BASE_TIME + timedelta(seconds=i * 2))
            for i in range(5)
        ]
        await handle_ingested_logs(logs)

        assert len(saved_detections) == 1
        assert len(generated_alerts) == 1

    async def test_no_detections_means_no_persistence_calls(self, monkeypatch):
        called = {"save": False, "alert": False}

        async def fake_save_detections(detections):
            called["save"] = True

        async def fake_generate_alerts(detections):
            called["alert"] = True
            return []

        monkeypatch.setattr("app.db.mongo.save_detections", fake_save_detections)
        monkeypatch.setattr("app.detection.alerting.generate_alerts", fake_generate_alerts)

        # A single benign log won't trigger any of the 8 default rules.
        await handle_ingested_logs([make_log(event_type="successful_login")])

        assert called["save"] is False
        assert called["alert"] is False
