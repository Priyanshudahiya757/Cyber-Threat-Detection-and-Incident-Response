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

from app.detection.engine import RuleEngine
from app.detection.rules.base_rule import BaseRule, RuleConfigError
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


class TestRuleSettings:
    def test_settings_start_at_declared_defaults(self):
        assert SSHBruteForceRule().config == {"threshold": 4, "window_seconds": 120}

    def test_updated_threshold_takes_effect_immediately(self):
        rule = SSHBruteForceRule()
        logs = [
            make_log(source_ip="192.168.1.20", timestamp=BASE_TIME + timedelta(seconds=i * 2))
            for i in range(5)
        ]
        assert len(rule.evaluate(logs)) == 1

        rule.update_config({"threshold": 6})
        assert rule.evaluate(logs) == []

    def test_unknown_setting_is_rejected(self):
        with pytest.raises(RuleConfigError):
            SSHBruteForceRule().update_config({"no_such_setting": 1})

    def test_out_of_range_value_is_rejected_and_nothing_is_applied(self):
        rule = SSHBruteForceRule()
        with pytest.raises(RuleConfigError):
            rule.update_config({"window_seconds": 300, "threshold": 0})
        assert rule.config == {"threshold": 4, "window_seconds": 120}

    def test_persisted_state_is_restored_and_stale_entries_ignored(self):
        engine = RuleEngine(rules=[SSHBruteForceRule()])
        engine.apply_persisted_state(
            [
                {"rule_name": "ssh_brute_force", "enabled": False, "config": {"threshold": 9}},
                {"rule_name": "rule_that_was_removed", "enabled": True, "config": {}},
            ]
        )
        rule = engine.get_rule("ssh_brute_force")
        assert rule.enabled is False
        assert rule.config["threshold"] == 9
