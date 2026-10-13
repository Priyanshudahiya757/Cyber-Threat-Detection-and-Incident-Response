"""
tests/test_alerting.py

Purpose:
    Tests alert generation thresholding logic in isolation from MongoDB
    (save_alert is monkeypatched, matching the established pattern for
    anything touching a repository function).
"""
import pytest

from app.detection.alerting import generate_alerts
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import Severity


def make_detection(severity: Severity, **overrides) -> DetectionEvent:
    defaults = dict(
        engine=DetectionEngine.RULE,
        rule_name="ssh_brute_force",
        confidence=0.8,
        severity=severity,
        mitre_technique="T1110 - Brute Force",
        entity=Entity(type=EntityType.IP, value="192.168.1.20"),
        evidence_log_ids=["a", "b"],
        explanation="test detection",
    )
    defaults.update(overrides)
    return DetectionEvent(**defaults)


@pytest.mark.asyncio
class TestGenerateAlerts:
    async def test_high_severity_generates_alert(self, monkeypatch):
        saved = []

        async def fake_save_alert(alert):
            saved.append(alert)

        monkeypatch.setattr("app.detection.alerting.save_alert", fake_save_alert)

        detection = make_detection(Severity.HIGH)
        result = await generate_alerts([detection])

        assert len(result) == 1
        assert len(saved) == 1
        assert saved[0].severity == Severity.HIGH.value

    async def test_critical_severity_generates_alert(self, monkeypatch):
        saved = []

        async def fake_save_alert(alert):
            saved.append(alert)

        monkeypatch.setattr("app.detection.alerting.save_alert", fake_save_alert)

        detection = make_detection(Severity.CRITICAL)
        result = await generate_alerts([detection])
        assert len(result) == 1

    async def test_low_severity_does_not_generate_alert(self, monkeypatch):
        saved = []

        async def fake_save_alert(alert):
            saved.append(alert)

        monkeypatch.setattr("app.detection.alerting.save_alert", fake_save_alert)

        detection = make_detection(Severity.LOW)
        result = await generate_alerts([detection])

        assert result == []
        assert saved == []

    async def test_medium_severity_does_not_generate_alert(self, monkeypatch):
        async def fake_save_alert(alert):
            pass

        monkeypatch.setattr("app.detection.alerting.save_alert", fake_save_alert)

        detection = make_detection(Severity.MEDIUM)
        result = await generate_alerts([detection])
        assert result == []

    async def test_mixed_severities_only_alerts_qualifying_ones(self, monkeypatch):
        saved = []

        async def fake_save_alert(alert):
            saved.append(alert)

        monkeypatch.setattr("app.detection.alerting.save_alert", fake_save_alert)

        detections = [
            make_detection(Severity.LOW),
            make_detection(Severity.HIGH),
            make_detection(Severity.MEDIUM),
            make_detection(Severity.CRITICAL),
        ]
        result = await generate_alerts(detections)

        assert len(result) == 2
        assert len(saved) == 2

    async def test_alert_persistence_failure_does_not_raise(self, monkeypatch):
        async def failing_save_alert(alert):
            raise ConnectionError("mongo is down")

        monkeypatch.setattr("app.detection.alerting.save_alert", failing_save_alert)

        detection = make_detection(Severity.HIGH)
        result = await generate_alerts([detection])  # should not raise
        assert result == []  # failed to persist, so not included
