"""
tests/test_alerting.py

Purpose:
    Alert generation rules: which severities alert, the cool-down that
    stops an ongoing attack from alerting on every batch, and resilience
    to storage failures.
"""
import pytest

from app.detection.alerting import generate_alerts
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import Severity


def make_detection(severity: Severity, ip: str = "192.168.1.20", **overrides) -> DetectionEvent:
    defaults = dict(
        engine=DetectionEngine.RULE,
        rule_name="ssh_brute_force",
        confidence=0.8,
        severity=severity,
        mitre_technique="T1110 - Brute Force",
        entity=Entity(type=EntityType.IP, value=ip),
        evidence_log_ids=["a", "b"],
        explanation="test detection",
    )
    defaults.update(overrides)
    return DetectionEvent(**defaults)


@pytest.mark.asyncio
class TestGenerateAlerts:
    async def test_high_and_critical_generate_alerts(self, mock_db):
        alerts = await generate_alerts(
            [make_detection(Severity.HIGH, ip="10.0.0.1"), make_detection(Severity.CRITICAL, ip="10.0.0.2")]
        )

        assert [a.severity for a in alerts] == ["high", "critical"]
        assert await mock_db.alerts.count_documents({}) == 2
        assert all(a.id for a in alerts)

    async def test_low_and_medium_do_not_generate_alerts(self, mock_db):
        alerts = await generate_alerts([make_detection(Severity.LOW), make_detection(Severity.MEDIUM)])

        assert alerts == []
        assert await mock_db.alerts.count_documents({}) == 0

    async def test_alert_carries_the_detection_details(self, mock_db):
        detection = make_detection(Severity.HIGH)
        [alert] = await generate_alerts([detection])

        assert alert.threat_type == "ssh_brute_force"
        assert alert.title == "SSH Brute Force — 192.168.1.20"
        assert alert.detection_id == detection.detection_id
        assert alert.acknowledged is False

    async def test_ml_detection_is_labelled_as_ai_anomaly(self, mock_db):
        detection = make_detection(Severity.HIGH, engine=DetectionEngine.ML, rule_name=None, mitre_technique=None)
        [alert] = await generate_alerts([detection])

        assert alert.threat_type == "ml_anomaly"
        assert alert.title.startswith("AI Anomaly")

    async def test_repeat_for_same_entity_and_threat_is_suppressed(self, mock_db):
        first = await generate_alerts([make_detection(Severity.HIGH)])
        again = await generate_alerts([make_detection(Severity.CRITICAL, evidence_log_ids=["a", "b", "c"])])

        assert len(first) == 1
        assert again == []
        assert await mock_db.alerts.count_documents({}) == 1

    async def test_duplicates_within_one_call_are_suppressed(self, mock_db):
        alerts = await generate_alerts([make_detection(Severity.HIGH), make_detection(Severity.HIGH)])
        assert len(alerts) == 1

    async def test_different_threat_on_same_entity_still_alerts(self, mock_db):
        await generate_alerts([make_detection(Severity.HIGH)])
        other = await generate_alerts([make_detection(Severity.HIGH, rule_name="port_scan")])
        assert len(other) == 1

    async def test_persistence_failure_does_not_raise(self, mock_db, monkeypatch):
        async def failing_save_alert(alert):
            raise ConnectionError("mongo is down")

        monkeypatch.setattr("app.detection.alerting.save_alert", failing_save_alert)

        assert await generate_alerts([make_detection(Severity.HIGH)]) == []
