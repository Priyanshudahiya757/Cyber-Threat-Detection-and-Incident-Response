"""
tests/test_normalizer.py

Purpose:
    Verifies ParsedEvent -> NormalizedLog mapping, severity resolution,
    and deterministic log_id generation (the mechanism duplicate
    detection depends on).
"""
from datetime import datetime

from app.ingestion.normalizer import compute_log_id, normalize
from app.ingestion.parsers.base_parser import ParsedEvent
from app.models.log_schema import EventCategory, Severity, SourceType


def _sample_event(**overrides) -> ParsedEvent:
    defaults = dict(
        event_category=EventCategory.AUTHENTICATION,
        event_type="failed_login",
        user="root",
        source_ip="192.168.1.20",
        raw_log="Failed password for root from 192.168.1.20 port 51422 ssh2",
        timestamp=datetime(2026, 7, 18, 9, 12, 3),
        severity_hint="medium",
    )
    defaults.update(overrides)
    return ParsedEvent(**defaults)


class TestNormalize:
    def test_maps_all_fields(self):
        event = _sample_event()
        log = normalize(event, source_type=SourceType.LINUX, source_host="web01")

        assert log.source_type == SourceType.LINUX.value
        assert log.source_host == "web01"
        assert log.user == "root"
        assert log.source_ip == "192.168.1.20"
        assert log.severity == Severity.MEDIUM.value

    def test_defaults_severity_when_hint_missing(self):
        event = _sample_event(severity_hint=None)
        log = normalize(event, source_type=SourceType.LINUX)
        assert log.severity == Severity.LOW.value

    def test_invalid_severity_hint_falls_back_to_low(self):
        event = _sample_event(severity_hint="not_a_real_severity")
        log = normalize(event, source_type=SourceType.LINUX)
        assert log.severity == Severity.LOW.value

    def test_log_id_is_deterministic(self):
        event = _sample_event()
        log1 = normalize(event, source_type=SourceType.LINUX, source_host="web01")
        log2 = normalize(event, source_type=SourceType.LINUX, source_host="web01")
        assert log1.log_id == log2.log_id

    def test_log_id_differs_for_different_content(self):
        event1 = _sample_event(raw_log="line A")
        event2 = _sample_event(raw_log="line B")
        log1 = normalize(event1, source_type=SourceType.LINUX)
        log2 = normalize(event2, source_type=SourceType.LINUX)
        assert log1.log_id != log2.log_id

    def test_log_id_differs_across_source_hosts(self):
        event = _sample_event()
        log1 = normalize(event, source_type=SourceType.LINUX, source_host="web01")
        log2 = normalize(event, source_type=SourceType.LINUX, source_host="web02")
        assert log1.log_id != log2.log_id


class TestComputeLogId:
    def test_same_inputs_produce_same_hash(self):
        id1 = compute_log_id(SourceType.LINUX, "web01", "raw line", "2026-07-18T09:12:03")
        id2 = compute_log_id(SourceType.LINUX, "web01", "raw line", "2026-07-18T09:12:03")
        assert id1 == id2

    def test_is_sha256_hex_digest(self):
        log_id = compute_log_id(SourceType.LINUX, "web01", "raw line", "2026-07-18T09:12:03")
        assert len(log_id) == 64
        int(log_id, 16)  # raises ValueError if not valid hex
