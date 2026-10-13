"""
tests/test_feature_extraction.py

Purpose:
    Tests per-entity feature computation in isolation — pure logic over
    NormalizedLog lists, no model or database involved, matching the
    testability pattern used for parsers/rules throughout the project.
"""
from datetime import datetime

import numpy as np

from app.detection.ml.feature_extraction import FEATURE_NAMES, extract_entity_features, extract_feature_matrix
from app.models.log_schema import EventCategory, NormalizedLog, SourceType

BASE_TIME = datetime(2026, 7, 18, 14, 0, 0)  # 2 PM, business hours


def make_log(**overrides) -> NormalizedLog:
    defaults = dict(
        source_type=SourceType.LINUX,
        event_category=EventCategory.AUTHENTICATION,
        event_type="failed_login",
        source_ip="192.168.1.20",
        raw_log="raw",
        timestamp=BASE_TIME,
    )
    defaults.update(overrides)
    return NormalizedLog(**defaults)


class TestExtractEntityFeatures:
    def test_empty_logs_returns_empty_dict(self):
        assert extract_entity_features([]) == {}

    def test_logs_without_source_ip_are_excluded(self):
        log = make_log(source_ip=None)
        assert extract_entity_features([log]) == {}

    def test_single_entity_feature_vector_shape(self):
        logs = [make_log() for _ in range(3)]
        features = extract_entity_features(logs)

        assert "192.168.1.20" in features
        assert features["192.168.1.20"].shape == (len(FEATURE_NAMES),)

    def test_failed_login_count_accurate(self):
        logs = [make_log(event_type="failed_login") for _ in range(4)] + [
            make_log(event_type="successful_login")
        ]
        features = extract_entity_features(logs)
        vec = features["192.168.1.20"]

        failed_idx = FEATURE_NAMES.index("failed_login_count")
        success_idx = FEATURE_NAMES.index("successful_login_count")
        total_idx = FEATURE_NAMES.index("total_event_count")

        assert vec[failed_idx] == 4
        assert vec[success_idx] == 1
        assert vec[total_idx] == 5

    def test_distinct_dest_ports_counted(self):
        logs = [make_log(dest_port=p) for p in [22, 80, 443]]
        features = extract_entity_features(logs)
        idx = FEATURE_NAMES.index("distinct_dest_ports")
        assert features["192.168.1.20"][idx] == 3

    def test_off_hours_ratio_computed(self):
        # 4 events at 2 AM (off-hours), 1 at 2 PM (business hours)
        off_hours_logs = [make_log(timestamp=datetime(2026, 7, 18, 2, 0, 0)) for _ in range(4)]
        business_hours_log = [make_log(timestamp=datetime(2026, 7, 18, 14, 0, 0))]
        features = extract_entity_features(off_hours_logs + business_hours_log)

        idx = FEATURE_NAMES.index("off_hours_event_ratio")
        assert features["192.168.1.20"][idx] == 0.8  # 4/5

    def test_avg_response_size_from_web_logs(self):
        logs = [
            make_log(
                source_type=SourceType.WEB_SERVER,
                event_type="http_request",
                parsed_fields={"response_size_bytes": size},
            )
            for size in [1000, 2000, 3000]
        ]
        features = extract_entity_features(logs)
        idx = FEATURE_NAMES.index("avg_response_size_bytes")
        assert features["192.168.1.20"][idx] == 2000.0

    def test_avg_response_size_zero_when_no_web_data(self):
        logs = [make_log() for _ in range(3)]
        features = extract_entity_features(logs)
        idx = FEATURE_NAMES.index("avg_response_size_bytes")
        assert features["192.168.1.20"][idx] == 0.0

    def test_multiple_entities_computed_independently(self):
        logs = [make_log(source_ip="10.0.0.1") for _ in range(2)] + [
            make_log(source_ip="10.0.0.2") for _ in range(5)
        ]
        features = extract_entity_features(logs)
        total_idx = FEATURE_NAMES.index("total_event_count")

        assert features["10.0.0.1"][total_idx] == 2
        assert features["10.0.0.2"][total_idx] == 5


class TestExtractFeatureMatrix:
    def test_returns_matrix_and_ordered_entity_list(self):
        logs = [make_log(source_ip="10.0.0.2")] + [make_log(source_ip="10.0.0.1")]
        X, entity_order = extract_feature_matrix(logs)

        assert X.shape == (2, len(FEATURE_NAMES))
        assert entity_order == ["10.0.0.1", "10.0.0.2"]  # sorted

    def test_empty_logs_returns_empty_matrix(self):
        X, entity_order = extract_feature_matrix([])
        assert X.shape == (0, len(FEATURE_NAMES))
        assert entity_order == []

    def test_matrix_rows_match_entity_order(self):
        logs_ip1 = [make_log(source_ip="10.0.0.1") for _ in range(10)]
        logs_ip2 = [make_log(source_ip="10.0.0.2") for _ in range(2)]
        X, entity_order = extract_feature_matrix(logs_ip1 + logs_ip2)

        total_idx = FEATURE_NAMES.index("total_event_count")
        ip1_row = entity_order.index("10.0.0.1")
        ip2_row = entity_order.index("10.0.0.2")

        assert X[ip1_row, total_idx] == 10
        assert X[ip2_row, total_idx] == 2
