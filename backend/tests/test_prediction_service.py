"""
tests/test_prediction_service.py

Purpose:
    Tests PredictionService against a tmp_path-backed registry: no
    trained model yet (graceful empty result), a trained model scoring a
    clear outlier vs. normal entities, and the DetectionEvent shape
    (engine=ML, risk_percentage, evidence trail) it produces.
"""
from datetime import datetime, timedelta

from app.detection.ml.model_registry import ModelRegistry
from app.detection.ml.prediction_service import PredictionService
from app.detection.ml.training_service import TrainingService
from app.models.detection_schema import DetectionEngine
from app.models.log_schema import EventCategory, NormalizedLog, SourceType

BASE_TIME = datetime(2026, 7, 18, 12, 0, 0)


def make_log(source_ip: str, **overrides) -> NormalizedLog:
    defaults = dict(
        source_type=SourceType.LINUX,
        event_category=EventCategory.AUTHENTICATION,
        event_type="failed_login",
        source_ip=source_ip,
        raw_log="raw",
        timestamp=BASE_TIME,
    )
    defaults.update(overrides)
    return NormalizedLog(**defaults)


def _normal_entity_logs(ip: str) -> list:
    """A handful of routine events — nothing anomalous."""
    return [
        make_log(ip, event_type="successful_login", timestamp=BASE_TIME + timedelta(seconds=i))
        for i in range(2)
    ]


def _brute_force_entity_logs(ip: str) -> list:
    """A large burst of failed logins — should stand out as an outlier."""
    return [
        make_log(ip, event_type="failed_login", timestamp=BASE_TIME + timedelta(seconds=i))
        for i in range(40)
    ]


class TestPredictionServiceNoModel:
    def test_returns_empty_list_when_no_model_trained(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        service = PredictionService(registry=registry)

        logs = _normal_entity_logs("10.0.0.1")
        assert service.predict(logs) == []


class TestPredictionServiceWithTrainedModel:
    def _train_on_mixed_population(self, registry: ModelRegistry):
        training_logs = []
        for i in range(15):
            training_logs.extend(_normal_entity_logs(f"10.0.1.{i}"))
        # One clear brute-force outlier in the training population too,
        # so the model has something to contrast against.
        training_logs.extend(_brute_force_entity_logs("10.0.1.99"))

        TrainingService(registry=registry).train(training_logs, contamination=0.1)

    def test_flags_clear_outlier_entity(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        self._train_on_mixed_population(registry)

        service = PredictionService(registry=registry)
        # Score a fresh batch containing one obviously anomalous entity
        # alongside normal ones.
        scoring_logs = []
        for i in range(15):
            scoring_logs.extend(_normal_entity_logs(f"10.0.2.{i}"))
        scoring_logs.extend(_brute_force_entity_logs("203.0.113.99"))

        detections = service.predict(scoring_logs)
        flagged_ips = {d.entity.value for d in detections}

        assert "203.0.113.99" in flagged_ips

    def test_detection_event_shape(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        self._train_on_mixed_population(registry)

        service = PredictionService(registry=registry)
        scoring_logs = _brute_force_entity_logs("203.0.113.99")
        for i in range(15):
            scoring_logs.extend(_normal_entity_logs(f"10.0.3.{i}"))

        detections = service.predict(scoring_logs)
        assert len(detections) >= 1

        detection = next(d for d in detections if d.entity.value == "203.0.113.99")
        assert detection.engine == DetectionEngine.ML.value
        assert detection.anomaly_score is not None
        assert 0 <= detection.risk_percentage <= 100
        assert 0 <= detection.confidence <= 1
        assert len(detection.evidence_log_ids) > 0
        assert "Isolation Forest" in detection.explanation

    def test_empty_logs_returns_empty(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        self._train_on_mixed_population(registry)

        service = PredictionService(registry=registry)
        assert service.predict([]) == []
