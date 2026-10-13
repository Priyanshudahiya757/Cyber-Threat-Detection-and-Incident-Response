"""
tests/test_training_service.py

Purpose:
    Tests TrainingService.train() against synthetic NormalizedLog data
    (isolated via a tmp_path-backed ModelRegistry) and
    evaluate_on_labeled_dataset() against the real generated CSV fixture
    — the latter is a genuine integration check that the shipped sample
    dataset actually produces sane precision/recall, not just that the
    code path executes.
"""
import os
from datetime import datetime, timedelta

import pytest

from app.detection.ml.model_registry import ModelRegistry
from app.detection.ml.training_service import InsufficientTrainingDataError, TrainingService
from app.models.log_schema import EventCategory, NormalizedLog, SourceType

BASE_TIME = datetime(2026, 7, 18, 12, 0, 0)

SAMPLE_DATASET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "ml", "datasets", "sample_training_data.csv"
)


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


def _logs_for_n_entities(n: int, events_per_entity: int = 3):
    logs = []
    for i in range(n):
        ip = f"10.0.0.{i}"
        for j in range(events_per_entity):
            logs.append(make_log(ip, timestamp=BASE_TIME + timedelta(seconds=j)))
    return logs


class TestTrainingServiceTrain:
    def test_raises_below_minimum_entities(self, tmp_path):
        service = TrainingService(registry=ModelRegistry(base_dir=str(tmp_path)))
        logs = _logs_for_n_entities(2)  # below MIN_TRAINING_SAMPLES

        with pytest.raises(InsufficientTrainingDataError):
            service.train(logs)

    def test_trains_and_registers_model(self, tmp_path):
        service = TrainingService(registry=ModelRegistry(base_dir=str(tmp_path)))
        logs = _logs_for_n_entities(10)

        result = service.train(logs)

        assert result.version == "v1"
        assert result.model_type == "isolation_forest"
        assert result.n_samples == 10
        assert result.n_features == 8
        assert 0.0 <= result.anomaly_ratio <= 1.0

    def test_repeated_training_creates_new_versions(self, tmp_path):
        service = TrainingService(registry=ModelRegistry(base_dir=str(tmp_path)))
        logs = _logs_for_n_entities(10)

        result1 = service.train(logs)
        result2 = service.train(logs)

        assert result1.version == "v1"
        assert result2.version == "v2"

    def test_trained_model_is_retrievable_from_registry(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        service = TrainingService(registry=registry)
        logs = _logs_for_n_entities(10)

        service.train(logs)

        model = registry.get_latest_model()
        assert model is not None


class TestEvaluateOnLabeledDataset:
    def test_dataset_fixture_exists(self):
        assert os.path.exists(SAMPLE_DATASET_PATH), (
            "Run ml/datasets/generate_sample_data.py to generate the fixture before running this test."
        )

    def test_evaluation_produces_reasonable_metrics(self, tmp_path):
        service = TrainingService(registry=ModelRegistry(base_dir=str(tmp_path)))
        metrics = service.evaluate_on_labeled_dataset(SAMPLE_DATASET_PATH, contamination=0.1)

        assert metrics["n_samples"] == 200
        assert metrics["n_true_anomalies"] == 20
        # A reasonable Isolation Forest on this cleanly-separated synthetic
        # data should substantially beat random guessing.
        assert metrics["precision"] > 0.5
        assert metrics["recall"] > 0.5
        assert metrics["f1_score"] > 0.5

    def test_missing_columns_raises(self, tmp_path):
        import pandas as pd

        bad_csv = tmp_path / "bad.csv"
        pd.DataFrame({"only_one_column": [1, 2, 3]}).to_csv(bad_csv, index=False)

        service = TrainingService(registry=ModelRegistry(base_dir=str(tmp_path)))
        with pytest.raises(ValueError):
            service.evaluate_on_labeled_dataset(str(bad_csv))
