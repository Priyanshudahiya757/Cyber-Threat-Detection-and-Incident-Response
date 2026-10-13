"""
tests/test_model_registry.py

Purpose:
    Tests versioning, persistence, and metadata tracking in isolation
    from the process-wide default_registry by constructing a fresh
    ModelRegistry pointed at pytest's tmp_path for every test — no test
    ever touches the real ml/models/ directory.
"""
import numpy as np
import pytest

from app.detection.ml.isolation_forest_model import IsolationForestModel
from app.detection.ml.model_registry import ModelRegistry


def _fitted_model(seed=42):
    model = IsolationForestModel(contamination=0.1, random_state=seed)
    X = np.random.RandomState(seed).normal(0, 1, (30, 8))
    model.fit(X)
    return model


class TestModelRegistry:
    def test_get_latest_model_returns_none_when_empty(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        assert registry.get_latest_model() is None

    def test_get_latest_metadata_returns_none_when_empty(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        assert registry.get_latest_metadata() is None

    def test_register_model_persists_and_is_loadable(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        model = _fitted_model()

        version = registry.register_model(
            model=model,
            feature_names=["f1", "f2"],
            n_samples=30,
            metrics={"anomaly_ratio": 0.1},
        )

        assert version == "v1"
        loaded = registry.get_latest_model()
        assert loaded is not None
        assert loaded.model_type == "isolation_forest"

    def test_versions_increment(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))

        v1 = registry.register_model(_fitted_model(1), ["f1"], 10, {})
        v2 = registry.register_model(_fitted_model(2), ["f1"], 10, {})
        v3 = registry.register_model(_fitted_model(3), ["f1"], 10, {})

        assert [v1, v2, v3] == ["v1", "v2", "v3"]

    def test_get_latest_model_returns_most_recent_version(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        registry.register_model(_fitted_model(1), ["f1"], 10, {"tag": "first"})
        registry.register_model(_fitted_model(2), ["f1"], 10, {"tag": "second"})

        metadata = registry.get_latest_metadata()
        assert metadata["version"] == "v2"
        assert metadata["metrics"]["tag"] == "second"

    def test_list_all_metadata_returns_every_version(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        registry.register_model(_fitted_model(1), ["f1"], 10, {})
        registry.register_model(_fitted_model(2), ["f1"], 10, {})

        all_meta = registry.list_all_metadata()
        assert len(all_meta) == 2
        assert {m["version"] for m in all_meta} == {"v1", "v2"}

    def test_metadata_includes_feature_names_and_n_samples(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        registry.register_model(_fitted_model(), ["failed_login_count", "total_event_count"], 42, {})

        metadata = registry.get_latest_metadata()
        assert metadata["feature_names"] == ["failed_login_count", "total_event_count"]
        assert metadata["n_samples"] == 42

    def test_unknown_model_type_raises_on_load(self, tmp_path):
        registry = ModelRegistry(base_dir=str(tmp_path))
        # Manually inject a metadata entry for a model_type with no
        # registered class, to exercise the lookup-failure branch
        # specifically (rather than the "no metadata at all" branch).
        registry._append_index_entry(
            {
                "model_type": "nonexistent_model_type",
                "version": "v1",
                "trained_at": "2026-01-01T00:00:00+00:00",
                "feature_names": [],
                "n_samples": 1,
                "params": {},
                "metrics": {},
                "file": "nonexistent_model_type_v1.joblib",
            }
        )
        with pytest.raises(ValueError):
            registry.get_latest_model(model_type="nonexistent_model_type")
