"""
tests/test_isolation_forest_model.py

Purpose:
    Tests the AnomalyModel contract implementation directly against
    synthetic numpy data — no NormalizedLog, no feature extraction, no
    database. Verifies fit/predict/decision_scores semantics and the
    save/load round trip that model_registry.py depends on.
"""
import numpy as np
import pytest

from app.detection.ml.isolation_forest_model import IsolationForestModel


def _make_data_with_outliers(n_normal=50, n_outliers=5, seed=42):
    rng = np.random.RandomState(seed)
    normal = rng.normal(0, 1, (n_normal, 4))
    outliers = rng.normal(15, 1, (n_outliers, 4))
    return np.vstack([normal, outliers])


class TestIsolationForestModel:
    def test_predict_before_fit_raises(self):
        model = IsolationForestModel()
        with pytest.raises(RuntimeError):
            model.predict(np.zeros((5, 4)))

    def test_decision_scores_before_fit_raises(self):
        model = IsolationForestModel()
        with pytest.raises(RuntimeError):
            model.decision_scores(np.zeros((5, 4)))

    def test_fit_predict_flags_injected_outliers(self):
        X = _make_data_with_outliers()
        model = IsolationForestModel(contamination=0.1, random_state=42)
        model.fit(X)
        predictions = model.predict(X)

        # The last 5 rows are the injected outliers — most should be flagged -1.
        assert (predictions[-5:] == -1).sum() >= 3

    def test_decision_scores_lower_for_outliers(self):
        X = _make_data_with_outliers()
        model = IsolationForestModel(contamination=0.1, random_state=42)
        model.fit(X)
        scores = model.decision_scores(X)

        assert scores[-5:].mean() < scores[:50].mean()

    def test_get_params_returns_constructor_args(self):
        model = IsolationForestModel(n_estimators=50, contamination=0.2, random_state=7)
        params = model.get_params()
        assert params == {"n_estimators": 50, "contamination": 0.2, "random_state": 7}

    def test_save_before_fit_raises(self, tmp_path):
        model = IsolationForestModel()
        with pytest.raises(RuntimeError):
            model.save(tmp_path / "model.joblib")

    def test_save_and_load_round_trip_preserves_predictions(self, tmp_path):
        X = _make_data_with_outliers()
        model = IsolationForestModel(contamination=0.1, random_state=42)
        model.fit(X)
        original_predictions = model.predict(X)

        path = tmp_path / "model.joblib"
        model.save(path)
        loaded_model = IsolationForestModel.load(path)

        loaded_predictions = loaded_model.predict(X)
        assert np.array_equal(original_predictions, loaded_predictions)

    def test_loaded_model_preserves_params(self, tmp_path):
        model = IsolationForestModel(n_estimators=30, contamination=0.15, random_state=1)
        model.fit(_make_data_with_outliers())

        path = tmp_path / "model.joblib"
        model.save(path)
        loaded_model = IsolationForestModel.load(path)

        assert loaded_model.get_params() == {"n_estimators": 30, "contamination": 0.15, "random_state": 1}

    def test_model_type_identifier(self):
        assert IsolationForestModel().model_type == "isolation_forest"
