"""
app/detection/ml/isolation_forest_model.py

Purpose:
    scikit-learn IsolationForest wrapped behind the AnomalyModel
    interface. This is the only place sklearn's IsolationForest API is
    touched directly — training_service.py and prediction_service.py
    only ever see the AnomalyModel contract, so swapping in a different
    algorithm later (e.g. sklearn's OneClassSVM, or a custom autoencoder)
    means writing one new class here, not touching either service.

Connects to:
    - Implements app.detection.ml.base_model.AnomalyModel
    - Instantiated by training_service.py, persisted via model_registry.py
"""
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.detection.ml.base_model import AnomalyModel


class IsolationForestModel(AnomalyModel):
    """
    Wraps sklearn.ensemble.IsolationForest.

    `contamination` is the expected proportion of anomalies in the
    training data — it directly controls the decision threshold between
    predict()'s -1/1 output. 0.05 (5%) is a reasonable default for
    security telemetry where genuine attacks are a small minority of
    traffic; it's exposed as a constructor parameter so training_service
    can tune it per dataset rather than it being a hardcoded assumption
    baked into this class.
    """

    model_type = "isolation_forest"

    def __init__(self, n_estimators: int = 100, contamination: float = 0.05, random_state: int = 42):
        self._params = {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": random_state,
        }
        self._model = IsolationForest(**self._params)
        self._is_fitted = False

    def fit(self, X: np.ndarray) -> None:
        self._model.fit(X)
        self._is_fitted = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        self._ensure_fitted()
        return self._model.predict(X)

    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        self._ensure_fitted()
        return self._model.decision_function(X)

    def save(self, path: Path) -> None:
        self._ensure_fitted()
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "params": self._params}, path)

    @classmethod
    def load(cls, path: Path) -> "IsolationForestModel":
        payload = joblib.load(path)
        instance = cls(**payload["params"])
        instance._model = payload["model"]
        instance._is_fitted = True
        return instance

    def get_params(self) -> Dict[str, Any]:
        return dict(self._params)

    def _ensure_fitted(self) -> None:
        if not self._is_fitted:
            raise RuntimeError("IsolationForestModel.fit() must be called before predict/decision_scores")
