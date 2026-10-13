"""
app/detection/ml/isolation_forest_model.py

Purpose:
    scikit-learn IsolationForest wrapped behind the AnomalyModel
    interface. This is the only place sklearn's IsolationForest API is
    touched directly — training_service.py and prediction_service.py
    only ever see the AnomalyModel contract, so swapping in a different
    algorithm later (e.g. sklearn's OneClassSVM, or a custom autoencoder)
    means writing one new class here, not touching either service.

    Alongside the fitted forest, the model keeps two things learned from
    the training data: the score of the most anomalous training entity
    (the yardstick for risk_scores) and each feature's typical value and
    spread (the baseline for feature_deviations). Both are saved with the
    model, so a risk score means the same thing on every prediction run.

Connects to:
    - Implements app.detection.ml.base_model.AnomalyModel
    - Instantiated by training_service.py, persisted via model_registry.py
"""
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.detection.ml.base_model import AnomalyModel

#: Smallest score distance treated as "fully anomalous". Guards the risk
#: scale when the training data contained no clear outlier.
_MIN_SCORE_REFERENCE = 0.05


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
        self._score_reference = _MIN_SCORE_REFERENCE
        self._feature_mean: Optional[np.ndarray] = None
        self._feature_std: Optional[np.ndarray] = None

    def fit(self, X: np.ndarray) -> None:
        self._model.fit(X)
        self._is_fitted = True
        self._score_reference = max(_MIN_SCORE_REFERENCE, float(-self._model.decision_function(X).min()))
        self._feature_mean = X.mean(axis=0)
        # A constant feature has zero spread; use 1 so deviations stay finite.
        self._feature_std = np.where(X.std(axis=0) > 0, X.std(axis=0), 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        self._ensure_fitted()
        return self._model.predict(X)

    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        self._ensure_fitted()
        return self._model.decision_function(X)

    def risk_scores(self, X: np.ndarray) -> np.ndarray:
        # decision score 0 is the anomaly boundary -> 50; a score as low
        # as the worst training entity -> 100; equally far on the normal
        # side -> 0.
        scores = self.decision_scores(X)
        return np.clip(50.0 * (1.0 - scores / self._score_reference), 0.0, 100.0)

    def feature_deviations(self, X: np.ndarray) -> np.ndarray:
        self._ensure_fitted()
        if self._feature_mean is None or self._feature_std is None:
            return np.zeros_like(X, dtype=np.float64)
        return (X - self._feature_mean) / self._feature_std

    def save(self, path: Path) -> None:
        self._ensure_fitted()
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "params": self._params,
                "score_reference": self._score_reference,
                "feature_mean": self._feature_mean,
                "feature_std": self._feature_std,
            },
            path,
        )

    @classmethod
    def load(cls, path: Path) -> "IsolationForestModel":
        payload = joblib.load(path)
        instance = cls(**payload["params"])
        instance._model = payload["model"]
        instance._is_fitted = True
        # .get(): model files saved before calibration was added lack these keys.
        instance._score_reference = payload.get("score_reference", _MIN_SCORE_REFERENCE)
        instance._feature_mean = payload.get("feature_mean")
        instance._feature_std = payload.get("feature_std")
        return instance

    def get_params(self) -> Dict[str, Any]:
        return dict(self._params)

    def _ensure_fitted(self) -> None:
        if not self._is_fitted:
            raise RuntimeError("IsolationForestModel.fit() must be called before predict/decision_scores")
