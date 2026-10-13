"""
app/detection/ml/base_model.py

Purpose:
    Defines the contract every anomaly detection model must implement
    (Strategy pattern, mirroring BaseLogParser and BaseRule). This is
    what satisfies "design so additional models can be added later" —
    IsolationForestModel is the only implementation today, but an
    AutoencoderModel or RandomForestModel would implement the same four
    methods and drop into ModelRegistry / PredictionService with zero
    changes to either (Open/Closed Principle).

    Models operate on plain numpy feature matrices, not on NormalizedLog
    or DetectionEvent directly — that separation (feature extraction vs.
    model fitting vs. result interpretation) is what makes each piece
    independently testable: feature_extraction.py can be tested without
    ever fitting a model, and a model can be tested with synthetic numpy
    arrays without ever touching a NormalizedLog.

Connects to:
    - Implemented by isolation_forest_model.py
    - Consumed by training_service.py (fit) and prediction_service.py
      (predict/score)
    - Persisted/loaded via model_registry.py
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np


class AnomalyModel(ABC):
    """
    Abstract contract for an unsupervised anomaly detection model.

    Convention: predict() returns -1 for anomalies and 1 for normal
    points (matching scikit-learn's IsolationForest/OneClassSVM
    convention), so callers can treat any AnomalyModel implementation
    identically regardless of the underlying algorithm.
    """

    #: Short identifier used in persisted metadata and API responses,
    #: e.g. "isolation_forest". Overridden by each subclass.
    model_type: str

    @abstractmethod
    def fit(self, X: np.ndarray) -> None:
        """Fit the model on a feature matrix of shape (n_samples, n_features)."""
        raise NotImplementedError

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return an array of shape (n_samples,) with values in {-1, 1}."""
        raise NotImplementedError

    @abstractmethod
    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Return raw anomaly scores of shape (n_samples,). Convention:
        LOWER scores are MORE anomalous (matches scikit-learn's
        decision_function), so downstream risk-percentage conversion is
        consistent regardless of which model produced the scores.
        """
        raise NotImplementedError

    @abstractmethod
    def save(self, path: Path) -> None:
        """Persist model weights/parameters to `path`."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def load(cls, path: Path) -> "AnomalyModel":
        """Load a previously saved model from `path`."""
        raise NotImplementedError

    @abstractmethod
    def get_params(self) -> Dict[str, Any]:
        """Return the hyperparameters this model was constructed with (for metadata/audit)."""
        raise NotImplementedError
