"""
app/detection/ml/training_service.py

Purpose:
    Orchestrates model training: extract features from historical logs
    -> fit an AnomalyModel -> compute training-time diagnostics ->
    register the new version via ModelRegistry. Also provides
    evaluate_on_labeled_dataset(), which trains+evaluates against a
    synthetic labeled CSV (ml/datasets/sample_training_data.csv) to
    produce real precision/recall/F1 metrics — something pure unsupervised
    training on unlabeled production logs can't give you, and which the
    project brief explicitly asks for ("evaluation metrics").

    Kept as a class (not free functions) because it holds one piece of
    configurable state — which ModelRegistry to write to — making it easy
    to inject a temp-directory registry in tests without monkeypatching
    module globals.

Connects to:
    - api/v1/ml.py::train_model / retrain_model call TrainingService.train()
    - detection/ml/feature_extraction.py for X construction
    - detection/ml/isolation_forest_model.py for the concrete model
    - detection/ml/model_registry.py for persistence
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from app.core.logging_config import get_logger
from app.detection.ml.base_model import AnomalyModel
from app.detection.ml.feature_extraction import FEATURE_NAMES, extract_feature_matrix
from app.detection.ml.isolation_forest_model import IsolationForestModel
from app.detection.ml.model_registry import ModelRegistry, default_registry
from app.models.log_schema import NormalizedLog

logger = get_logger(__name__)

MIN_TRAINING_SAMPLES = 5


@dataclass
class TrainingResult:
    version: str
    model_type: str
    n_samples: int
    n_features: int
    anomaly_ratio: float
    mean_decision_score: float
    std_decision_score: float
    entities_flagged_anomalous: List[str] = field(default_factory=list)


class InsufficientTrainingDataError(Exception):
    """Raised when fewer than MIN_TRAINING_SAMPLES entities are available to train on."""


class TrainingService:
    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or default_registry

    def train(
        self,
        logs: List[NormalizedLog],
        contamination: float = 0.05,
        n_estimators: int = 100,
    ) -> TrainingResult:
        """
        Extracts per-entity features from `logs`, fits a fresh
        IsolationForest, and registers it as a new version. Raises
        InsufficientTrainingDataError rather than silently training a
        near-meaningless model on a handful of entities — Isolation
        Forest technically runs on tiny data, but a model "trained" on 2
        entities has no useful notion of "normal" and would produce
        misleading anomaly scores in production.
        """
        X, entity_order = extract_feature_matrix(logs)

        if len(entity_order) < MIN_TRAINING_SAMPLES:
            raise InsufficientTrainingDataError(
                f"Need at least {MIN_TRAINING_SAMPLES} distinct source IPs to train; got {len(entity_order)}"
            )

        model: AnomalyModel = IsolationForestModel(n_estimators=n_estimators, contamination=contamination)
        model.fit(X)

        predictions = model.predict(X)
        scores = model.decision_scores(X)
        anomalous_entities = [entity_order[i] for i, p in enumerate(predictions) if p == -1]

        metrics = {
            "anomaly_ratio": float((predictions == -1).mean()),
            "mean_decision_score": float(scores.mean()),
            "std_decision_score": float(scores.std()),
        }

        version = self.registry.register_model(
            model=model,
            feature_names=FEATURE_NAMES,
            n_samples=len(entity_order),
            metrics=metrics,
        )

        logger.info(
            f"TrainingService: trained {model.model_type} {version} on {len(entity_order)} entities, "
            f"{len(anomalous_entities)} flagged anomalous"
        )

        return TrainingResult(
            version=version,
            model_type=model.model_type,
            n_samples=len(entity_order),
            n_features=X.shape[1],
            anomaly_ratio=metrics["anomaly_ratio"],
            mean_decision_score=metrics["mean_decision_score"],
            std_decision_score=metrics["std_decision_score"],
            entities_flagged_anomalous=anomalous_entities,
        )

    def evaluate_on_labeled_dataset(self, csv_path: str, contamination: float = 0.1) -> Dict[str, Any]:
        """
        Trains a throwaway model (not registered — this is evaluation,
        not production training) on a labeled synthetic dataset and
        reports precision/recall/F1/accuracy against the known labels.

        Expected CSV columns: FEATURE_NAMES + "label" (1 = anomaly, 0 = normal).
        See ml/datasets/sample_training_data.csv and
        ml/datasets/generate_sample_data.py for how this fixture is built.

        Isolation Forest is unsupervised — training doesn't see `label` —
        so this measures how well the model's own notion of "outlier"
        (driven purely by contamination + feature geometry) lines up with
        our synthetic ground truth. That's a legitimate and standard way
        to sanity-check an unsupervised model before trusting it in
        production, and it's what "evaluation metrics" means in this
        context, as opposed to supervised-classifier metrics.
        """
        df = pd.read_csv(csv_path)
        missing_cols = set(FEATURE_NAMES + ["label"]) - set(df.columns)
        if missing_cols:
            raise ValueError(f"Dataset missing required columns: {missing_cols}")

        X = df[FEATURE_NAMES].to_numpy(dtype=np.float64)
        y_true = df["label"].to_numpy()  # 1 = anomaly, 0 = normal

        model = IsolationForestModel(contamination=contamination)
        model.fit(X)
        raw_predictions = model.predict(X)  # -1 = anomaly, 1 = normal
        y_pred = np.where(raw_predictions == -1, 1, 0)  # normalize to 1/0 convention

        metrics = {
            "n_samples": len(df),
            "n_true_anomalies": int(y_true.sum()),
            "n_predicted_anomalies": int(y_pred.sum()),
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),  # [[TN, FP], [FN, TP]]
        }

        logger.info(
            f"TrainingService.evaluate_on_labeled_dataset: precision={metrics['precision']:.2f} "
            f"recall={metrics['recall']:.2f} f1={metrics['f1_score']:.2f}"
        )

        return metrics


default_training_service = TrainingService()
