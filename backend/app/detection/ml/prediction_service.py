"""
app/detection/ml/prediction_service.py

Purpose:
    Loads the latest registered model and scores a batch of NormalizedLog
    for anomalies, producing DetectionEvent objects (engine="ml") in the
    exact same shape rule-based detections use — which is what lets
    incidents/correlator.py treat ML and rule detections identically.

    Risk scoring and explanation both come from the model itself
    (AnomalyModel.risk_scores / feature_deviations), calibrated against
    the data it was trained on. A flagged entity's explanation names the
    features that deviate most from the training baseline, not merely
    the largest raw numbers.

Connects to:
    - detection/ml/model_registry.py for loading the latest model
    - detection/ml/feature_extraction.py for building the score matrix
    - detection/service.py calls predict() after ingestion and on manual scans
"""
from typing import Dict, List, Optional

import numpy as np

from app.core.logging_config import get_logger
from app.detection.ml.base_model import AnomalyModel
from app.detection.ml.feature_extraction import FEATURE_NAMES, extract_feature_matrix
from app.detection.ml.model_registry import ModelRegistry, default_registry
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity

logger = get_logger(__name__)

#: Anomalies at or above this risk are HIGH severity rather than MEDIUM.
#: 50 is the model's anomaly boundary, so 75 is halfway to the most
#: anomalous entity seen in training.
HIGH_RISK_THRESHOLD = 75.0

#: A feature must sit at least this many standard deviations above the
#: training baseline to be named in an explanation.
_NOTABLE_DEVIATION = 1.0

#: Evidence log ids attached to one ML detection are capped at this many.
_MAX_EVIDENCE_LOGS = 50


class PredictionService:
    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or default_registry
        self._cached_model: Optional[AnomalyModel] = None
        self._cached_version: Optional[str] = None

    def _latest_model(self, model_type: str) -> Optional[AnomalyModel]:
        """Load the latest model, re-reading from disk only when a new version was registered."""
        metadata = self.registry.get_latest_metadata(model_type)
        if metadata is None:
            return None
        if self._cached_model is None or self._cached_version != metadata["version"]:
            self._cached_model = self.registry.get_latest_model(model_type)
            self._cached_version = metadata["version"]
        return self._cached_model

    def predict(self, logs: List[NormalizedLog], model_type: str = "isolation_forest") -> List[DetectionEvent]:
        """
        Scores every entity present in `logs` against the latest trained
        model and returns a DetectionEvent for each one flagged
        anomalous. Returns an empty list rather than raising if no model
        has been trained yet — a not-yet-trained ML engine shouldn't
        block rule-based detection.
        """
        if not logs:
            return []

        model = self._latest_model(model_type)
        if model is None:
            logger.info(f"PredictionService: no trained '{model_type}' model yet; skipping ML detection")
            return []

        X, entity_order = extract_feature_matrix(logs)
        if not entity_order:
            return []

        predictions = model.predict(X)
        scores = model.decision_scores(X)
        risks = model.risk_scores(X)
        deviations = model.feature_deviations(X)

        evidence_by_entity: Dict[str, List[str]] = {}
        for log in logs:
            if log.source_ip:
                evidence_by_entity.setdefault(log.source_ip, []).append(log.log_id)

        detections: List[DetectionEvent] = []
        for i, entity_ip in enumerate(entity_order):
            if predictions[i] != -1:
                continue  # not flagged anomalous by the model

            risk = float(risks[i])
            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.ML,
                    anomaly_score=float(scores[i]),
                    risk_percentage=round(risk, 2),
                    confidence=round(risk / 100.0, 2),
                    severity=Severity.HIGH if risk >= HIGH_RISK_THRESHOLD else Severity.MEDIUM,
                    entity=Entity(type=EntityType.IP, value=entity_ip),
                    evidence_log_ids=sorted(evidence_by_entity.get(entity_ip, []))[:_MAX_EVIDENCE_LOGS],
                    explanation=self._build_explanation(X[i], deviations[i], risk),
                )
            )

        if detections:
            logger.info(f"PredictionService: flagged {len(detections)} anomalous entities out of {len(entity_order)}")

        return detections

    @staticmethod
    def _build_explanation(features: np.ndarray, deviations: np.ndarray, risk: float) -> str:
        """Name the (up to three) features furthest above the training baseline."""
        ranked = sorted(zip(FEATURE_NAMES, features, deviations), key=lambda item: item[2], reverse=True)
        notable = [
            f"{name}={value:g} ({deviation:.1f}σ above normal)"
            for name, value, deviation in ranked[:3]
            if deviation >= _NOTABLE_DEVIATION
        ]
        signals = ", ".join(notable) or "an unusual combination of otherwise ordinary activity"
        return f"Isolation Forest flagged this entity as anomalous (risk {risk:.0f}%). Top signals: {signals}."


default_prediction_service = PredictionService()
