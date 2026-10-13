"""
app/detection/ml/prediction_service.py

Purpose:
    Loads the latest registered model and scores a batch of NormalizedLog
    for anomalies, producing DetectionEvent objects (engine="ml") in the
    exact same shape rule-based detections use — this is what lets
    incidents/correlator.py (Phase 7) treat ML and rule detections
    identically, and what makes the ML engine a drop-in addition to
    detection/engine.py's on_ingested pipeline rather than a parallel
    system.

    Risk scoring: IsolationForest's decision_function output is a raw,
    unbounded real number (lower = more anomalous) with no intrinsic
    "percent" meaning. This service converts it to an intuitive 0-100
    risk_percentage via min-max normalization *within the scored batch*.
    That's a deliberate, documented simplification — a globally
    calibrated risk score would need a fixed reference distribution from
    training time, which is a reasonable Phase-2-of-ML enhancement, not
    a blocker for a working, explainable first version.

Connects to:
    - detection/ml/model_registry.py for loading the latest model
    - detection/ml/feature_extraction.py for building the score matrix
    - Produces app.models.detection_schema.DetectionEvent (engine=ML),
      unifying with detection/engine.py's rule-based output
"""
from typing import Dict, List, Optional

import numpy as np

from app.core.logging_config import get_logger
from app.detection.ml.feature_extraction import FEATURE_NAMES, extract_entity_features
from app.detection.ml.model_registry import ModelRegistry, default_registry
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity

logger = get_logger(__name__)

#: Anomaly detections at or above this risk percentage are surfaced as
#: HIGH severity rather than MEDIUM — mirrors the rule engine's severity
#: escalation pattern for consistency across both detection engines.
HIGH_RISK_THRESHOLD = 75.0


class NoTrainedModelError(Exception):
    """Raised when prediction is requested but no model has been trained yet."""


class PredictionService:
    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or default_registry

    def predict(self, logs: List[NormalizedLog], model_type: str = "isolation_forest") -> List[DetectionEvent]:
        """
        Scores every entity present in `logs` against the latest trained
        model and returns a DetectionEvent for each one flagged
        anomalous. Returns an empty list (with a warning logged) rather
        than raising if no model has been trained yet — this keeps the
        ingestion pipeline's on_ingested hook resilient exactly the way
        detection/engine.py's per-rule exception handling does; a
        not-yet-trained ML engine shouldn't block rule-based detection.
        """
        model = self.registry.get_latest_model(model_type)
        if model is None:
            logger.warning(
                f"PredictionService: no trained '{model_type}' model available yet; skipping ML detection"
            )
            return []

        entity_features = extract_entity_features(logs)
        if not entity_features:
            return []

        entity_order = list(entity_features.keys())
        X = np.vstack([entity_features[ip] for ip in entity_order])

        predictions = model.predict(X)
        scores = model.decision_scores(X)
        risk_percentages = self._scores_to_risk_percentages(scores)

        # Map entity -> its evidence log_ids, for the DetectionEvent trail.
        evidence_by_entity: Dict[str, List[str]] = {}
        for log in logs:
            if log.source_ip:
                evidence_by_entity.setdefault(log.source_ip, []).append(log.log_id)

        detections: List[DetectionEvent] = []
        for i, entity_ip in enumerate(entity_order):
            if predictions[i] != -1:
                continue  # not flagged anomalous by the model

            risk = risk_percentages[i]
            severity = Severity.HIGH if risk >= HIGH_RISK_THRESHOLD else Severity.MEDIUM
            explanation = self._build_explanation(entity_features[entity_ip], risk)

            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.ML,
                    anomaly_score=float(scores[i]),
                    risk_percentage=round(risk, 2),
                    confidence=round(min(1.0, risk / 100.0), 2),
                    severity=severity,
                    entity=Entity(type=EntityType.IP, value=entity_ip),
                    evidence_log_ids=evidence_by_entity.get(entity_ip, [])[:50],
                    explanation=explanation,
                )
            )

        if detections:
            logger.info(f"PredictionService: flagged {len(detections)} anomalous entities out of {len(entity_order)}")

        return detections

    @staticmethod
    def _scores_to_risk_percentages(scores: np.ndarray) -> np.ndarray:
        """Min-max normalize decision scores (lower=more anomalous) to a 0-100 risk scale (higher=riskier)."""
        min_score, max_score = scores.min(), scores.max()
        spread = max_score - min_score
        if spread == 0:
            # All entities equally "normal" relative to each other — no
            # meaningful risk differentiation possible within this batch.
            return np.zeros_like(scores)
        return 100.0 * (max_score - scores) / spread

    @staticmethod
    def _build_explanation(feature_vector: np.ndarray, risk: float) -> str:
        """
        Basic explainability: report the top contributing raw feature
        values by magnitude, so an analyst sees *why* an entity was
        flagged rather than just a bare score. This is intentionally
        simple (no SHAP/LIME) — appropriate for a first ML pass, and
        upgradeable later without changing the DetectionEvent contract.
        """
        ranked = sorted(zip(FEATURE_NAMES, feature_vector), key=lambda x: x[1], reverse=True)
        top_features = ", ".join(f"{name}={value:.1f}" for name, value in ranked[:3] if value > 0)
        return (
            f"Isolation Forest flagged this entity as anomalous (risk {risk:.0f}%). "
            f"Top contributing signals: {top_features or 'low overall activity relative to peers'}."
        )


default_prediction_service = PredictionService()
