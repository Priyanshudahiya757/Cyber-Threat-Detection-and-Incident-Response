"""
app/api/v1/ml.py

Purpose:
    Exposes the ML anomaly detection subsystem: training/retraining over
    recent Elasticsearch data, on-demand prediction over a time window,
    model registry inspection, and evaluation against the labeled
    synthetic dataset (ml/datasets/sample_training_data.csv).

    Training/retraining is admin-only (it changes what "anomalous" means
    for every analyst going forward); prediction and model inspection
    are available to both roles.

Connects to:
    - db/elastic.py::search_logs to assemble the training/prediction window
    - detection/ml/training_service.py for fit + evaluation
    - detection/ml/prediction_service.py for scoring
    - detection/ml/model_registry.py for version listing
    - db/mongo.py to persist detections found via manual prediction runs
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.dependencies import require_role
from app.core.logging_config import get_logger
from app.db.elastic import search_logs
from app.db.mongo import save_detections
from app.detection.alerting import generate_alerts
from app.detection.ml.model_registry import default_registry
from app.detection.ml.prediction_service import NoTrainedModelError, default_prediction_service
from app.detection.ml.training_service import InsufficientTrainingDataError, default_training_service
from app.models.log_schema import NormalizedLog
from app.models.user_schema import UserInDB, UserRole

router = APIRouter(prefix="/ml", tags=["AI Anomaly Detection"])
logger = get_logger(__name__)

def _resolve_sample_dataset() -> str:
    candidates = [
        os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "..", "ml", "datasets", "sample_training_data.csv"
        ),
        "/ml/datasets/sample_training_data.csv",
        os.path.join(os.getcwd(), "ml", "datasets", "sample_training_data.csv"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return candidates[0]


_SAMPLE_DATASET_PATH = _resolve_sample_dataset()


@router.post("/train", status_code=status.HTTP_201_CREATED)
async def train_model(
    days: int = Query(default=7, ge=1, le=90, description="How many days of history to train on"),
    contamination: float = Query(default=0.05, ge=0.01, le=0.5),
    current_user: UserInDB = Depends(require_role(UserRole.ADMIN)),
):
    """
    Trains a new Isolation Forest version on the last `days` of ingested
    logs and registers it as the new latest version (existing versions
    are retained, not deleted — see model_registry.py). This endpoint
    doubles as the "retraining pipeline": there's no separate /retrain
    route because retraining IS training again with fresh data; the
    registry's versioning is what makes repeated calls to this endpoint
    safe and auditable.
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    search_result = await search_logs(start_time=start_time, end_time=end_time, size=10000)
    logs = [NormalizedLog(**doc) for doc in search_result["results"]]

    try:
        result = await _train_async(logs, contamination)
    except InsufficientTrainingDataError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    logger.info(f"ML model trained by {current_user.username}: version={result.version} n_samples={result.n_samples}")

    return {
        "version": result.version,
        "model_type": result.model_type,
        "n_samples": result.n_samples,
        "n_features": result.n_features,
        "anomaly_ratio": result.anomaly_ratio,
        "entities_flagged_anomalous": result.entities_flagged_anomalous,
    }


@router.post("/predict", status_code=status.HTTP_200_OK)
async def predict_anomalies(
    minutes: int = Query(default=60, ge=1, le=1440),
    current_user: UserInDB = Depends(require_role(UserRole.ADMIN, UserRole.SOC_ANALYST)),
):
    """Scores the last `minutes` of ingested logs against the latest trained model."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=minutes)

    search_result = await search_logs(start_time=start_time, end_time=end_time, size=5000)
    logs = [NormalizedLog(**doc) for doc in search_result["results"]]

    detections = default_prediction_service.predict(logs)

    if detections:
        await save_detections(detections)
        alerts = await generate_alerts(detections)
        try:
            from app.incidents.correlator import correlate_detections

            await correlate_detections(detections)
        except Exception as exc:
            logger.error(f"ML predict: incident correlation failed: {exc}")
    else:
        alerts = []

    return {
        "logs_scanned": len(logs),
        "anomalies_found": len(detections),
        "alerts_generated": len(alerts),
        "detections": [d.model_dump() for d in detections],
    }


@router.get("/models")
async def list_models(current_user: UserInDB = Depends(require_role(UserRole.ADMIN, UserRole.SOC_ANALYST))):
    """Lists every trained model version with its training metadata and metrics."""
    return {"models": default_registry.list_all_metadata()}


@router.get("/models/latest")
async def get_latest_model_info(current_user: UserInDB = Depends(require_role(UserRole.ADMIN, UserRole.SOC_ANALYST))):
    metadata = default_registry.get_latest_metadata()
    if metadata is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No model has been trained yet")
    return metadata


@router.post("/evaluate")
async def evaluate_model(
    contamination: float = Query(default=0.1, ge=0.01, le=0.5),
    current_user: UserInDB = Depends(require_role(UserRole.ADMIN)),
):
    """
    Runs precision/recall/F1 evaluation against the labeled synthetic
    dataset (ml/datasets/sample_training_data.csv). This does NOT
    register a model — it's purely diagnostic, intended for the project
    report/viva to demonstrate the model's detection quality against
    known ground truth.
    """
    if not os.path.exists(_SAMPLE_DATASET_PATH):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample evaluation dataset not found. Run ml/datasets/generate_sample_data.py first.",
        )

    metrics = default_training_service.evaluate_on_labeled_dataset(_SAMPLE_DATASET_PATH, contamination=contamination)
    return metrics


async def _train_async(logs, contamination: float):
    # TrainingService.train is CPU-bound (sklearn) and synchronous by
    # nature; running it directly is acceptable at this project's scale
    # (thousands, not millions, of samples). A production deployment
    # training on much larger windows would offload this to a background
    # worker (Celery/RQ) rather than blocking the request — noted here
    # rather than over-engineered prematurely.
    return default_training_service.train(logs, contamination=contamination)
