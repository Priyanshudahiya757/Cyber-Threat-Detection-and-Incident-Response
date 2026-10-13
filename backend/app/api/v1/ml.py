"""
app/api/v1/ml.py

Purpose:
    Exposes the ML anomaly detection subsystem: training/retraining over
    recently ingested logs, on-demand scoring, model registry inspection,
    and evaluation against the labeled synthetic dataset
    (ml/datasets/sample_training_data.csv).

    Training is admin-only (it changes what "anomalous" means for every
    analyst going forward); scoring and model inspection are available
    to every authenticated user.

Connects to:
    - detection/service.py for assembling log windows and recording findings
    - detection/ml/training_service.py for fit + evaluation
    - detection/ml/model_registry.py for version listing
"""
import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.dependencies import get_current_user, require_admin
from app.core.logging_config import audit_event
from app.detection import service as detection_service
from app.detection.ml.model_registry import default_registry
from app.detection.ml.training_service import InsufficientTrainingDataError, default_training_service
from app.models.detection_schema import DetectionEngine
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/ml", tags=["AI Anomaly Detection"])

#: Locations of the labeled evaluation dataset: repository layout, then the docker-compose mount.
_DATASET_CANDIDATES = [
    Path(__file__).resolve().parents[4] / "ml" / "datasets" / "sample_training_data.csv",
    Path("/ml/datasets/sample_training_data.csv"),
]


@router.post("/train", status_code=status.HTTP_201_CREATED)
async def train_model(
    days: int = Query(default=7, ge=1, le=90, description="Train on logs ingested in the last N days"),
    contamination: float = Query(default=0.05, ge=0.01, le=0.5),
    admin: UserInDB = Depends(require_admin),
):
    """
    Trains a new Isolation Forest version on logs ingested in the last
    `days` and registers it as the latest version. Earlier versions are
    kept, so calling this again is how the model is retrained.
    """
    logs = await detection_service.training_logs(days)

    try:
        # scikit-learn training is CPU-bound; keep it off the event loop.
        result = await asyncio.to_thread(default_training_service.train, logs, contamination)
    except InsufficientTrainingDataError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    audit_event("ml_model_trained", version=result.version, n_samples=result.n_samples, actor=admin.username)
    return {
        "version": result.version,
        "model_type": result.model_type,
        "n_samples": result.n_samples,
        "n_features": result.n_features,
        "anomaly_ratio": result.anomaly_ratio,
        "entities_flagged_anomalous": result.entities_flagged_anomalous,
    }


@router.post("/predict")
async def predict_anomalies(
    minutes: int = Query(default=60, ge=1, le=10_080, description="Score logs ingested in the last N minutes"),
    current_user: UserInDB = Depends(get_current_user),
):
    """Scores recently ingested logs against the latest trained model."""
    if default_registry.get_latest_metadata() is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No model has been trained yet")
    outcome = await detection_service.scan_recent_logs(DetectionEngine.ML, minutes)
    return detection_service.summarize(outcome)


@router.get("/models")
async def list_models(current_user: UserInDB = Depends(get_current_user)):
    """Lists every trained model version with its training metadata and metrics."""
    return {"models": default_registry.list_all_metadata()}


@router.post("/evaluate")
async def evaluate_model(
    contamination: float = Query(default=0.1, ge=0.01, le=0.5),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Runs precision/recall/F1 evaluation against the labeled synthetic
    dataset. This does not register a model — it is a diagnostic that
    shows how well the algorithm separates known attacks from normal
    behaviour.
    """
    dataset = next((path for path in _DATASET_CANDIDATES if path.is_file()), None)
    if dataset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation dataset not found. Run ml/datasets/generate_sample_data.py first.",
        )
    return await asyncio.to_thread(
        default_training_service.evaluate_on_labeled_dataset, str(dataset), contamination
    )
