"""
app/detection/ml/model_registry.py

Purpose:
    Versions and persists trained AnomalyModel artifacts to disk (under
    settings.ML_MODEL_DIR), alongside a JSON metadata index recording
    when each version was trained, on how much data, with what
    hyperparameters, and what evaluation metrics it achieved. This is
    what makes "model persistence" and "retraining pipeline" concrete:
    retraining produces a NEW version rather than overwriting the model
    currently serving predictions, and PredictionService always asks the
    registry for "the latest version" rather than hardcoding a path.

    Deliberately filesystem+JSON rather than a database table: model
    artifacts are binary blobs that belong beside the code/deployment
    (mounted as a Docker volume, per docker-compose.yml), and the
    metadata index is small enough that a JSON file avoids adding a
    Mongo dependency to a module that's really about file I/O.

Connects to:
    - training_service.py calls register_model() after fitting
    - prediction_service.py calls get_latest_model() to load for inference
    - api/v1/ml.py exposes list_model_versions() for the model info endpoint
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.core.logging_config import get_logger
from app.detection.ml.base_model import AnomalyModel
from app.detection.ml.isolation_forest_model import IsolationForestModel

logger = get_logger(__name__)

#: Maps model_type string -> the class that implements it. Extended when
#: a new AnomalyModel implementation is added (e.g. "autoencoder": AutoencoderModel).
MODEL_CLASS_REGISTRY: Dict[str, type] = {
    "isolation_forest": IsolationForestModel,
}


class ModelRegistry:
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir or settings.ML_MODEL_DIR)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.base_dir / "registry_index.json"

    def register_model(
        self,
        model: AnomalyModel,
        feature_names: List[str],
        n_samples: int,
        metrics: Dict[str, Any],
    ) -> str:
        """
        Persists `model` as a new version and appends its metadata to the
        registry index. Returns the assigned version string (e.g. "v3").
        """
        version = self._next_version(model.model_type)
        model_path = self._model_path(model.model_type, version)
        model.save(model_path)

        entry = {
            "model_type": model.model_type,
            "version": version,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "feature_names": feature_names,
            "n_samples": n_samples,
            "params": model.get_params(),
            "metrics": metrics,
            "file": str(model_path.name),
        }
        self._append_index_entry(entry)
        logger.info(f"ModelRegistry: registered {model.model_type} {version} (n_samples={n_samples})")
        return version

    def get_latest_model(self, model_type: str = "isolation_forest") -> Optional[AnomalyModel]:
        entry = self.get_latest_metadata(model_type)
        if entry is None:
            return None

        model_class = MODEL_CLASS_REGISTRY.get(model_type)
        if model_class is None:
            raise ValueError(f"No model class registered for model_type '{model_type}'")

        path = self._model_path(model_type, entry["version"])
        return model_class.load(path)

    def get_latest_metadata(self, model_type: str = "isolation_forest") -> Optional[Dict[str, Any]]:
        entries = [e for e in self._read_index() if e["model_type"] == model_type]
        if not entries:
            return None
        return max(entries, key=lambda e: e["trained_at"])

    def list_all_metadata(self) -> List[Dict[str, Any]]:
        return self._read_index()

    def _next_version(self, model_type: str) -> str:
        existing = [e for e in self._read_index() if e["model_type"] == model_type]
        return f"v{len(existing) + 1}"

    def _model_path(self, model_type: str, version: str) -> Path:
        return self.base_dir / f"{model_type}_{version}.joblib"

    def _read_index(self) -> List[Dict[str, Any]]:
        if not self._index_path.exists():
            return []
        with open(self._index_path, "r") as f:
            return json.load(f)

    def _append_index_entry(self, entry: Dict[str, Any]) -> None:
        entries = self._read_index()
        entries.append(entry)
        with open(self._index_path, "w") as f:
            json.dump(entries, f, indent=2, default=str)


#: Process-wide singleton used by training_service.py and prediction_service.py.
default_registry = ModelRegistry()
