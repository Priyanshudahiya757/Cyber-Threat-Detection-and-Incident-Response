"""
app/detection/ml/feature_extraction.py

Purpose:
    Converts a batch of NormalizedLog into per-entity (source IP) numeric
    feature vectors suitable for the Isolation Forest (or any future
    AnomalyModel). This is the ML-equivalent of ingestion/normalizer.py:
    a single, well-tested place that maps domain objects to model inputs,
    so feature engineering changes never require touching model code and
    vice versa (SRP).

    Entity choice: source_ip. A real deployment would likely extract
    features per-user as well (privileged-account behavior profiling),
    but a single well-implemented entity dimension is more valuable for
    a first ML pass than two shallow ones — user-level features are a
    natural Phase-2-of-ML extension using the exact same pipeline shape.

Feature vector (order matters — must match FEATURE_NAMES exactly, since
the trained model's weights are positional):
    1. failed_login_count      - count of failed_login events
    2. successful_login_count  - count of successful_login events
    3. total_event_count       - total events from this entity in the window
    4. distinct_event_types    - count of distinct event_type values
    5. distinct_dest_ports     - count of distinct destination ports touched
    6. distinct_dest_ips       - count of distinct destination IPs touched
    7. avg_response_size_bytes - mean HTTP response size (0 if no web events)
    8. off_hours_event_ratio   - fraction of events outside 06:00-22:00 UTC

Connects to:
    - training_service.py calls extract_feature_matrix() over historical logs
    - prediction_service.py calls extract_feature_matrix() over a recent window
"""
from collections import defaultdict
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from app.models.log_schema import NormalizedLog

FEATURE_NAMES: List[str] = [
    "failed_login_count",
    "successful_login_count",
    "total_event_count",
    "distinct_event_types",
    "distinct_dest_ports",
    "distinct_dest_ips",
    "avg_response_size_bytes",
    "off_hours_event_ratio",
]

_BUSINESS_HOURS_START = 6
_BUSINESS_HOURS_END = 22


def _logs_to_dataframe(logs: List[NormalizedLog]) -> pd.DataFrame:
    """
    Flattens NormalizedLog objects into a pandas DataFrame for vectorized
    aggregation. Only the columns feature extraction actually needs are
    pulled out, to keep this fast on large batches.
    """
    rows = []
    for log in logs:
        if not log.source_ip:
            continue
        rows.append(
            {
                "source_ip": log.source_ip,
                "event_type": log.event_type,
                "dest_port": log.dest_port,
                "dest_ip": log.dest_ip,
                "response_size": log.parsed_fields.get("response_size_bytes"),
                "hour": log.timestamp.hour,
            }
        )
    return pd.DataFrame(rows)


def extract_entity_features(logs: List[NormalizedLog]) -> Dict[str, np.ndarray]:
    """
    Groups `logs` by source_ip and computes the FEATURE_NAMES vector for
    each. Entities with zero logs (impossible by construction) are never
    returned; the caller decides how to handle entities with very few
    events (e.g. Isolation Forest with n<2 samples for that entity is
    still fittable, but low-volume entities are inherently less reliable
    signal — that's a modeling/thresholding concern, not a feature
    extraction concern, so it's not filtered out here).

    Returns:
        Dict mapping source_ip -> np.ndarray of shape (len(FEATURE_NAMES),)
    """
    df = _logs_to_dataframe(logs)
    if df.empty:
        return {}

    features: Dict[str, np.ndarray] = {}

    for source_ip, group in df.groupby("source_ip"):
        failed_login_count = int((group["event_type"] == "failed_login").sum())
        successful_login_count = int((group["event_type"] == "successful_login").sum())
        total_event_count = len(group)
        distinct_event_types = group["event_type"].nunique()
        distinct_dest_ports = group["dest_port"].dropna().nunique()
        distinct_dest_ips = group["dest_ip"].dropna().nunique()

        response_sizes = group["response_size"].dropna()
        avg_response_size = float(response_sizes.mean()) if not response_sizes.empty else 0.0

        off_hours_mask = ~group["hour"].between(_BUSINESS_HOURS_START, _BUSINESS_HOURS_END - 1)
        off_hours_ratio = float(off_hours_mask.mean()) if total_event_count > 0 else 0.0

        features[source_ip] = np.array(
            [
                failed_login_count,
                successful_login_count,
                total_event_count,
                distinct_event_types,
                distinct_dest_ports,
                distinct_dest_ips,
                avg_response_size,
                off_hours_ratio,
            ],
            dtype=np.float64,
        )

    return features


def extract_feature_matrix(logs: List[NormalizedLog]) -> Tuple[np.ndarray, List[str]]:
    """
    Convenience wrapper for training: returns (X, entity_order) where X
    is shape (n_entities, n_features) and entity_order[i] is the
    source_ip corresponding to row i of X — needed because dict
    iteration order, while stable in modern Python, shouldn't be relied
    on implicitly by callers that need to map rows back to entities.
    """
    entity_features = extract_entity_features(logs)
    entity_order = sorted(entity_features.keys())
    if not entity_order:
        return np.empty((0, len(FEATURE_NAMES))), []

    X = np.vstack([entity_features[ip] for ip in entity_order])
    return X, entity_order
