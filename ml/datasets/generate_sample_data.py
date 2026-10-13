"""
ml/datasets/generate_sample_data.py

Purpose:
    Generates a synthetic, LABELED feature dataset for evaluating the
    Isolation Forest model (see backend/app/detection/ml/training_service.py
    ::evaluate_on_labeled_dataset). Isolation Forest itself is trained
    unsupervised on real, unlabeled production logs — this labeled
    dataset exists purely to sanity-check the model's notion of
    "anomalous" against known ground truth, which real ingested logs
    can't provide without manual analyst labeling.

    Columns match app.detection.ml.feature_extraction.FEATURE_NAMES
    exactly, plus a `label` column (1 = anomaly, 0 = normal).

Usage:
    python ml/datasets/generate_sample_data.py
    (writes ml/datasets/sample_training_data.csv)
"""
import os

import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "failed_login_count",
    "successful_login_count",
    "total_event_count",
    "distinct_event_types",
    "distinct_dest_ports",
    "distinct_dest_ips",
    "avg_response_size_bytes",
    "off_hours_event_ratio",
]

RANDOM_SEED = 42
N_NORMAL = 180
N_ANOMALOUS = 20  # ~10% contamination, a realistic minority-class ratio


def _generate_normal_entities(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    Normal entities: a handful of failed logins at most (typos happen),
    modest total activity, few distinct ports/IPs touched, business-hours
    skew, and typical response sizes.
    """
    return pd.DataFrame(
        {
            "failed_login_count": rng.poisson(0.5, n),
            "successful_login_count": rng.poisson(1.5, n),
            "total_event_count": rng.poisson(15, n) + 1,
            "distinct_event_types": rng.integers(1, 4, n),
            "distinct_dest_ports": rng.integers(1, 3, n),
            "distinct_dest_ips": rng.integers(1, 3, n),
            "avg_response_size_bytes": rng.normal(4000, 800, n).clip(min=0),
            "off_hours_event_ratio": rng.beta(1, 6, n),  # skewed toward 0 (mostly business hours)
            "label": 0,
        }
    )


def _generate_brute_force_entities(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Anomalous: brute-force pattern — high failed logins, low success, minimal diversity."""
    return pd.DataFrame(
        {
            "failed_login_count": rng.integers(15, 60, n),
            "successful_login_count": rng.integers(0, 2, n),
            "total_event_count": rng.integers(15, 60, n),
            "distinct_event_types": np.ones(n, dtype=int),
            "distinct_dest_ports": np.ones(n, dtype=int),
            "distinct_dest_ips": np.ones(n, dtype=int),
            "avg_response_size_bytes": rng.normal(500, 100, n).clip(min=0),
            "off_hours_event_ratio": rng.beta(4, 2, n),  # skewed toward off-hours
            "label": 1,
        }
    )


def _generate_port_scan_entities(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Anomalous: port-scan pattern — many distinct ports/IPs, low per-port volume."""
    return pd.DataFrame(
        {
            "failed_login_count": np.zeros(n, dtype=int),
            "successful_login_count": np.zeros(n, dtype=int),
            "total_event_count": rng.integers(20, 100, n),
            "distinct_event_types": rng.integers(1, 3, n),
            "distinct_dest_ports": rng.integers(15, 80, n),
            "distinct_dest_ips": rng.integers(1, 5, n),
            "avg_response_size_bytes": np.zeros(n),
            "off_hours_event_ratio": rng.beta(3, 3, n),
            "label": 1,
        }
    )


def generate_dataset() -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_SEED)

    normal = _generate_normal_entities(N_NORMAL, rng)
    brute_force = _generate_brute_force_entities(N_ANOMALOUS // 2, rng)
    port_scan = _generate_port_scan_entities(N_ANOMALOUS - N_ANOMALOUS // 2, rng)

    df = pd.concat([normal, brute_force, port_scan], ignore_index=True)
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)  # shuffle
    return df[FEATURE_NAMES + ["label"]]


if __name__ == "__main__":
    dataset = generate_dataset()
    output_path = os.path.join(os.path.dirname(__file__), "sample_training_data.csv")
    dataset.to_csv(output_path, index=False)
    print(f"Wrote {len(dataset)} rows ({dataset['label'].sum()} labeled anomalous) to {output_path}")
