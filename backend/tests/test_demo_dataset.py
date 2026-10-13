"""
tests/test_demo_dataset.py

Purpose:
    Guards the demo. The four files in sample_logs/ are what
    scripts/seed_demo_data.py uploads; together they must exercise every
    detection rule and give the ML engine enough distinct entities to
    train on. If a parser, rule or fixture changes in a way that breaks
    the walkthrough, this fails.
"""
from pathlib import Path

import pytest

from app.detection.engine import RuleEngine
from app.detection.ml.model_registry import ModelRegistry
from app.detection.ml.prediction_service import PredictionService
from app.detection.ml.training_service import MIN_TRAINING_SAMPLES, TrainingService
from app.ingestion.normalizer import normalize
from app.ingestion.pipeline import PARSER_REGISTRY
from app.models.log_schema import SourceType
from scripts.seed_demo_data import SAMPLE_MAP

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample_logs"


@pytest.fixture(scope="module")
def demo_logs():
    logs = []
    for filename, source_type, host in SAMPLE_MAP:
        content = (SAMPLE_DIR / filename).read_text(encoding="utf-8")
        events = PARSER_REGISTRY[SourceType(source_type)].parse(content, source_host=host)
        assert events, f"{filename} produced no events"
        logs.extend(normalize(event, source_type=SourceType(source_type), source_host=host) for event in events)
    return logs


def test_every_rule_fires_on_the_demo_logs(demo_logs):
    engine = RuleEngine()
    fired = {detection.rule_name for detection in engine.run(demo_logs)}
    assert fired == {rule.rule_name for rule in engine.list_rules()}


def test_demo_logs_are_enough_to_train_and_flag_the_port_scanner(demo_logs, tmp_path):
    assert len({log.source_ip for log in demo_logs if log.source_ip}) >= MIN_TRAINING_SAMPLES

    registry = ModelRegistry(base_dir=str(tmp_path))
    TrainingService(registry=registry).train(demo_logs)
    flagged = {d.entity.value for d in PredictionService(registry=registry).predict(demo_logs)}

    assert "198.51.100.77" in flagged
