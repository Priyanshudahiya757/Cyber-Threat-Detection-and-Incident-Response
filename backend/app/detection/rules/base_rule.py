"""
app/detection/rules/base_rule.py

Purpose:
    Defines the contract every detection rule must implement (Strategy
    pattern, mirroring ingestion/parsers/base_parser.py). RuleEngine
    (engine.py) holds a list of BaseRule instances and knows nothing
    about their internals — adding a new rule means writing one new class
    and registering it, with zero changes to the engine or to any
    existing rule (Open/Closed).

    Each rule declares its MITRE ATT&CK mapping and its tunable
    `settings` (thresholds, time windows). Settings are read on every
    evaluate() call, so an admin changing one through the rules API takes
    effect immediately, without a restart.

Connects to:
    - Implemented by every module in detection/rules/
    - Instantiated and run by detection/engine.py::RuleEngine
    - api/v1/rules.py reads and updates `config` through update_config()
    - Produces app.models.detection_schema.DetectionEvent instances
"""
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from app.models.detection_schema import DetectionEvent
from app.models.log_schema import NormalizedLog


class RuleConfigError(ValueError):
    """Raised when a rule is given a setting it doesn't have or a value outside its allowed range."""


@dataclass(frozen=True)
class IntSetting:
    default: int
    minimum: int = 1
    maximum: int = 100_000

    def validate(self, name: str, value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise RuleConfigError(f"'{name}' must be a whole number")
        if not self.minimum <= value <= self.maximum:
            raise RuleConfigError(f"'{name}' must be between {self.minimum} and {self.maximum}")
        return value


@dataclass(frozen=True)
class StringListSetting:
    default: Tuple[str, ...]

    def validate(self, name: str, value: Any) -> List[str]:
        if not isinstance(value, (list, tuple)) or not value:
            raise RuleConfigError(f"'{name}' must be a non-empty list of text values")
        if not all(isinstance(item, str) and item.strip() for item in value):
            raise RuleConfigError(f"'{name}' must contain only non-empty text values")
        return [item.strip() for item in value]


Setting = Union[IntSetting, StringListSetting]


class BaseRule(ABC):
    """
    Abstract detection rule contract. Subclasses hold no state between
    evaluate() calls other than `enabled` and `config`, so a single
    instance is safe to reuse for the lifetime of the process.
    """

    #: Unique machine-readable name, used as DetectionEvent.rule_name
    #: and as the lookup key in RuleEngine.
    rule_name: str

    #: Human-readable description, surfaced in the rules UI.
    description: str

    #: MITRE ATT&CK technique this rule detects, e.g. "T1110 - Brute Force".
    mitre_technique: str

    #: Tunable settings this rule exposes, keyed by setting name.
    settings: Dict[str, Setting] = {}

    def __init__(self, config: Optional[Dict[str, Any]] = None, enabled: bool = True):
        self.enabled = enabled
        self.config: Dict[str, Any] = {
            name: list(setting.default) if isinstance(setting, StringListSetting) else setting.default
            for name, setting in self.settings.items()
        }
        if config:
            self.update_config(config)

    def update_config(self, values: Dict[str, Any]) -> None:
        """Validate and apply setting overrides. Applies nothing if any value is invalid."""
        validated: Dict[str, Any] = {}
        for name, value in values.items():
            setting = self.settings.get(name)
            if setting is None:
                raise RuleConfigError(f"Rule '{self.rule_name}' has no setting '{name}'")
            validated[name] = setting.validate(name, value)
        self.config.update(validated)

    @abstractmethod
    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        """
        Evaluate a batch of NormalizedLog and return zero or more
        DetectionEvent. Rules operate on whatever window of logs the
        caller provides (see detection/service.py for how that window is
        assembled).

        Implementations must not raise for "no match" — return an empty
        list. Only raise for genuine rule-logic errors, which
        RuleEngine.run() catches and logs without aborting other rules.
        """
        raise NotImplementedError


def group_by_source_ip(logs: List[NormalizedLog]) -> Dict[str, List[NormalizedLog]]:
    """Bucket logs by source_ip, skipping logs without one."""
    grouped: Dict[str, List[NormalizedLog]] = defaultdict(list)
    for log in logs:
        if log.source_ip:
            grouped[log.source_ip].append(log)
    return grouped


def window_seconds(logs: List[NormalizedLog]) -> float:
    """Time span (in seconds) covered by a group of logs, used for rate-based thresholds."""
    if len(logs) < 2:
        return 0.0
    timestamps = [log.timestamp for log in logs]
    return (max(timestamps) - min(timestamps)).total_seconds()
