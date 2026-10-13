"""
app/detection/rules/base_rule.py

Purpose:
    Defines the contract every detection rule must implement (Strategy
    pattern, mirroring ingestion/parsers/base_parser.py). This is what
    satisfies the "rule engine should be modular / configurable"
    requirement: RuleEngine (engine.py) holds a list of BaseRule
    instances and knows nothing about their internals — adding a new
    rule means writing one new class and registering it, with zero
    changes to the engine or to any existing rule (Open/Closed).

    Each concrete rule declares its own MITRE ATT&CK mapping, default
    severity, and confidence — these are rule metadata, not engine
    concerns, which is why they live on the rule class rather than being
    threaded through evaluate()'s return values by the caller.

Connects to:
    - Implemented by every module in detection/rules/
    - Instantiated and run by detection/engine.py::RuleEngine
    - Produces app.models.detection_schema.DetectionEvent instances
"""
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional
from urllib.parse import unquote
import re

from app.models.detection_schema import DetectionEvent
from app.models.log_schema import NormalizedLog


class RuleConfig:
    """
    Tunable parameters for threshold-based rules (window size, trigger
    count, etc). Kept as a plain, mutable, independently-constructible
    object — deliberately NOT a Pydantic model tied to MongoDB — so each
    rule can be unit-tested with arbitrary thresholds without touching a
    database. Phase 5 (admin rule configuration API) will bridge this to
    persisted config in the `detection_rules` Mongo collection; that's a
    read/write adapter around this object, not a redesign of it.
    """

    def __init__(self, **kwargs):
        self._values: Dict[str, object] = kwargs

    def get(self, key: str, default=None):
        return self._values.get(key, default)

    def __repr__(self) -> str:
        return f"RuleConfig({self._values!r})"


class BaseRule(ABC):
    """
    Abstract detection rule contract. Subclasses are stateless aside from
    their RuleConfig (no mutable state between evaluate() calls), so a
    single instance is safe to reuse across every detection run for the
    lifetime of the process — matching the same reuse pattern as parsers.
    """

    #: Unique machine-readable name, used as the DetectionEvent.rule_name
    #: and as the config lookup key in RuleEngine.
    rule_name: str

    #: Human-readable description, surfaced in the incident/alert UI.
    description: str

    #: MITRE ATT&CK technique this rule detects, e.g. "T1110 - Brute Force".
    mitre_technique: str

    def __init__(self, config: RuleConfig = None, enabled: bool = True):
        self.config = config or RuleConfig()
        self.enabled = enabled

    @abstractmethod
    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        """
        Evaluate a batch of NormalizedLog and return zero or more
        DetectionEvent. Rules operate on whatever window of logs the
        caller provides (see detection/engine.py for how that window is
        assembled — typically the just-ingested batch, or a query result
        for periodic wider-window scans).

        Implementations must not raise for "no match" — return an empty
        list. Only raise for genuine rule-logic errors, which
        RuleEngine.run() catches and logs without aborting other rules.
        """
        raise NotImplementedError


def group_by_source_ip(logs: List[NormalizedLog]) -> Dict[str, List[NormalizedLog]]:
    """Shared grouping utility: bucket logs by source_ip, skipping logs without one."""
    grouped: Dict[str, List[NormalizedLog]] = defaultdict(list)
    for log in logs:
        if log.source_ip:
            grouped[log.source_ip].append(log)
    return grouped


def group_by_user(logs: List[NormalizedLog]) -> Dict[str, List[NormalizedLog]]:
    """Shared grouping utility: bucket logs by user, skipping logs without one."""
    grouped: Dict[str, List[NormalizedLog]] = defaultdict(list)
    for log in logs:
        if log.user:
            grouped[log.user].append(log)
    return grouped


def window_seconds(logs: List[NormalizedLog]) -> float:
    """Time span (in seconds) covered by a group of logs, used for rate-based thresholds."""
    if len(logs) < 2:
        return 0.0
    timestamps = sorted(log.timestamp for log in logs)
    return (timestamps[-1] - timestamps[0]).total_seconds()


def find_matching_pattern(patterns: List[re.Pattern], text: str) -> Optional[re.Match]:
    """
    Shared helper for web-attack rules (SQL injection, XSS, directory
    traversal): URL-decodes the input once (attackers commonly percent-
    encode payloads to slip past naive string matching) and returns the
    first regex match against the compiled `patterns` list, or None.
    """
    decoded = unquote(text)
    for pattern in patterns:
        match = pattern.search(decoded) or pattern.search(text)
        if match:
            return match
    return None
