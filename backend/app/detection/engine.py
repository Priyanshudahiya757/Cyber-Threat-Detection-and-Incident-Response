"""
app/detection/engine.py

Purpose:
    Owns the registry of detection rules and runs all enabled rules
    against a batch of NormalizedLog, collecting their DetectionEvent
    output. This is the single place that knows "which rules exist" —
    everything else goes through RuleEngine rather than importing
    individual rule classes.

    A rule raising an exception is caught and logged per-rule so one
    broken rule can't take down detection for the rest of the batch —
    the same isolation principle ingestion/pipeline.py uses for
    per-record parsing errors.

Connects to:
    - detection/service.py runs `default_rule_engine` over detection windows
    - api/v1/rules.py lists rules and changes their enabled state / settings
    - main.py restores persisted rule state at startup
"""
from typing import Any, Dict, List, Optional

from app.core.logging_config import get_logger
from app.detection.rules.base_rule import BaseRule, RuleConfigError
from app.detection.rules.directory_traversal import DirectoryTraversalRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.privilege_escalation import PrivilegeEscalationRule
from app.detection.rules.sql_injection import SQLInjectionRule
from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.detection.rules.suspicious_admin_login import SuspiciousAdminLoginRule
from app.detection.rules.windows_failed_login import WindowsFailedLoginRule
from app.detection.rules.xss import XSSRule
from app.models.detection_schema import DetectionEvent
from app.models.log_schema import NormalizedLog

logger = get_logger(__name__)


def _default_rules() -> List[BaseRule]:
    """
    Factory for the default rule set. A factory (rather than a module-
    level constant list) so tests can build a fresh, isolated set of rule
    instances without sharing state with the process-wide default engine.
    """
    return [
        SSHBruteForceRule(),
        WindowsFailedLoginRule(),
        PortScanRule(),
        SQLInjectionRule(),
        XSSRule(),
        DirectoryTraversalRule(),
        PrivilegeEscalationRule(),
        SuspiciousAdminLoginRule(),
    ]


class RuleEngine:
    """Runs a configurable set of BaseRule instances against a log batch."""

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self._rules: Dict[str, BaseRule] = {rule.rule_name: rule for rule in (rules or _default_rules())}

    def run(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        """Run all enabled rules against `logs` and return the combined DetectionEvent list."""
        if not logs:
            return []

        all_detections: List[DetectionEvent] = []
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            try:
                detections = rule.evaluate(logs)
            except Exception as exc:
                logger.error(f"RuleEngine: rule '{rule.rule_name}' raised an exception: {exc}")
                continue

            if detections:
                logger.info(f"RuleEngine: rule '{rule.rule_name}' produced {len(detections)} detection(s)")
                all_detections.extend(detections)

        return all_detections

    def get_rule(self, rule_name: str) -> Optional[BaseRule]:
        return self._rules.get(rule_name)

    def list_rules(self) -> List[BaseRule]:
        return list(self._rules.values())

    def set_rule_enabled(self, rule_name: str, enabled: bool) -> bool:
        """Returns True if the rule was found and updated, False if no such rule exists."""
        rule = self._rules.get(rule_name)
        if rule is None:
            return False
        rule.enabled = enabled
        return True

    def apply_persisted_state(self, saved: List[Dict[str, Any]]) -> None:
        """
        Restore enabled state and settings saved by the rules API. Entries
        for rules that no longer exist, or settings that are no longer
        valid, are skipped so stale stored config can never block startup.
        """
        for entry in saved:
            rule = self._rules.get(entry.get("rule_name", ""))
            if rule is None:
                continue
            rule.enabled = bool(entry.get("enabled", True))
            try:
                rule.update_config(entry.get("config") or {})
            except RuleConfigError as exc:
                logger.warning(f"RuleEngine: ignoring stored settings for '{rule.rule_name}': {exc}")


#: Process-wide singleton used by detection/service.py and api/v1/rules.py.
default_rule_engine = RuleEngine()
