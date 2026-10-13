"""
app/detection/engine.py

Purpose:
    Owns the registry of active detection rules and runs all enabled
    rules against a batch of NormalizedLog, collecting their
    DetectionEvent output. This is the single place that knows "which
    rules exist" — everything else (the ingestion pipeline's on_ingested
    hook, the manual /detections/run API endpoint, tests) goes through
    RuleEngine.run() rather than importing individual rule classes.

    A rule raising an exception is caught and logged per-rule so one
    broken rule can't take down detection for the rest of the batch —
    this mirrors the same isolation principle used in
    ingestion/pipeline.py for per-record parsing errors.

Connects to:
    - Instantiated once as `default_rule_engine` and registered with
      ingestion/pipeline.py::default_pipeline as the on_ingested callback
      (wired in app/main.py)
    - detection/alerting.py consumes RuleEngine.run() output to generate
      alerts for high-severity detections
    - db/mongo.py persists DetectionEvent results
"""
from typing import Dict, List, Optional

from app.core.logging_config import get_logger
from app.detection.rules.base_rule import BaseRule
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
    """
    Runs a configurable set of BaseRule instances against a log batch.
    Rules can be enabled/disabled by name at runtime (see set_rule_enabled),
    which is what Phase 5's admin rule-configuration API will drive.
    """

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


#: Process-wide singleton, registered as the ingestion pipeline's
#: on_ingested callback in app/main.py at startup.
default_rule_engine = RuleEngine()


async def handle_ingested_logs(logs: List[NormalizedLog]) -> None:
    """
    Post-ingestion hook: run BOTH detection engines (rule-based and ML)
    against freshly ingested logs, persist any resulting detections, and
    generate alerts for high-severity ones. Registered with
    ingestion.pipeline.default_pipeline.register_on_ingested_callback()
    in app/main.py.

    The two engines are independent and additive — a rule-engine failure
    doesn't block ML scoring or vice versa (each is wrapped separately),
    matching the same fault-isolation principle used within RuleEngine.run()
    for individual rules.
    """
    # Imported locally to avoid a module-level circular import concern
    # and to keep the dependency explicit at the point of use (mirrors
    # alerting.py's own import style).
    from app.db.mongo import save_detections
    from app.detection.alerting import generate_alerts
    from app.detection.ml.prediction_service import default_prediction_service

    rule_detections = default_rule_engine.run(logs)

    try:
        ml_detections = default_prediction_service.predict(logs)
    except Exception as exc:
        logger.error(f"handle_ingested_logs: ML prediction failed, continuing with rule detections only: {exc}")
        ml_detections = []

    all_detections = rule_detections + ml_detections
    if not all_detections:
        return

    await save_detections(all_detections)
    await generate_alerts(all_detections)

    try:
        from app.incidents.correlator import correlate_detections

        await correlate_detections(all_detections)
    except Exception as exc:
        logger.error(f"handle_ingested_logs: incident correlation failed: {exc}")
