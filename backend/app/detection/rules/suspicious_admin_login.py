"""
app/detection/rules/suspicious_admin_login.py

Purpose:
    Flags successful logins to privileged/admin-named accounts
    (root, admin, administrator, and configurable equivalents) that
    occur outside normal business hours. Privileged-account logins are
    high-value targets, and an off-hours login is a classic weak signal
    worth surfacing even without other corroborating evidence — this is
    intentionally a lower-confidence rule than the others, precisely
    because "an admin logged in late" is common enough on its own to
    need corroboration from an analyst, not an auto-close.

MITRE ATT&CK:
    T1078 - Valid Accounts
"""
from typing import List

from app.detection.rules.base_rule import BaseRule, RuleConfig
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType

_DEFAULT_PRIVILEGED_ACCOUNTS = {"root", "admin", "administrator"}
_DEFAULT_BUSINESS_HOURS_START = 6   # 06:00 UTC
_DEFAULT_BUSINESS_HOURS_END = 22    # 22:00 UTC

_SUCCESSFUL_LOGIN_EVENT_TYPES = {"successful_login"}


class SuspiciousAdminLoginRule(BaseRule):
    rule_name = "suspicious_admin_login"
    description = "Successful login to a privileged account outside configured business hours."
    mitre_technique = "T1078 - Valid Accounts"

    def __init__(self, config: RuleConfig = None, enabled: bool = True):
        super().__init__(config, enabled)
        self.privileged_accounts = {
            u.lower() for u in self.config.get("privileged_accounts", _DEFAULT_PRIVILEGED_ACCOUNTS)
        }
        self.business_start = self.config.get("business_hours_start", _DEFAULT_BUSINESS_HOURS_START)
        self.business_end = self.config.get("business_hours_end", _DEFAULT_BUSINESS_HOURS_END)

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        detections: List[DetectionEvent] = []

        for log in logs:
            if (
                log.source_type not in {SourceType.LINUX.value, SourceType.WINDOWS.value}
                or log.event_type not in _SUCCESSFUL_LOGIN_EVENT_TYPES
                or not log.user
                or log.user.lower() not in self.privileged_accounts
            ):
                continue

            hour = log.timestamp.hour
            is_off_hours = not (self.business_start <= hour < self.business_end)
            if not is_off_hours:
                continue

            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.RULE,
                    rule_name=self.rule_name,
                    confidence=0.4,
                    severity=Severity.MEDIUM,
                    mitre_technique=self.mitre_technique,
                    entity=Entity(type=EntityType.USER, value=log.user),
                    evidence_log_ids=[log.log_id],
                    explanation=(
                        f"Privileged account '{log.user}' logged in at {log.timestamp.strftime('%H:%M UTC')}, "
                        f"outside configured business hours ({self.business_start}:00-{self.business_end}:00 UTC). "
                        "Low-confidence signal — corroborate with source IP reputation and analyst context."
                    ),
                )
            )

        return detections
