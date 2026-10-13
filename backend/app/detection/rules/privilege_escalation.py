"""
app/detection/rules/privilege_escalation.py

Purpose:
    Detects privilege escalation activity across both Linux and Windows
    sources:
      - Linux: a `sudo` command escalating to the root user
        (parsed_fields.target_user == "root")
      - Windows: new-account-creation (4720) or security-group-membership
        changes (4728) events, which commonly follow a successful
        escalation as the attacker persists access

    Kept as one rule (rather than split per-OS like the brute-force rules)
    because the detection logic here is genuinely a single concept —
    "an identity gained elevated rights" — expressed through different
    log signatures per OS, not two different *kinds* of detection logic
    the way brute-force pacing/thresholds differ meaningfully by platform.

MITRE ATT&CK:
    T1548 - Abuse Elevation Control Mechanism
"""
from typing import List

from app.detection.rules.base_rule import BaseRule
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType

_WINDOWS_ESCALATION_EVENT_TYPES = {"account_created", "group_membership_added"}


class PrivilegeEscalationRule(BaseRule):
    rule_name = "privilege_escalation"
    description = "Root-level sudo command execution or Windows privileged group/account changes."
    mitre_technique = "T1548 - Abuse Elevation Control Mechanism"

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        detections: List[DetectionEvent] = []

        for log in logs:
            if log.source_type == SourceType.LINUX.value and log.event_type == "privilege_command":
                detections.extend(self._evaluate_linux_sudo(log))
            elif (
                log.source_type == SourceType.WINDOWS.value
                and log.event_type in _WINDOWS_ESCALATION_EVENT_TYPES
            ):
                detections.extend(self._evaluate_windows_event(log))

        return detections

    def _evaluate_linux_sudo(self, log: NormalizedLog) -> List[DetectionEvent]:
        target_user = log.parsed_fields.get("target_user")
        if target_user != "root":
            return []

        command = log.parsed_fields.get("command", "unknown command")
        return [
            DetectionEvent(
                engine=DetectionEngine.RULE,
                rule_name=self.rule_name,
                confidence=0.55,
                severity=Severity.MEDIUM,
                mitre_technique=self.mitre_technique,
                entity=Entity(type=EntityType.USER, value=log.user or "unknown"),
                evidence_log_ids=[log.log_id],
                explanation=(
                    f"User '{log.user}' executed a command as root via sudo: '{command}'. "
                    "Root-level sudo activity is expected admin behavior in many environments — "
                    "review against known maintenance windows before escalating."
                ),
            )
        ]

    def _evaluate_windows_event(self, log: NormalizedLog) -> List[DetectionEvent]:
        severity = Severity.HIGH if log.event_type == "group_membership_added" else Severity.MEDIUM
        action = (
            "was added to a privileged security group"
            if log.event_type == "group_membership_added"
            else "a new account was created"
        )

        return [
            DetectionEvent(
                engine=DetectionEngine.RULE,
                rule_name=self.rule_name,
                confidence=0.6,
                severity=severity,
                mitre_technique=self.mitre_technique,
                entity=Entity(type=EntityType.USER, value=log.user or "unknown"),
                evidence_log_ids=[log.log_id],
                explanation=f"Windows account '{log.user}' {action} (Event ID {log.parsed_fields.get('event_id')}).",
            )
        ]
