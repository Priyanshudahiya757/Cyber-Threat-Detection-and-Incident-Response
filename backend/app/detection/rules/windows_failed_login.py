"""
app/detection/rules/windows_failed_login.py

Purpose:
    Detects repeated Windows failed logon events (Event ID 4625) from the
    same source IP within a short window — the Windows-domain equivalent
    of ssh_brute_force.py, kept as a separate rule (rather than a single
    generic "brute force" rule parameterized by OS) because Windows and
    Linux failed-login semantics diverge enough in practice (logon types,
    domain vs local accounts, lockout policy interaction) to warrant
    independent tuning and independent MITRE sub-technique mapping later.

MITRE ATT&CK:
    T1110.001 - Brute Force: Password Guessing
"""
from typing import List

from app.detection.rules.base_rule import BaseRule, RuleConfig, group_by_source_ip, window_seconds
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType


class WindowsFailedLoginRule(BaseRule):
    rule_name = "windows_failed_login"
    description = "Multiple Windows failed logon events (4625) from the same source IP within a short window."
    mitre_technique = "T1110.001 - Brute Force: Password Guessing"

    DEFAULT_THRESHOLD = 3
    DEFAULT_WINDOW_SECONDS = 120

    def __init__(self, config: RuleConfig = None, enabled: bool = True):
        super().__init__(config, enabled)
        self.threshold = self.config.get("threshold", self.DEFAULT_THRESHOLD)
        self.window = self.config.get("window_seconds", self.DEFAULT_WINDOW_SECONDS)

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        candidates = [
            log
            for log in logs
            if log.source_type == SourceType.WINDOWS.value and log.event_type == "failed_login"
        ]
        if not candidates:
            return []

        detections: List[DetectionEvent] = []
        for source_ip, ip_logs in group_by_source_ip(candidates).items():
            if len(ip_logs) < self.threshold:
                continue

            targeted_users = sorted({log.user for log in ip_logs if log.user})
            confidence = min(1.0, 0.5 + 0.1 * (len(ip_logs) - self.threshold))
            severity = Severity.CRITICAL if len(ip_logs) >= self.threshold * 3 else Severity.HIGH

            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.RULE,
                    rule_name=self.rule_name,
                    confidence=round(confidence, 2),
                    severity=severity,
                    mitre_technique=self.mitre_technique,
                    entity=Entity(type=EntityType.IP, value=source_ip),
                    evidence_log_ids=[log.log_id for log in ip_logs],
                    explanation=(
                        f"{len(ip_logs)} Windows failed logon events from {source_ip} "
                        f"targeting account(s) {', '.join(targeted_users) or 'unknown'} "
                        f"within {window_seconds(ip_logs):.0f}s."
                    ),
                )
            )

        return detections
