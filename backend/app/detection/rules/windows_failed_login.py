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

from app.detection.rules.base_rule import BaseRule, IntSetting, group_by_source_ip, window_seconds
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType


class WindowsFailedLoginRule(BaseRule):
    rule_name = "windows_failed_login"
    description = "Multiple Windows failed logon events (4625) from the same source IP within a short window."
    mitre_technique = "T1110.001 - Brute Force: Password Guessing"

    settings = {
        "threshold": IntSetting(default=3, minimum=2, maximum=1000),
        "window_seconds": IntSetting(default=120, minimum=10, maximum=86_400),
    }

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        candidates = [
            log
            for log in logs
            if log.source_type == SourceType.WINDOWS.value and log.event_type == "failed_login"
        ]
        if not candidates:
            return []

        threshold, window = self.config["threshold"], self.config["window_seconds"]

        detections: List[DetectionEvent] = []
        for source_ip, ip_logs in group_by_source_ip(candidates).items():
            if len(ip_logs) < threshold:
                continue
            if window_seconds(ip_logs) > window and len(ip_logs) < threshold * 2:
                # Spread out too thin to be a burst attack, unless the volume
                # is high enough to be suspicious regardless of pacing.
                continue

            targeted_users = sorted({log.user for log in ip_logs if log.user})
            confidence = min(1.0, 0.5 + 0.1 * (len(ip_logs) - threshold))
            severity = Severity.CRITICAL if len(ip_logs) >= threshold * 3 else Severity.HIGH

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
