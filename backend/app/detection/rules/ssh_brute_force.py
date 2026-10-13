"""
app/detection/rules/ssh_brute_force.py

Purpose:
    Detects SSH brute-force attempts: multiple failed_login events from
    Linux hosts, from the same source IP, within a short time window.

MITRE ATT&CK:
    T1110 - Brute Force (https://attack.mitre.org/techniques/T1110/)
"""
from typing import List

from app.detection.rules.base_rule import BaseRule, IntSetting, group_by_source_ip, window_seconds
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType


class SSHBruteForceRule(BaseRule):
    rule_name = "ssh_brute_force"
    description = "Multiple failed SSH login attempts from the same source IP within a short time window."
    mitre_technique = "T1110 - Brute Force"

    settings = {
        "threshold": IntSetting(default=4, minimum=2, maximum=1000),
        "window_seconds": IntSetting(default=120, minimum=10, maximum=86_400),
    }

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        candidates = [
            log
            for log in logs
            if log.source_type == SourceType.LINUX.value and log.event_type == "failed_login"
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
            confidence = min(1.0, 0.5 + 0.08 * (len(ip_logs) - threshold))
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
                        f"{len(ip_logs)} failed SSH login attempts from {source_ip} "
                        f"targeting user(s) {', '.join(targeted_users) or 'unknown'} "
                        f"within {window_seconds(ip_logs):.0f}s."
                    ),
                )
            )

        return detections
