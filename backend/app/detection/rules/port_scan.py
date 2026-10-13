"""
app/detection/rules/port_scan.py

Purpose:
    Detects port scanning: a single source IP triggering firewall DENY
    events against many distinct destination ports on the same
    destination host within a short window — the classic
    connect()/SYN-scan signature.

MITRE ATT&CK:
    T1046 - Network Service Discovery
"""
from collections import defaultdict
from typing import Dict, List, Tuple

from app.detection.rules.base_rule import BaseRule, RuleConfig, window_seconds
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType


class PortScanRule(BaseRule):
    rule_name = "port_scan"
    description = "Single source IP denied across many distinct destination ports on one host in a short window."
    mitre_technique = "T1046 - Network Service Discovery"

    DEFAULT_DISTINCT_PORT_THRESHOLD = 5
    DEFAULT_WINDOW_SECONDS = 60

    def __init__(self, config: RuleConfig = None, enabled: bool = True):
        super().__init__(config, enabled)
        self.port_threshold = self.config.get("distinct_port_threshold", self.DEFAULT_DISTINCT_PORT_THRESHOLD)
        self.window = self.config.get("window_seconds", self.DEFAULT_WINDOW_SECONDS)

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        candidates = [
            log
            for log in logs
            if log.source_type == SourceType.FIREWALL.value
            and log.event_type == "connection_denied"
            and log.source_ip
            and log.dest_ip
            and log.dest_port is not None
        ]
        if not candidates:
            return []

        # Group by (source_ip, dest_ip) — scanning one host at a time is
        # the common case; a source hitting multiple hosts is caught as
        # multiple separate detections, one per targeted host.
        grouped: Dict[Tuple[str, str], List[NormalizedLog]] = defaultdict(list)
        for log in candidates:
            grouped[(log.source_ip, log.dest_ip)].append(log)

        detections: List[DetectionEvent] = []
        for (source_ip, dest_ip), group_logs in grouped.items():
            distinct_ports = sorted({log.dest_port for log in group_logs})
            if len(distinct_ports) < self.port_threshold:
                continue

            span = window_seconds(group_logs)
            if span > self.window and len(distinct_ports) < self.port_threshold * 2:
                continue

            confidence = min(1.0, 0.5 + 0.05 * (len(distinct_ports) - self.port_threshold))
            severity = Severity.HIGH if len(distinct_ports) >= self.port_threshold * 2 else Severity.MEDIUM

            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.RULE,
                    rule_name=self.rule_name,
                    confidence=round(confidence, 2),
                    severity=severity,
                    mitre_technique=self.mitre_technique,
                    entity=Entity(type=EntityType.IP, value=source_ip),
                    evidence_log_ids=[log.log_id for log in group_logs],
                    explanation=(
                        f"{source_ip} probed {len(distinct_ports)} distinct ports on {dest_ip} "
                        f"({distinct_ports[:10]}{'...' if len(distinct_ports) > 10 else ''}) "
                        f"within {span:.0f}s — consistent with a port scan."
                    ),
                )
            )

        return detections
