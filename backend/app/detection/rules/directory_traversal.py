"""
app/detection/rules/directory_traversal.py

Purpose:
    Detects directory/path traversal attempts in web request paths —
    sequences attempting to escape the web root via "../" (and its
    encoded variants) to reach sensitive files like /etc/passwd or
    Windows SAM hives.

MITRE ATT&CK:
    T1083 - File and Directory Discovery (reconnaissance via traversal)
"""
import re
from typing import List

from app.detection.rules.base_rule import BaseRule, find_matching_pattern
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType

_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./){2,}"),  # multiple ../ segments
    re.compile(r"\.\.%2f", re.IGNORECASE),  # encoded ../
    re.compile(r"%2e%2e[/\\]", re.IGNORECASE),
    re.compile(r"(etc/passwd|boot\.ini|win\.ini|system32)", re.IGNORECASE),
]


class DirectoryTraversalRule(BaseRule):
    rule_name = "directory_traversal"
    description = "Web request path contains directory traversal sequences targeting sensitive system paths."
    mitre_technique = "T1083 - File and Directory Discovery"

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        detections: List[DetectionEvent] = []

        for log in logs:
            if log.source_type != SourceType.WEB_SERVER.value:
                continue

            path = log.parsed_fields.get("path", "") or log.raw_log
            match = find_matching_pattern(_TRAVERSAL_PATTERNS, path)
            if not match:
                continue

            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.RULE,
                    rule_name=self.rule_name,
                    confidence=0.8,
                    severity=Severity.HIGH,
                    mitre_technique=self.mitre_technique,
                    entity=Entity(type=EntityType.IP, value=log.source_ip or "unknown"),
                    evidence_log_ids=[log.log_id],
                    explanation=f"Directory traversal sequence matched in request path: {path[:200]}",
                )
            )

        return detections
