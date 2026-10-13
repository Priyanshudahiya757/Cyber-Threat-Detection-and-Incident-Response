"""
app/detection/rules/xss.py

Purpose:
    Detects reflected/stored Cross-Site Scripting attempts in web request
    paths/query strings via signature matching against common XSS payload
    patterns (script tags, event-handler injection, javascript: URIs).

MITRE ATT&CK:
    T1059.007 - Command and Scripting Interpreter: JavaScript
"""
import re
from typing import List

from app.detection.rules.base_rule import BaseRule, find_matching_pattern
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType

_XSS_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouseover|focus)\s*=", re.IGNORECASE),  # event handler injection
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<img[^>]+src\s*=", re.IGNORECASE),
    re.compile(r"document\.(cookie|location)", re.IGNORECASE),
    re.compile(r"<iframe[\s>]", re.IGNORECASE),
]


class XSSRule(BaseRule):
    rule_name = "xss"
    description = "Web request path/query string matches known Cross-Site Scripting payload signatures."
    mitre_technique = "T1059.007 - Command and Scripting Interpreter: JavaScript"

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        detections: List[DetectionEvent] = []

        for log in logs:
            if log.source_type != SourceType.WEB_SERVER.value:
                continue

            path = log.parsed_fields.get("path", "") or log.raw_log
            match = find_matching_pattern(_XSS_PATTERNS, path)
            if not match:
                continue

            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.RULE,
                    rule_name=self.rule_name,
                    confidence=0.7,
                    severity=Severity.MEDIUM,
                    mitre_technique=self.mitre_technique,
                    entity=Entity(type=EntityType.IP, value=log.source_ip or "unknown"),
                    evidence_log_ids=[log.log_id],
                    explanation=f"XSS payload signature matched in request path: {path[:200]}",
                )
            )

        return detections
