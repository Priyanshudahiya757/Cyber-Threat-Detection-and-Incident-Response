"""
app/detection/rules/sql_injection.py

Purpose:
    Detects SQL injection attempts in web server request paths/query
    strings via signature matching against common SQLi payload patterns
    (boolean-based tautologies, UNION SELECT, comment terminators,
    stacked queries). Signature-based detection has known limitations
    (evadable by novel obfuscation) — documented here rather than
    oversold, since anomaly-based detection (Phase 4) is what catches
    what signatures miss.

MITRE ATT&CK:
    T1190 - Exploit Public-Facing Application
"""
import re
from typing import List

from app.detection.rules.base_rule import BaseRule, RuleConfig, find_matching_pattern
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType

_SQLI_PATTERNS = [
    re.compile(r"(\bOR\b|\bAND\b)\s+'?\d+'?\s*=\s*'?\d+'?", re.IGNORECASE),  # ' OR 1=1
    re.compile(r"UNION(\s+ALL)?\s+SELECT", re.IGNORECASE),
    re.compile(r"(--|#|/\*).*$", re.MULTILINE),  # SQL comment terminators
    re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT)\s+", re.IGNORECASE),  # stacked queries
    re.compile(r"\bSLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),  # time-based blind SQLi
    re.compile(r"information_schema", re.IGNORECASE),
]


class SQLInjectionRule(BaseRule):
    rule_name = "sql_injection"
    description = "Web request path/query string matches known SQL injection payload signatures."
    mitre_technique = "T1190 - Exploit Public-Facing Application"

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        detections: List[DetectionEvent] = []

        for log in logs:
            if log.source_type != SourceType.WEB_SERVER.value:
                continue

            path = log.parsed_fields.get("path", "") or log.raw_log
            match = find_matching_pattern(_SQLI_PATTERNS, path)
            if not match:
                continue

            severity = Severity.CRITICAL if "UNION" in match.group(0).upper() else Severity.HIGH

            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.RULE,
                    rule_name=self.rule_name,
                    confidence=0.75,
                    severity=severity,
                    mitre_technique=self.mitre_technique,
                    entity=Entity(type=EntityType.IP, value=log.source_ip or "unknown"),
                    evidence_log_ids=[log.log_id],
                    explanation=f"SQL injection signature matched in request path: {path[:200]}",
                )
            )

        return detections
