"""
app/detection/rules/web_signature.py

Purpose:
    Shared base for signature-matching web attack rules (SQL injection,
    XSS, directory traversal). Each subclass only supplies its compiled
    patterns and metadata; the matching, URL-decoding and grouping logic
    lives here once.

    Requests are grouped by source IP: an attacker firing fifty payloads
    produces one detection listing all fifty requests as evidence, not
    fifty separate detections.

    Signature-based detection has a known limitation — novel obfuscation
    evades it — which is what the ML anomaly engine complements.
"""
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

from app.detection.rules.base_rule import BaseRule
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import NormalizedLog, Severity, SourceType

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class WebSignatureRule(BaseRule):
    #: Compiled payload signatures; the first one that matches wins.
    patterns: List[re.Pattern]

    #: Attack name used in the explanation, e.g. "SQL injection".
    attack_label: str

    severity: Severity
    confidence: float

    def severity_for(self, match: re.Match) -> Severity:
        """Severity of one matched request. Override to grade specific payloads higher."""
        return self.severity

    def _match(self, text: str) -> Optional[re.Match]:
        # Attackers percent-encode payloads to slip past naive matching,
        # so check the decoded form first and the raw form as a fallback.
        decoded = unquote(text)
        for pattern in self.patterns:
            match = pattern.search(decoded) or pattern.search(text)
            if match:
                return match
        return None

    def evaluate(self, logs: List[NormalizedLog]) -> List[DetectionEvent]:
        hits: Dict[str, List[Tuple[NormalizedLog, str, Severity]]] = defaultdict(list)

        for log in logs:
            if log.source_type != SourceType.WEB_SERVER.value:
                continue
            path = log.parsed_fields.get("path") or log.raw_log
            match = self._match(path)
            if match:
                hits[log.source_ip or "unknown"].append((log, path, self.severity_for(match)))

        detections: List[DetectionEvent] = []
        for source_ip, ip_hits in hits.items():
            severity = max((sev for _, _, sev in ip_hits), key=_SEVERITY_ORDER.index)
            count = len(ip_hits)
            requests = f"{count} requests" if count > 1 else "a request"
            detections.append(
                DetectionEvent(
                    engine=DetectionEngine.RULE,
                    rule_name=self.rule_name,
                    confidence=self.confidence,
                    severity=severity,
                    mitre_technique=self.mitre_technique,
                    entity=Entity(type=EntityType.IP, value=source_ip),
                    evidence_log_ids=[log.log_id for log, _, _ in ip_hits],
                    explanation=(
                        f"{self.attack_label} signature matched in {requests} from {source_ip}. "
                        f"Example: {ip_hits[0][1][:200]}"
                    ),
                )
            )
        return detections
