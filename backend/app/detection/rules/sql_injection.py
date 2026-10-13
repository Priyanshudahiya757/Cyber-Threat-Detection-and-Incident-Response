"""
app/detection/rules/sql_injection.py

Purpose:
    Detects SQL injection attempts in web server request paths/query
    strings via signature matching against common SQLi payload patterns
    (boolean-based tautologies, UNION SELECT, comment terminators,
    stacked queries, time-based probes).

MITRE ATT&CK:
    T1190 - Exploit Public-Facing Application
"""
import re

from app.detection.rules.web_signature import WebSignatureRule
from app.models.log_schema import Severity


class SQLInjectionRule(WebSignatureRule):
    rule_name = "sql_injection"
    description = "Web request path/query string matches known SQL injection payload signatures."
    mitre_technique = "T1190 - Exploit Public-Facing Application"

    attack_label = "SQL injection"
    severity = Severity.HIGH
    confidence = 0.75
    patterns = [
        re.compile(r"UNION(\s+ALL)?\s+SELECT", re.IGNORECASE),
        re.compile(r"(\bOR\b|\bAND\b)\s+'?\d+'?\s*=\s*'?\d+'?", re.IGNORECASE),  # ' OR 1=1
        re.compile(r"['\")]\s*(--|#|/\*)"),  # quote closed, rest of query commented out
        re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT)\s+", re.IGNORECASE),  # stacked queries
        re.compile(r"\bSLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),  # time-based blind SQLi
        re.compile(r"information_schema", re.IGNORECASE),
    ]

    def severity_for(self, match: re.Match) -> Severity:
        # UNION SELECT is a data-extraction attempt, not just a probe.
        return Severity.CRITICAL if "UNION" in match.group(0).upper() else self.severity
