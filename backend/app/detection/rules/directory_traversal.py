"""
app/detection/rules/directory_traversal.py

Purpose:
    Detects directory/path traversal attempts in web request paths —
    sequences attempting to escape the web root via "../" (and its
    encoded variants) to reach sensitive files like /etc/passwd or
    Windows system files.

MITRE ATT&CK:
    T1083 - File and Directory Discovery (reconnaissance via traversal)
"""
import re

from app.detection.rules.web_signature import WebSignatureRule
from app.models.log_schema import Severity


class DirectoryTraversalRule(WebSignatureRule):
    rule_name = "directory_traversal"
    description = "Web request path contains directory traversal sequences targeting sensitive system paths."
    mitre_technique = "T1083 - File and Directory Discovery"

    attack_label = "Directory traversal"
    severity = Severity.HIGH
    confidence = 0.8
    patterns = [
        re.compile(r"(\.\./){2,}"),  # multiple ../ segments
        re.compile(r"\.\.%2f", re.IGNORECASE),  # encoded ../
        re.compile(r"%2e%2e[/\\]", re.IGNORECASE),
        re.compile(r"(etc/passwd|boot\.ini|win\.ini|system32)", re.IGNORECASE),
    ]
