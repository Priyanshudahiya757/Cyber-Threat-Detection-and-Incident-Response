"""
app/detection/rules/xss.py

Purpose:
    Detects Cross-Site Scripting payloads in web server request
    paths/query strings: script tags, inline event handlers,
    javascript: URLs and DOM access probes.

MITRE ATT&CK:
    T1059.007 - Command and Scripting Interpreter: JavaScript
"""
import re

from app.detection.rules.web_signature import WebSignatureRule
from app.models.log_schema import Severity


class XSSRule(WebSignatureRule):
    rule_name = "xss"
    description = "Web request path/query string matches known Cross-Site Scripting payload signatures."
    mitre_technique = "T1059.007 - Command and Scripting Interpreter: JavaScript"

    attack_label = "XSS payload"
    severity = Severity.MEDIUM
    confidence = 0.7
    patterns = [
        re.compile(r"<script[\s>]", re.IGNORECASE),
        re.compile(r"on(error|load|click|mouseover|focus)\s*=", re.IGNORECASE),  # event handler injection
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"<img[^>]+src\s*=", re.IGNORECASE),
        re.compile(r"document\.(cookie|location)", re.IGNORECASE),
        re.compile(r"<iframe[\s>]", re.IGNORECASE),
    ]
