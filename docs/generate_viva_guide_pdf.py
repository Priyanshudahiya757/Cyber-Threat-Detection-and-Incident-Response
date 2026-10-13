#!/usr/bin/env python3
"""Generate the project-specific developer and viva guide PDF.

This document is intentionally written from the checked-in implementation,
not from a generic SIEM template.  Run from the repository root:
    /Users/rudranildatta/Downloads/cyber threat detection/.pptx-venv/bin/python docs/generate_viva_guide_pdf.py
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent.parent
DOCS_PDF = ROOT / "docs" / "PROJECT_DEVELOPER_VIVA_GUIDE.pdf"
ROOT_PDF = ROOT.parent.parent / "PROJECT_DEVELOPER_VIVA_GUIDE.pdf"


def page_number(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#1D4ED8"))
    canvas.line(1.8 * cm, 1.35 * cm, A4[0] - 1.8 * cm, 1.35 * cm)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(1.8 * cm, 0.9 * cm, "Cyber Threat Detection and Incident Response Dashboard")
    canvas.drawRightString(A4[0] - 1.8 * cm, 0.9 * cm, f"Page {doc.page}")
    canvas.restoreState()


styles = getSampleStyleSheet()
TITLE = ParagraphStyle(
    "GuideTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=25,
    leading=31, alignment=TA_CENTER, textColor=colors.HexColor("#0F172A"), spaceAfter=14,
)
SUBTITLE = ParagraphStyle(
    "GuideSubtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=13,
    leading=19, alignment=TA_CENTER, textColor=colors.HexColor("#475569"), spaceAfter=10,
)
H1 = ParagraphStyle(
    "GuideH1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17,
    leading=22, textColor=colors.HexColor("#0F3D7A"), spaceBefore=10, spaceAfter=9,
)
H2 = ParagraphStyle(
    "GuideH2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13,
    leading=17, textColor=colors.HexColor("#1D4ED8"), spaceBefore=10, spaceAfter=6,
)
H3 = ParagraphStyle(
    "GuideH3", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10.5,
    leading=14, textColor=colors.HexColor("#334155"), spaceBefore=7, spaceAfter=3,
)
BODY = ParagraphStyle(
    "GuideBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.2,
    leading=13.2, spaceAfter=5, textColor=colors.HexColor("#172033"),
)
BULLET = ParagraphStyle(
    "GuideBullet", parent=BODY, leftIndent=13, firstLineIndent=-9, bulletIndent=2, spaceAfter=3,
)
CODE = ParagraphStyle(
    "GuideCode", parent=BODY, fontName="Courier", fontSize=7.8, leading=10.5,
    textColor=colors.HexColor("#7C2D12"), backColor=colors.HexColor("#FFF7ED"),
    borderColor=colors.HexColor("#FED7AA"), borderWidth=0.3, borderPadding=4, spaceAfter=5,
)
SMALL = ParagraphStyle(
    "GuideSmall", parent=BODY, fontSize=8, leading=10.5, textColor=colors.HexColor("#475569"),
)


def P(text, style=BODY):
    return Paragraph(text, style)


def code(text):
    return P(escape(text), CODE)


def path(text):
    return f'<font face="Courier" color="#7C2D12">{escape(text)}</font>'


def bullets(items):
    return [Paragraph(escape(item), BULLET, bulletText="•") for item in items]


def section(story, number, title, intro=None):
    story.append(P(f"{number}. {escape(title)}", H1))
    if intro:
        story.append(P(intro))


def sub(story, number, title, intro=None):
    story.append(P(f"{number} {escape(title)}", H2))
    if intro:
        story.append(P(intro))


def answer_table(rows):
    data = [[P("<b>Question</b>", SMALL), P("<b>Project-specific answer</b>", SMALL)]]
    for left, right in rows:
        data.append([P(f"<b>{escape(left)}</b>", SMALL), P(right, SMALL)])
    table = Table(data, colWidths=[4.0 * cm, 12.9 * cm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DBEAFE")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BFDBFE")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    return table


MODULES = [
    {
        "name": "Application entry point", "files": "backend/app/main.py",
        "what": "The FastAPI composition root. It creates the application, configures CORS and global error handling, owns lifecycle startup/shutdown, and mounts every version-1 router.",
        "why": "It gives the backend one controlled boot sequence. Mongo indexes, Elasticsearch templates, persisted rule states, and the ingestion-to-detection callback must be ready before requests arrive.",
        "problem": "Without a composition root, routers and infrastructure would initialize independently and the upload pipeline could ingest logs without automatic detection.",
        "interaction": "On startup it calls Mongo connect/index setup, attempts Elasticsearch connect, registers <i>handle_ingested_logs</i> on <i>default_pipeline</i>, loads Mongo rule configuration, then mounts auth, logs, incidents, analytics, rules, detections, and ML routers.",
        "removed": "The API would have no ASGI application, no routes, no startup connections, and no automatic pipeline callback. The React client could not use the service.",
        "apis": "/health, /health/ready, and all /api/v1/* routes through router inclusion.",
        "stores": "Directly checks MongoDB and Elasticsearch on <i>/health/ready</i>; does not own a collection or index.",
        "enters": "Environment-derived settings, HTTP requests, and FastAPI lifespan events.",
        "leaves": "Mounted REST API, standardized 500 response, liveness/readiness JSON, and initialized process-wide services.",
    },
    {
        "name": "Core configuration, security, and dependencies", "files": "backend/app/core/config.py; backend/app/core/security.py; backend/app/core/dependencies.py; backend/app/core/logging_config.py",
        "what": "Cross-cutting platform layer: typed environment settings, bcrypt password functions, JWT issue/validation, OAuth bearer extraction, and role-based dependency checks.",
        "why": "Security rules should be centrally auditable instead of duplicated inside each endpoint.",
        "problem": "It solves secret/config sprawl, inconsistent token validation, and endpoints accidentally trusting unauthenticated callers.",
        "interaction": "Auth router uses hashing and token creation; protected routers use <i>get_current_user</i> or <i>require_role</i>; database clients read connection settings; main reads CORS and app metadata.",
        "removed": "Login cannot safely issue tokens, RBAC cannot protect upload/admin functions, and modules would need unsafe direct environment access.",
        "apis": "Indirectly protects all authenticated APIs; admin-only examples include <i>POST /ml/train</i>, <i>PATCH /rules/{rule_name}</i>, and <i>POST /auth/register</i>.",
        "stores": "Reads Mongo <i>users</i> while resolving a token; no Elasticsearch index.",
        "enters": ".env variables, Bearer tokens, plaintext login password, and requested allowed roles.",
        "leaves": "Settings object, password hashes/verification result, signed access/refresh JWTs, current <i>UserInDB</i>, or HTTP 401/403.",
    },
    {
        "name": "API v1 HTTP layer", "files": "backend/app/api/v1/auth.py; logs.py; detections.py; incidents.py; analytics.py; rules.py; ml.py",
        "what": "Thin FastAPI controllers grouped by bounded context under the <i>/api/v1</i> prefix.",
        "why": "It separates HTTP validation/authorization/response shaping from parsing, persistence, detection, and incident business logic.",
        "problem": "It provides a stable contract for the frontend and external clients while preventing UI code from reaching data stores directly.",
        "interaction": "Routers depend on core authentication, invoke ingestion/detection/incident services, query repositories, and return Pydantic/JSON response shapes consumed by frontend services.",
        "removed": "The business classes might exist, but neither the React UI nor a shipper can call them over HTTP.",
        "apis": "Auth: login/refresh/register/me; Logs: upload/ingest/search/batches; Detections: list/alerts/rules/run; ML: train/predict/models/evaluate; Incidents: list/detail/status/notes/assign; Analytics: summary/top-ips/severity/timeline/attack-types/recent-events; Rules: list/update.",
        "stores": "Through services: all Mongo collections and the <i>security-logs-*</i> Elasticsearch indices.",
        "enters": "JSON bodies, multipart files, query parameters, and JWT-authenticated user context.",
        "leaves": "HTTP status codes and frontend-ready JSON such as <i>{detections, count}</i>, <i>{incidents, count}</i>, upload counts, and analytics charts data.",
    },
    {
        "name": "Domain models and schemas", "files": "backend/app/models/log_schema.py; detection_schema.py; alert_schema.py; incident_schema.py; user_schema.py",
        "what": "Pydantic contracts for normalized logs, upload batches, detection events, alerts, incidents, users, tokens, roles, and request bodies.",
        "why": "A shared typed language prevents parser, detector, database, and API layers from disagreeing about field names and legal values.",
        "problem": "It solves schema drift and validates required structure before data reaches downstream logic.",
        "interaction": "Parsers produce <i>ParsedEvent</i>; normalizer creates <i>NormalizedLog</i>; rules/ML produce <i>DetectionEvent</i>; alerting and correlator use those events; API routes expose model-shaped data.",
        "removed": "Validation and canonical contracts disappear; detection and storage would need ad-hoc dictionaries and failures would appear later and less clearly.",
        "apis": "All routes use these directly or indirectly; upload response is <i>LogUploadResponse</i>, login response is <i>TokenResponse</i>.",
        "stores": "Schema maps to Mongo users/incidents/detections/alerts/ingestion_batches and ES normalized log documents.",
        "enters": "Raw parser results, request models, database documents, model scores, and incident workflow input.",
        "leaves": "Validated, serialized objects with enum values such as source type, severity, engine, role, and incident status.",
    },
    {
        "name": "MongoDB repository", "files": "backend/app/db/mongo.py",
        "what": "Async Motor connection owner and repository functions for operational, identity, workflow, detection, alert, rule, and audit metadata.",
        "why": "MongoDB suits mutable document-style operational records and aggregates; the repository keeps Motor out of business and HTTP code.",
        "problem": "It provides persistent users, incidents, detection results, alerts, rule settings, and ingestion audit records.",
        "interaction": "Core dependencies retrieve users; auth creates users/updates logins; pipeline saves batches; engine saves detections/alerts; correlator and incident service update incidents; analytics aggregates Mongo results.",
        "removed": "Authentication user lookup, incident history, alert/detection persistence, configurable rule state, audit batches, and dashboard counts fail.",
        "apis": "Auth, logs/batches, detections/alerts, incidents, analytics, and rules APIs use it indirectly.",
        "stores": "Collections: <i>users</i>, <i>incidents</i>, <i>detection_rules</i>, <i>system_config</i>, <i>ingestion_batches</i>, <i>detections</i>, <i>alerts</i>, and <i>counters</i>.",
        "enters": "User credentials after hashing, incident documents, detection/alert Pydantic dumps, rule updates, upload batch metadata, and aggregation filters.",
        "leaves": "Typed users, documents/lists/counts/aggregates, monotonic incident sequence numbers, and write acknowledgements.",
    },
    {
        "name": "Elasticsearch log repository", "files": "backend/app/db/elastic.py; elasticsearch/mappings/security_logs_mapping.json",
        "what": "Async Elasticsearch client owner for time-oriented normalized log indexing, search, deduplication, and log-derived aggregation.",
        "why": "Logs are searched and aggregated by time/IP/text more often than they are updated; daily ES indices fit that workload better than Mongo operational collections.",
        "problem": "It provides scalable evidence search, ingest deduplication, live monitoring, top-IP and severity views.",
        "interaction": "Pipeline uses cross-index duplicate checks and bulk indexing; logs API searches it; detections manual/ML training retrieve a time window; analytics runs aggregations.",
        "removed": "Raw evidence cannot be stored/searchable, ingestion cannot complete, and analytics/features depending on telemetry fail.",
        "apis": "GET /logs/search; POST /detections/run; POST /ml/train; POST /ml/predict; GET analytics summary/top-ips/severity endpoints.",
        "stores": "Daily <i>security-logs-YYYY.MM.DD</i> indices, queried with <i>security-logs-*</i>; template is named from <i>security-logs</i> prefix.",
        "enters": "NormalizedLog documents, search filters, time windows, source IP/source type/severity terms, and log-id lists.",
        "leaves": "Indexed IDs, accepted/rejected bulk counts, search <i>{total, results}</i>, dedupe set, and aggregate counts/buckets.",
    },
    {
        "name": "Ingestion parser and normalization layer", "files": "backend/app/ingestion/parsers/base_parser.py; linux_parser.py; windows_parser.py; firewall_parser.py; web_parser.py; backend/app/ingestion/normalizer.py",
        "what": "Source adapters convert four raw formats into a light ParsedEvent; normalizer then produces one canonical NormalizedLog and deterministic SHA-256 log ID.",
        "why": "Linux syslog, Windows JSON, firewall connection lines, and Apache/Nginx access logs are structurally incompatible, but detectors need one stable schema.",
        "problem": "It separates format extraction from canonical mapping and makes re-upload idempotent through content-based log IDs.",
        "interaction": "Pipeline selects a parser from PARSER_REGISTRY, sends ParsedEvent to normalize, and passes NormalizedLog to ES/detection/ML.",
        "removed": "The system has no trustworthy bridge from source-specific bytes to detection-ready fields; every detector would need four format implementations.",
        "apis": "POST /logs/upload and POST /logs/ingest use it through the pipeline.",
        "stores": "No direct store; its NormalizedLog output is written to ES and its batch outcome later goes to Mongo.",
        "enters": "UTF-8 raw content and source type/host. Windows accepts JSON array or NDJSON; Linux recognizes sshd/sudo; firewall recognizes ALLOW/DENY lines; web recognizes Combined Log Format.",
        "leaves": "ParsedEvent list, normalized logs containing event fields/raw evidence/timestamps, and low-default or parser-suggested severity.",
    },
    {
        "name": "Ingestion orchestration pipeline", "files": "backend/app/ingestion/pipeline.py",
        "what": "The single end-to-end ingestion coordinator implementing parse → normalize → validate → deduplicate → ES bulk index → Mongo batch audit → post-ingestion callback.",
        "why": "This sequence must be consistent for file upload and programmatic ingestion and must not be duplicated in controllers.",
        "problem": "It isolates bad records, prevents duplicate logs across daily indices, records traceability, and decouples detection using an injected callback.",
        "interaction": "Logs API calls <i>default_pipeline.process</i>; it uses parser registry/normalizer/ES/Mongo; main injects <i>handle_ingested_logs</i> after startup.",
        "removed": "Uploads would need bespoke orchestration, have inconsistent dedupe/audit behavior, and would not automatically invoke detection.",
        "apis": "POST /logs/upload and POST /logs/ingest.",
        "stores": "Reads ES <i>security-logs-*</i> for duplicate IDs, writes fresh logs to today’s ES index, writes batch metadata to Mongo <i>ingestion_batches</i>.",
        "enters": "Raw content, source type, uploader username, optional source host and file name.",
        "leaves": "LogUploadResponse with accepted/rejected/duplicates/errors/log_ids/batch_id and an asynchronous list of fresh logs for detection.",
    },
    {
        "name": "Rule detection engine", "files": "backend/app/detection/engine.py; backend/app/detection/rules/base_rule.py",
        "what": "A configurable RuleEngine registry that runs enabled BaseRule strategies and combines their DetectionEvent output.",
        "why": "Known attack signatures and behavioral thresholds need transparent, auditable detection independent of ML availability.",
        "problem": "It detects repeat failed logins, port scans, web payload signatures, privilege escalation, and off-hours privileged logins with MITRE context.",
        "interaction": "Main registers its post-ingest handler. It invokes rule classes, then also calls ML prediction, saves combined detections, generates alerts, and asks the incident correlator to group them.",
        "removed": "Ingestion would still store logs but known attack patterns would not become detections, alerts, incidents, or dashboard threat counts.",
        "apis": "Automatic on upload; POST /detections/run manually scans a recent ES window; GET /detections/rules exposes live rule metadata.",
        "stores": "Writes Mongo <i>detections</i> through the handler; source evidence comes from ES normalized logs.",
        "enters": "A list of NormalizedLog objects and persisted enabled/config state from Mongo.",
        "leaves": "Rule DetectionEvent objects with rule name, confidence, severity, MITRE technique, entity, evidence IDs, and explanation.",
    },
    {
        "name": "Detection rules", "files": "backend/app/detection/rules/ssh_brute_force.py; windows_failed_login.py; port_scan.py; sql_injection.py; xss.py; directory_traversal.py; privilege_escalation.py; suspicious_admin_login.py",
        "what": "Eight focused detection strategies, each carrying its own rule name, MITRE mapping, thresholds/config, evidence selection, explanation, and severity logic.",
        "why": "Attack types have materially different semantics: a port scan is a many-port network pattern while SQLi/XSS/traversal are per-request payload signatures.",
        "problem": "They transform normalized telemetry into actionable, explainable security findings rather than opaque raw logs.",
        "interaction": "Engine instantiates these rules; rules use BaseRule grouping/window/pattern helpers; their DetectionEvent output flows to Mongo, alerts, incidents, and frontend.",
        "removed": "The engine remains but has no substantive signatures/threshold logic and produces no rule-based detections.",
        "apis": "GET /rules, PATCH /rules/{rule_name}, GET /detections/rules, POST /detections/run, and automatic upload processing.",
        "stores": "Rule enabled/config state is Mongo <i>detection_rules</i>; results are Mongo <i>detections</i>, alerts can reach <i>alerts</i>, and evidence lives in ES.",
        "enters": "NormalizedLog batches: Linux/Windows auth events, firewall denied connections, and decoded web request paths.",
        "leaves": "DetectionEvent records. Key thresholds: Linux SSH ≥4 in 120s, Windows failed logins ≥3 in 120s, port scan ≥5 distinct ports in 60s.",
    },
    {
        "name": "ML anomaly detection", "files": "backend/app/detection/ml/base_model.py; feature_extraction.py; isolation_forest_model.py; model_registry.py; prediction_service.py; training_service.py",
        "what": "An unsupervised Isolation Forest subsystem behind an AnomalyModel interface, with feature engineering, versioned joblib artifacts, training, prediction, and labeled evaluation.",
        "why": "Rules catch known patterns; ML adds a source-IP behavioral outlier signal for unusual activity that may not match a signature.",
        "problem": "It trains a repeatable model, prevents training on fewer than five distinct entities, produces explainable anomaly events, and persists versions rather than overwriting them.",
        "interaction": "ML API loads historical ES logs; feature extraction builds eight features per source IP; training registers a model; prediction returns DetectionEvents to the same alert/correlation path as rules.",
        "removed": "The dashboard loses AI anomaly counts and the system only detects explicitly coded patterns; core ingestion/rules still operate.",
        "apis": "POST /ml/train, POST /ml/predict, GET /ml/models, GET /ml/models/latest, POST /ml/evaluate; prediction also runs automatically after ingest if a model exists.",
        "stores": "Reads ES logs; writes ML DetectionEvents/alerts/incidents to Mongo; artifacts and <i>registry_index.json</i> live in <i>ml/models</i> mounted by Docker.",
        "enters": "Normalized logs grouped by source IP, hyperparameters (days/contamination), and labeled CSV for evaluation.",
        "leaves": "Version metadata, precision/recall/F1 diagnostics, and ML DetectionEvents with raw score, 0–100 batch-relative risk, evidence IDs, and top-feature explanation.",
    },
    {
        "name": "Alerting", "files": "backend/app/detection/alerting.py; backend/app/models/alert_schema.py",
        "what": "A focused in-application alert creator that converts high and critical DetectionEvents into persisted Alert documents.",
        "why": "Not every detection should interrupt an analyst; alert thresholding distinguishes stored signal from urgent signal.",
        "problem": "It provides a durable alert feed while keeping external email/Discord/Telegram delivery explicitly outside the implemented scope.",
        "interaction": "Called by automatic engine handler and manual rule/ML routes after detections are saved; uses Mongo repository and audit logger.",
        "removed": "Detections and incidents remain, but the dedicated alert list and critical alert dashboard count lose their source.",
        "apis": "GET /detections/alerts exposes persisted alerts; POST /detections/run and POST /ml/predict can create them.",
        "stores": "Writes Mongo <i>alerts</i>; AlertInDB includes <i>channel_dispatched</i> as a future integration seam.",
        "enters": "DetectionEvent list.",
        "leaves": "One AlertInDB per high/critical event: title, threat type, severity, entity, detection ID, MITRE technique, description, timestamp.",
    },
    {
        "name": "Incident correlation and service", "files": "backend/app/incidents/correlator.py; backend/app/incidents/service.py",
        "what": "Correlation groups related detection events into incidents; service enforces analyst workflow, notes, assignment, and non-destructive status transitions.",
        "why": "A burst of detections should not produce dozens of separate analyst tickets. Incidents are the SOC work unit, not raw logs.",
        "problem": "It deduplicates investigation workload by (entity value, threat key, active status), escalates severity, tracks evidence, and preserves audit history.",
        "interaction": "Engine/manual runners invoke correlator after detections; service reads/writes Mongo; incidents router exposes the workflow to the UI.",
        "removed": "Users would see isolated detections but could not manage a correlated case, assign it, record notes, or resolve it safely.",
        "apis": "GET /incidents, GET /incidents/{ref}, PATCH status, POST notes, PATCH assign.",
        "stores": "Mongo <i>incidents</i> and <i>counters</i> for atomic <i>INC-1001</i>-style references; reads detection evidence already stored in Mongo/ES.",
        "enters": "DetectionEvent lists, status/note/assignment request bodies, and authenticated actor username.",
        "leaves": "Created/updated incident documents, workflow audit notes, severity escalation notes, and safe status transitions OPEN → INVESTIGATING → RESOLVED → CLOSED.",
    },
    {
        "name": "Frontend API and service layer", "files": "frontend/src/api/client.ts; endpoints.ts; tokenStorage.ts; frontend/src/services/authService.ts; logService.ts; detectionService.ts; incidentService.ts; analyticsService.ts; ruleService.ts",
        "what": "Typed Axios boundary that centralizes API base URL, route strings, Bearer attachment, silent refresh/retry, browser token persistence, and service functions.",
        "why": "React components should describe UI state, not duplicate request URLs, headers, refresh logic, or response parsing.",
        "problem": "It solves cross-page consistency and prevents a 401 storm from causing multiple simultaneous refresh requests.",
        "interaction": "Every feature page calls a service; Axios interceptor adds access JWT; a single in-flight refresh calls <i>/auth/refresh</i>; tokenStorage chooses local or session storage for Remember Me.",
        "removed": "Pages would need direct HTTP calls; auth refresh and endpoint naming would become fragmented and fragile.",
        "apis": "Mirrors all backend v1 routes, especially /auth, /logs, /detections, /ml, /incidents, /analytics, and /rules.",
        "stores": "Browser localStorage/sessionStorage for access/refresh JWTs; no direct Mongo or ES access.",
        "enters": "Form data, typed query filters, endpoint-specific request bodies, and tokens.",
        "leaves": "Typed Promise response shapes for pages; authenticated HTTP requests; redirect to /login if refresh fails.",
    },
    {
        "name": "Frontend features and routes", "files": "frontend/src/routes/AppRouter.tsx; frontend/src/features/auth/*; dashboard/pages/DashboardPage.tsx; logs/pages/UploadLogsPage.tsx; monitoring/pages/LiveMonitoringPage.tsx; detections/pages/ThreatDetectionPage.tsx; anomalies/pages/AnomalyDetectionPage.tsx; incidents/pages/IncidentManagementPage.tsx; analytics/pages/AnalyticsPage.tsx; rules/pages/DetectionRulesPage.tsx",
        "what": "React TypeScript presentation and route layer for authentication, dashboard, upload/search, detections, ML, incidents, analytics, and rule administration.",
        "why": "It turns backend evidence and workflow data into a navigable SOC user experience with role gates and auto-refreshing visual summaries.",
        "problem": "It gives analysts a controlled interface to submit logs, investigate evidence, rerun detection, train/predict ML, and manage incidents.",
        "interaction": "AppRouter wraps protected pages in ProtectedRoute/AppShell and Users in AdminRoute. Pages call services; Dashboard uses React Query with 15-second refresh and Recharts.",
        "removed": "The REST API remains available but the human SOC dashboard/demo workflow is lost.",
        "apis": "Pages consume their matching service routes; Dashboard consumes six analytics endpoints and renders summary cards/charts/recent events.",
        "stores": "Indirectly consumes Mongo/ES-backed API data; only direct client storage is the token wrapper.",
        "enters": "User form actions, route state, API response objects, query filters, uploaded files, and auth context.",
        "leaves": "Rendered pages, charts, tables, status controls, feedback states, and API mutations.",
    },
    {
        "name": "Docker Compose deployment", "files": "docker-compose.yml; backend/Dockerfile; frontend/Dockerfile",
        "what": "Local multi-container deployment definition for MongoDB 7, Elasticsearch 8.15, optional Kibana, FastAPI backend, and Vite/React frontend.",
        "why": "The project requires two stateful services plus two applications; Compose makes versions, ports, health checks, mounts, and startup dependencies repeatable.",
        "problem": "It removes manual setup drift and gives an academic demo a predictable single command startup path.",
        "interaction": "Backend receives Compose-specific Mongo/ES hostnames and mounts backend code/models/datasets/mappings/sample logs. Frontend receives proxy/base URL environment values and waits for backend.",
        "removed": "The source can still run manually, but full-stack environment setup becomes error-prone; dependencies and persistent data are not orchestrated.",
        "apis": "Exposes Mongo 27017, ES 9200, Kibana 5601, backend 8000, and frontend 5173; backend serves all API endpoints.",
        "stores": "Named volumes <i>mongo_data</i> and <i>es_data</i>; mounted <i>ml/models</i>; corresponding Mongo collections and ES indices.",
        "enters": "Images/build contexts, .env, Compose environment overrides, mapped source directories, and health-check conditions.",
        "leaves": "Healthy interconnected containers, persistent volumes, host ports, and repeatable runtime topology.",
    },
]


def add_module(story, idx, module):
    sub(story, f"2.{idx}", module["name"])
    story.append(code(module["files"]))
    labels = [
        ("1. What is this module?", module["what"]),
        ("2. Why does it exist?", module["why"]),
        ("3. What problem does it solve?", module["problem"]),
        ("4. How does it interact with other modules?", module["interaction"]),
        ("5. What happens if removed?", module["removed"]),
        ("6. Which files are responsible?", f"Primary responsibility is in {path(module['files'])}."),
        ("7. Which APIs use it?", module["apis"]),
        ("8. Which Mongo collections / ES indices?", module["stores"]),
        ("9. What data enters?", module["enters"]),
        ("10. What data leaves?", module["leaves"]),
    ]
    story.append(answer_table(labels))
    story.append(Spacer(1, 5))


def workflow_steps(story):
    steps = [
        ("3.1 Login and credential validation",
         "The user submits <i>LoginForm</i> through <i>AuthContext.login</i> to <i>authService.login</i>, which POSTs <i>/api/v1/auth/login</i>. In <i>backend/app/api/v1/auth.py::login</i>, Mongo <i>get_user_by_username</i> retrieves <i>users</i>; <i>verify_password</i> checks bcrypt; <i>create_access_token</i> and <i>create_refresh_token</i> sign HS256 JWT claims <i>sub</i>, <i>role</i>, <i>type</i>, <i>iat</i>, <i>exp</i>. Mongo updates <i>last_login</i>. The frontend receives <i>{access_token, refresh_token, token_type, user}</i>, saves tokens in local/session storage, and holds <i>UserPublic</i> in context."),
        ("3.2 JWT use, refresh, and RBAC",
         "Every Axios request from <i>api/client.ts</i> attaches <i>Authorization: Bearer &lt;access token&gt;</i>. FastAPI <i>oauth2_scheme</i> extracts it; <i>get_current_user</i> calls <i>decode_token(expected_type='access')</i> and reloads the active user from Mongo. <i>require_role</i> adds precise 403 role gates. On a 401, the frontend serializes refresh calls with <i>refreshInFlight</i>, POSTs <i>/auth/refresh</i>, saves the rotated token pair, and retries once; invalid refresh clears storage and navigates to <i>/login</i>."),
        ("3.3 Upload and HTTP validation",
         "UploadLogsPage calls <i>logService.upload(file, sourceType, sourceHost)</i>, creating multipart FormData. <i>POST /logs/upload</i> checks that extension is .log/.txt/.json, limits raw bytes using <i>MAX_UPLOAD_FILE_SIZE_MB</i>, requires UTF-8 text, and passes raw content plus the authenticated uploader name to <i>default_pipeline.process</i>. Programmatic sources can POST JSON to <i>/logs/ingest</i> with source_type, source_host, and content."),
        ("3.4 Parser selection and raw extraction",
         "In <i>IngestionPipeline.process</i>, <i>PARSER_REGISTRY</i> maps SourceType to a stateless parser. Linux extracts failed/accepted SSH and sudo patterns; Windows loads JSON array or NDJSON and maps Event IDs 4624/4625/4672/4720/4728; firewall extracts action/protocol/source/destination/port; web extracts Combined Log Format fields. Each produces ParsedEvent, preserving raw evidence. A structurally invalid Windows payload raises a controlled 422; individual unrecognized lines are skipped."),
        ("3.5 Normalize, validate, deduplicate, and index",
         "For every ParsedEvent, <i>normalizer.normalize</i> produces NormalizedLog. It makes timestamps UTC, resolves valid severity hints or LOW default, and computes SHA-256 from source type, host, raw log, and timestamp. Pipeline queries ES <i>security-logs-*</i> for existing log_ids across all daily indices, removes duplicates, then calls <i>bulk_index_logs</i> into today’s <i>security-logs-YYYY.MM.DD</i>. It writes an IngestionBatch audit document to Mongo <i>ingestion_batches</i> and returns <i>{accepted, rejected, duplicates, errors, log_ids, batch_id}</i> to the frontend."),
        ("3.6 Rule engine and automatic AI scoring",
         "Main registered <i>handle_ingested_logs</i> as the pipeline callback. It runs enabled rules over just-indexed NormalizedLog objects, then calls <i>default_prediction_service.predict</i>. Prediction safely returns an empty list if no trained model exists, so AI readiness never blocks rule detection. Combined DetectionEvents are persisted in Mongo <i>detections</i>. This common event schema keeps later processing independent of whether an event came from rule or ML."),
        ("3.7 Alerts and correlated incidents",
         "<i>generate_alerts</i> creates Mongo <i>alerts</i> only for high/critical detections. Then <i>correlate_detections</i> derives a threat key (rule name or ml_anomaly) and searches for active Mongo incidents with the same entity value and correlation key. It adds evidence/detection IDs and escalates severity on a matching OPEN/INVESTIGATING incident; otherwise it atomically allocates an INC number from <i>counters</i> and creates a Mongo <i>incidents</i> document."),
        ("3.8 Dashboard, live monitoring, and analytics",
         "DashboardPage uses React Query every 15 seconds to request <i>/analytics/summary</i>, threat timeline, severity distribution, attack types, top IPs, and recent events. Analytics combines ES counts/aggregations with Mongo counts/aggregates. Live Monitoring calls <i>/logs/search</i>, receiving <i>{total, results: NormalizedLog[]}</i>. Threat/incident pages receive <i>{detections, count}</i> and <i>{incidents, count}</i>; all have field names matching backend schemas rather than custom UI-only shapes."),
    ]
    for title, text in steps:
        story.append(P(title, H2))
        story.append(P(text))


FEATURES = [
    ("Authentication", "JWT login is implemented, not mocked: bcrypt verifies a Mongo user, access and refresh JWTs carry subject/role/type, Axios retries one failed request after refresh, and FastAPI reloads the active user for each protected request.", "It protects SOC data and permits role-specific admin actions. Without it, upload, rule changes, model training, and incident operations would be unauthenticated.", "backend/app/api/v1/auth.py; backend/app/core/security.py; backend/app/core/dependencies.py; frontend/src/api/client.ts; frontend/src/api/tokenStorage.ts; frontend/src/features/auth/context/AuthContext.tsx"),
    ("Dashboard", "The dashboard is a live operational summary, not a static report: six React Query calls refresh every 15 seconds and Recharts renders trend, severity, attack type, and IP views.", "It compresses thousands of records into SOC prioritization signals. Without it, an analyst must query separate endpoints and cannot rapidly assess risk.", "frontend/src/features/dashboard/pages/DashboardPage.tsx; backend/app/api/v1/analytics.py"),
    ("Log Upload", "Multipart upload validates source type, extension, UTF-8, and maximum size before invoking one reusable pipeline. The response exposes accepted/rejected/duplicate counts and batch ID.", "It is the controlled gateway for evidence. Without it, logs are neither normalized nor auditable nor automatically detected.", "frontend/src/services/logService.ts; backend/app/api/v1/logs.py; backend/app/ingestion/pipeline.py"),
    ("Parsing", "Four source-specific strategies understand Linux sshd/sudo, Windows exported Security JSON, firewall ALLOW/DENY lines, and Apache/Nginx Combined Log Format.", "It extracts meaningful fields without conflating source-format handling with security verdicts. Without it, raw text cannot feed generic downstream rules.", "backend/app/ingestion/parsers/*.py"),
    ("Normalization", "Parsed events become NormalizedLog records with UTC timestamps, canonical enums, raw evidence, parsed fields, and deterministic SHA-256 IDs.", "It is the contract that makes all downstream logic source-agnostic and idempotent. Without it, every rule/ML feature would be parser-specific and duplicates would recur.", "backend/app/ingestion/normalizer.py; backend/app/models/log_schema.py"),
    ("Windows, Linux, Firewall, and Web processing", "Windows maps Event IDs to login/privilege semantics; Linux extracts auth and sudo; firewall maps DENY connections and ports; web extracts request paths for payload scanning.", "Each produces security-relevant fields unique to its source. Without a parser, that source type is unsupported but the architecture remains extensible through BaseLogParser and PARSER_REGISTRY.", "backend/app/ingestion/parsers/windows_parser.py; linux_parser.py; firewall_parser.py; web_parser.py"),
    ("Rule detection", "Eight explainable rules emit MITRE-mapped DetectionEvents, including brute force, port scanning, SQLi, XSS, traversal, privilege escalation, and suspicious privileged login.", "Known attack patterns need deterministic, reviewer-friendly detection. Without rules, training-independent signature coverage disappears.", "backend/app/detection/engine.py; backend/app/detection/rules/*.py"),
    ("AI anomaly detection", "Isolation Forest models eight source-IP features, requires at least five IP entities, versions artifacts, and turns anomalies into the same DetectionEvent shape as rules.", "It supplements signatures for unusual patterns. Without it, the application remains operational but cannot surface statistical outliers or AI metrics.", "backend/app/detection/ml/*.py; ml/models/registry_index.json"),
    ("Incidents", "Correlation reuses active incidents by entity plus threat key, accumulates evidence, escalates severity, and service code enforces a state machine with notes and assignment.", "It converts noisy technical findings into auditable analyst work. Without it, detections are isolated and there is no investigation workflow.", "backend/app/incidents/correlator.py; backend/app/incidents/service.py; backend/app/models/incident_schema.py"),
    ("Alerts", "High/critical detections create in-application Mongo Alert records. External dispatch is intentionally a future seam, represented by channel_dispatched rather than claimed as implemented.", "It provides urgency filtering. Without it, detections still exist, but critical alert count/feed disappears.", "backend/app/detection/alerting.py; backend/app/models/alert_schema.py"),
    ("Analytics", "Analytics safely combines ES telemetry aggregations with Mongo operational counts. ES failures return defaults so a partially unavailable search cluster does not crash the dashboard endpoint.", "It produces decision-ready measures. Without it, frontend charts/cards have no composed data source.", "backend/app/api/v1/analytics.py; backend/app/db/elastic.py; backend/app/db/mongo.py"),
    ("Elasticsearch", "Daily security-logs indices retain normalized evidence and support full-text raw-log search, filters, time queries, duplicate checks, and aggregations.", "Search-oriented, time-indexed telemetry needs different access patterns from user/incident documents. Without ES, ingestion and evidence monitoring fail.", "backend/app/db/elastic.py; elasticsearch/mappings/security_logs_mapping.json"),
    ("MongoDB", "Mongo holds users, workflow records, rule configuration, detections, alerts, and batch audit records with indexes for correctness/performance.", "It persists mutable application state and incident history. Without it, authentication, incident management, and dashboard counters fail.", "backend/app/db/mongo.py"),
    ("Docker", "Compose brings up Mongo, ES, optional Kibana, backend, and frontend with health checks, networks/hostnames, mounts, and persistent volumes.", "It makes a five-service demo reproducible. Without it, manual setup is possible but brittle.", "docker-compose.yml; backend/Dockerfile; frontend/Dockerfile"),
    ("React frontend", "Routes are protected by auth context; services isolate HTTP; page features render upload, monitoring, detection, anomaly, incident, rule, and analytics workflows.", "It makes the backend usable by an analyst and demonstrable in a viva. Without it, only Swagger/API tooling remains.", "frontend/src/routes/AppRouter.tsx; frontend/src/features/*; frontend/src/services/*"),
]


QA = [
    ("Why use both MongoDB and Elasticsearch?", "They have different responsibilities. Elasticsearch stores and searches time-oriented normalized raw logs in daily indices; MongoDB stores operational documents such as users, ingestion batches, detections, alerts, incidents, and rule state. Using one for both would either weaken evidence search or complicate mutable workflow data."),
    ("Explain the exact upload flow.", "The browser sends multipart data to POST /logs/upload. The API checks extension, size, and UTF-8. IngestionPipeline selects a source parser, creates ParsedEvent objects, normalizes them to NormalizedLog with deterministic IDs, checks ES for duplicates across daily indices, bulk indexes new logs, saves a Mongo ingestion batch, then invokes the post-ingest detection callback."),
    ("How is duplicate ingestion prevented?", "normalize.compute_log_id calculates SHA-256 from source type, source host, raw log text, and normalized timestamp. Pipeline queries security-logs-* for those IDs before bulk indexing. The cross-index search matters because the same log reuploaded on another day might otherwise target a different daily ES index."),
    ("Why are parser and normalizer separated?", "Parsers answer source-specific extraction questions; normalizer owns canonical schema mapping, UTC treatment, severity fallback, and ID construction. That single-responsibility boundary means adding a log source does not require modifying every detection consumer."),
    ("How does RBAC work?", "Login signs a JWT with username and role. Every protected endpoint runs get_current_user, which validates an access token then reloads the user from Mongo. require_role compares the current role with explicitly allowed roles; for example model training and rule updates are admin-only."),
    ("How do rules avoid one failure stopping all detection?", "RuleEngine.run wraps each enabled rule evaluation in its own try/except and logs a failure before continuing. The post-ingestion handler separately wraps ML prediction and incident correlation, so a trained-model or correlator issue does not erase successful rule detection or indexed evidence."),
    ("Give an example rule threshold.", "SSHBruteForceRule groups Linux failed_login records by source IP. It requires at least four attempts and expects a 120-second burst unless volume is at least double threshold; severity becomes critical at three times threshold. It records all evidence log IDs and MITRE T1110."),
    ("How is AI different from a rule here?", "Rules have coded predicates and thresholds, so they detect known behaviors transparently. The Isolation Forest learns a statistical boundary over eight per-IP features and flags outlier entities. Both emit DetectionEvent, so alerting and incident correlation do not care which engine originated the finding."),
    ("What are the ML features?", "failed_login_count, successful_login_count, total_event_count, distinct_event_types, distinct_dest_ports, distinct_dest_ips, average HTTP response size, and off-hours event ratio. Features are calculated per source IP, not per individual log."),
    ("What does ML risk percentage mean?", "It is not a globally calibrated probability. PredictionService min-max normalizes decision scores within the current scored batch, with lower Isolation Forest score becoming higher 0–100 risk. The correct viva answer is to state this limitation and describe fixed-reference calibration as a future improvement."),
    ("How are incidents correlated?", "The correlator derives an entity value and correlation key—usually the rule name, or ml_anomaly for ML—and looks for an OPEN or INVESTIGATING Mongo incident with the same pair. It adds unique detection/evidence IDs, updates timestamp, escalates severity if needed, or allocates a new INC- number atomically."),
    ("Why are incidents never deleted?", "The project preserves security audit integrity. Analysts transition OPEN to INVESTIGATING, RESOLVED, and CLOSED; each change records a note and actor. Deleting an incident would remove investigative evidence and weaken accountability."),
    ("What happens if ES is unavailable at startup?", "main.py logs the connection failure rather than immediately crashing the API, which helps Compose race conditions. Readiness reports degraded because it pings both Mongo and ES. Actual ingestion/search operations still require ES, so this is graceful startup visibility rather than a claim of offline ingestion."),
    ("What security limitations would you improve for production?", "Replace default JWT secret with secret management and key rotation, use HTTPS, add rate limiting and token revocation, reduce browser token exposure with hardened cookie/session design, validate file content beyond extension, add queue-based ingestion/training, enforce ES auth/TLS, and use background workers plus monitoring."),
    ("Why use Docker Compose?", "Compose provides a repeatable topology with health-gated Mongo/ES dependencies, named persistent volumes, mounts for model artifacts/datasets/log fixtures, service hostnames, and fixed demo ports. It prevents environment mismatch during a viva."),
    ("Which parser supports exported Windows data?", "WindowsEventLogParser in ingestion/parsers/windows_parser.py accepts JSON arrays, a JSON object, and NDJSON. It maps selected Security Event IDs but does not parse binary .evtx files."),
    ("What exactly does the Linux parser ignore?", "LinuxAuthLogParser only handles sshd failed/accepted-password and sudo patterns. Other syslog lines are intentionally skipped so an unrelated subsystem does not become a parser failure."),
    ("Why does the web parser not flag SQL injection itself?", "WebServerLogParser extracts the Combined Log Format path and evidence. SQLInjectionRule performs the policy decision later, preserving parser/detection separation and independent tuning."),
    ("What makes an alert?", "generate_alerts in detection/alerting.py persists AlertInDB records only for high or critical DetectionEvents. Low and medium detections remain stored detections without an alert."),
    ("Does this system send email or Telegram alerts?", "No. alerting.py creates in-application Mongo alerts. Its comments identify external dispatch as out of scope, and the alerts/ dispatcher area should not be presented as implemented."),
    ("What is the incident status machine?", "incidents/service.py allows OPEN to INVESTIGATING, RESOLVED, or CLOSED; INVESTIGATING to RESOLVED, CLOSED, or OPEN; RESOLVED to CLOSED or INVESTIGATING; CLOSED has no outgoing transition."),
    ("What occurs when an analyst assigns an open incident?", "assign_analyst writes assigned_to, adds an audit note, and automatically changes OPEN to INVESTIGATING. It leaves other current statuses unchanged."),
    ("How is incident severity escalated?", "correlator._upsert_for_detection compares ranks low/medium/high/critical. A higher related detection updates the active incident and appends a system investigation note."),
    ("What does IsolationForestModel contribute?", "IsolationForestModel is the concrete AnomalyModel implementation fitted by TrainingService. It is an unsupervised outlier detector, so it complements explicit rule predicates rather than replacing them."),
    ("How is a trained model versioned?", "ModelRegistry.register_model writes a new isolation_forest_vN.joblib artifact and appends metadata to registry_index.json. Retraining does not overwrite the currently saved version."),
    ("Why are five entities required for training?", "TrainingService rejects fewer than MIN_TRAINING_SAMPLES=5 distinct source IPs because a model trained on only a few entities has an unhelpful notion of normality."),
    ("What happens when no ML model is trained?", "PredictionService.predict returns an empty list and logs a warning. This means automatic ingestion still runs rules and indexing successfully."),
    ("What is the frontend authentication chain?", "LoginPage calls AuthContext, AuthContext calls authService, the shared Axios client stores/attaches tokens, and a single refresh-in-flight path calls /auth/refresh on a 401 before one retry."),
    ("Which data belongs in Mongo versus Elasticsearch?", "Mongo holds users, detections, alerts, incidents, ingestion_batches, detection_rules, counters and operational documents. ES holds time-oriented normalized log evidence in security-logs-YYYY.MM.DD searched as security-logs-*."),
    ("How can a manual rule run differ from upload?", "POST /api/v1/detections/run is an explicit controller action over retrieved logs. The normal upload path calls IngestionPipeline.process and then automatically reaches handle_ingested_logs for fresh indexed records."),
]

# Full-page source dossiers.  The generic ten-question layout is deliberate:
# it lets a student rehearse the same rigorous explanation for each concrete
# parser and rule without pretending that unsupported modules exist.
PARSER_DOSSIERS = [
    ("WindowsEventLogParser", "backend/app/ingestion/parsers/windows_parser.py", "Windows Security exports as a JSON array, object, or Winlogbeat-style NDJSON.", "parse → _load_records → _parse_record → _parse_timestamp. It maps 4624/4625/4672/4720/4728 to successful_login, failed_login, privileged_logon, account_created, and group_membership_added; unknown IDs become windows_event.", "WindowsFailedLoginRule and PrivilegeEscalationRule consume the normalized event types.", "TargetUserName, IpAddress and TimeCreated become user, source_ip and timestamp; remaining fields and event_id remain parsed_fields.", "This is JSON-export ingestion, not a binary EVTX reader. Invalid NDJSON lines are skipped; entirely unparseable content raises LogParsingError.", "Windows records → ParsedEvent → normalize → NormalizedLog → ES security-logs-YYYY.MM.DD.", "PARSER_REGISTRY selects it for SourceType.WINDOWS. It extracts evidence only; it does not declare an attack."),
    ("LinuxAuthLogParser", "backend/app/ingestion/parsers/linux_parser.py", "Linux auth.log/syslog lines for sshd failed/accepted passwords and sudo.", "parse → _parse_line → _build_login_event or _build_sudo_event. It yields failed_login, successful_login, or privilege_command and records host/port or target_user/command.", "SSHBruteForceRule, PrivilegeEscalationRule, and SuspiciousAdminLoginRule consume these event types.", "The syslog timestamp has no year, so _parse_syslog_timestamp assumes the current UTC year; normalize then supplies canonical UTC.", "It intentionally ignores unrelated syslog services; this is an auth parser, not a complete Linux logging parser.", "Raw lines → ParsedEvent → normalize → ES, detection, ML features.", "SSH detection is four failures in 120 seconds. Parser severity hints describe records, while rules produce verdict severity."),
    ("FirewallLogParser", "backend/app/ingestion/parsers/firewall_parser.py", "Project ALLOW/DENY connection lines with source/destination address and port.", "A compiled _FIREWALL_LINE_RE extracts timestamp, action, protocol, addresses, ports and flags. DENY maps to connection_denied; ALLOW maps to connection_allowed.", "PortScanRule consumes denied records with source_ip, dest_ip and dest_port.", "protocol, src_port, action and flags stay in parsed_fields; dest_port is promoted to NormalizedLog.", "It is a sample-format adapter, not a universal pfSense/Cisco/iptables parser.", "Connection text → ParsedEvent → normalize → ES → PortScanRule.", "The parser does not call a denial malicious; scanning policy is in PortScanRule."),
    ("WebServerLogParser", "backend/app/ingestion/parsers/web_parser.py", "Apache/Nginx Combined Log Format access lines.", "parse applies _COMBINED_LOG_RE, parses %d/%b/%Y:%H:%M:%S %z, and emits http_request records with method/path/status/response size/referrer/user-agent.", "SQLInjectionRule, XSSRule, DirectoryTraversalRule, and ML avg_response_size_bytes feature extraction.", "IP is source_ip; path and response_size_bytes are retained in parsed_fields for downstream use.", "Malformed Combined-format lines are skipped; custom JSON access logs require another adapter.", "Access line → ParsedEvent → normalize → ES → payload rules/ML.", "It does extraction only. SQLi/XSS/traversal classification is deliberately deferred to detection rules."),
]

RULE_DOSSIERS = [
    ("SSHBruteForceRule", "backend/app/detection/rules/ssh_brute_force.py", "Linux failed_login records grouped by source IP.", "DEFAULT_THRESHOLD=4 and DEFAULT_WINDOW_SECONDS=120; group_by_source_ip and window_seconds permit a longer window only at double volume.", "RuleEngine.run returns its DetectionEvent to handle_ingested_logs.", "T1110; confidence rises from 0.5, severity is HIGH or CRITICAL at three times threshold, and all group log IDs are evidence.", "It sees Linux failed_login only; it does not prove compromise.", "Normalized logs → RuleEngine.run → Mongo detections → generate_alerts → correlate_detections.", "RuleConfig may tune threshold/window; without it Linux failures remain searchable but produce no brute-force detection."),
    ("WindowsFailedLoginRule", "backend/app/detection/rules/windows_failed_login.py", "Windows failed_login (mapped Event ID 4625) grouped by source IP.", "Threshold 3 and 120-second configuration; targets and observed span are described in its event.", "RuleEngine.run invokes it after enabled checking.", "T1110.001; HIGH normally and CRITICAL at triple threshold; evidence IDs are preserved.", "It is deliberately separate from SSH because Windows tuning/semantics differ.", "Normalized Windows logs → engine → shared detection/alert/incident flow.", "It is behavioral evidence, not a parser claim that every 4625 is malicious."),
    ("PortScanRule", "backend/app/detection/rules/port_scan.py", "Denied firewall connections having source IP, destination IP, and destination port.", "Groups by (source_ip, dest_ip), counts distinct ports, applies threshold 5 and 60-second window.", "RuleEngine.run; no route or database is accessed directly by the rule.", "T1046; MEDIUM becomes HIGH at double threshold; explanation lists scanned ports and span.", "Only connection_denied firewall records qualify.", "Normalized firewall evidence → engine → Mongo detections/alerts/incidents.", "It signals reconnaissance consistent with scanning, not demonstrated service compromise."),
    ("SQLInjectionRule", "backend/app/detection/rules/sql_injection.py", "Web parsed_fields.path or raw_log.", "find_matching_pattern searches tautologies, UNION SELECT, comments, stacked writes, SLEEP and information_schema.", "RuleEngine.run and the shared post-ingest handler.", "T1190; confidence .75, UNION is CRITICAL and other signatures HIGH.", "It evaluates web records only and is evadable by novel obfuscation.", "Web log → normalized path → rule → DetectionEvent with one evidence ID.", "It records a finding; it does not block requests or dispatch external alerts."),
    ("XSSRule", "backend/app/detection/rules/xss.py", "Web request paths/query strings.", "find_matching_pattern checks script tags, event-handler injection, javascript URIs, image tags, document cookie/location and iframe.", "RuleEngine.run.", "T1059.007; confidence .7, MEDIUM, source IP and matching evidence ID.", "It is a transparent signature detector, not a complete browser exploit analysis.", "Web evidence → normalized path → XSS DetectionEvent.", "Removing it preserves logs but removes explicit XSS detections."),
    ("DirectoryTraversalRule", "backend/app/detection/rules/directory_traversal.py", "Web request paths.", "Matches repeated ../, encoded traversal, and sensitive targets including etc/passwd, boot.ini, win.ini and system32.", "RuleEngine.run.", "T1083; confidence .8, HIGH severity, one evidence log ID.", "It detects attempted traversal, not confirmed file disclosure.", "Web evidence → normalized path → traversal DetectionEvent.", "There is no threshold because this is a per-request signature."),
    ("PrivilegeEscalationRule", "backend/app/detection/rules/privilege_escalation.py", "Linux privilege_command and Windows account_created/group_membership_added records.", "evaluate dispatches to _evaluate_linux_sudo or _evaluate_windows_event; Linux requires target_user root.", "RuleEngine.run.", "T1548; root sudo MEDIUM/.55, Windows account creation MEDIUM, group membership HIGH/.6.", "Root sudo may be valid maintenance and the explanation explicitly asks for contextual review.", "OS evidence → rule → user-entity DetectionEvent.", "The code makes no automatic remediation decision."),
    ("SuspiciousAdminLoginRule", "backend/app/detection/rules/suspicious_admin_login.py", "Successful Linux/Windows logins for root, admin, administrator, or configured equivalents.", "Checks privileged_accounts and 06:00–22:00 UTC defaults against timestamp hour.", "RuleEngine.run.", "T1078; MEDIUM/.4 and explanation explicitly calls it a low-confidence signal.", "It only qualifies off-hours successful logins for named privileged accounts.", "Normalized auth evidence → rule → user-entity DetectionEvent.", "RuleConfig can tune accounts/hours; corroborate rather than treating it as proof."),
]

API_DOSSIERS = [
    ("Authentication", "backend/app/api/v1/auth.py", "POST /api/v1/auth/login; POST /api/v1/auth/refresh; POST /api/v1/auth/register; GET /api/v1/auth/me.", "login uses get_user_by_username, verify_password, create_access_token, create_refresh_token and update_last_login; register is admin-gated.", "users collection; no ES responsibility."),
    ("Logs", "backend/app/api/v1/logs.py", "POST /api/v1/logs/upload; POST /api/v1/logs/ingest; GET /api/v1/logs/search; GET /api/v1/logs/batches.", "upload/ingest call default_pipeline.process; search queries ES; batches reads Mongo audit data.", "security-logs-* evidence and ingestion_batches audit documents."),
    ("Detections", "backend/app/api/v1/detections.py", "GET /api/v1/detections; GET /api/v1/detections/alerts; GET /api/v1/detections/rules; POST /api/v1/detections/run.", "Lists persisted results, exposes rules, and supports a manual detection run in addition to automatic ingestion callback detection.", "detections and alerts collections, linked ES evidence IDs."),
    ("ML", "backend/app/api/v1/ml.py", "POST /api/v1/ml/train; POST /api/v1/ml/predict; GET /api/v1/ml/models; GET /api/v1/ml/models/latest; POST /api/v1/ml/evaluate.", "Uses TrainingService, PredictionService and ModelRegistry; train/evaluate are privileged operations.", "ES history, filesystem model artifacts/registry_index.json, then Mongo detection workflow."),
    ("Incidents", "backend/app/api/v1/incidents.py", "GET /api/v1/incidents; GET /api/v1/incidents/{incident_ref}; PATCH /api/v1/incidents/{incident_ref}/status; POST /api/v1/incidents/{incident_ref}/notes; PATCH /api/v1/incidents/{incident_ref}/assign.", "Delegates to incidents/service.py, which validates transitions and writes actor-attributed notes.", "incidents and counters."),
    ("Analytics", "backend/app/api/v1/analytics.py", "GET /api/v1/analytics/summary, /top-ips, /severity-distribution, /threat-timeline, /attack-types, /recent-events.", "Composes dashboard-shaped data for DashboardPage and AnalyticsPage.", "ES telemetry aggregations plus Mongo operational counts."),
    ("Rules", "backend/app/api/v1/rules.py", "GET /api/v1/rules; PATCH /api/v1/rules/{rule_name}.", "Exposes and updates active/persisted detection policy; changes require admin protection.", "detection_rules collection and RuleEngine instances."),
]

FRONTEND_DOSSIERS = [
    ("AuthContext", "frontend/src/features/auth/context/AuthContext.tsx", "Owns session/user state and delegates credentials to authService; token storage/client refresh are centralized rather than reimplemented per page."),
    ("AppRouter", "frontend/src/routes/AppRouter.tsx", "Maps protected UI routes and route guards to the application feature pages."),
    ("DashboardPage", "frontend/src/features/dashboard/pages/DashboardPage.tsx", "Uses analyticsService to render summary, trend, severity, attack, IP and recent-event views."),
    ("UploadLogsPage", "frontend/src/features/logs/pages/UploadLogsPage.tsx", "Uses logService to submit source/file metadata and display pipeline counts/batch results."),
    ("LiveMonitoringPage", "frontend/src/features/monitoring/pages/LiveMonitoringPage.tsx", "Uses logService search to investigate normalized, ES-backed evidence."),
    ("ThreatDetectionPage", "frontend/src/features/detections/pages/ThreatDetectionPage.tsx", "Uses detectionService for detections, alerts, rule metadata and manual run actions."),
    ("AnomalyDetectionPage", "frontend/src/features/anomalies/pages/AnomalyDetectionPage.tsx", "Uses ML-facing services for training, prediction, versions and evaluation."),
    ("IncidentManagementPage", "frontend/src/features/incidents/pages/IncidentManagementPage.tsx", "Uses incidentService for filtering, transitions, notes and assignment."),
    ("AnalyticsPage", "frontend/src/features/analytics/pages/AnalyticsPage.tsx", "Uses analyticsService for deeper API-backed aggregation views."),
    ("DetectionRulesPage", "frontend/src/features/rules/pages/DetectionRulesPage.tsx", "Uses ruleService for inspection/administration of rule policy."),
    ("SettingsPage and UserManagementPage", "frontend/src/features/settings/pages/SettingsPage.tsx; frontend/src/features/users/pages/UserManagementPage.tsx", "Remaining routed UI surfaces that should be acknowledged in a complete frontend walkthrough."),
]


def add_ten_question_dossier(story, title, filename, enters, mechanics, downstream, leaves, boundary, flow, policy):
    story.append(P(title, H2))
    story.append(code(filename))
    story.append(answer_table([
        ("1. What is this?", f"<b>{escape(title)}</b> is a concrete implementation unit in {path(filename)}."),
        ("2. Why does it exist?", "It keeps this responsibility separate from HTTP controllers, storage repositories, and presentation code."),
        ("3. What enters?", enters),
        ("4. How does it work?", mechanics),
        ("5. What uses it?", downstream),
        ("6. What leaves?", leaves),
        ("7. What boundary matters?", boundary),
        ("8. Where in the call chain?", flow),
        ("9. What must you say in a viva?", policy),
        ("10. What breaks if removed?", "The surrounding platform may still store raw evidence, but this specific transformation or detection is no longer available." ),
    ]))


def build_pdf():
    DOCS_PDF.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(DOCS_PDF), pagesize=A4, rightMargin=1.7 * cm, leftMargin=1.7 * cm,
        topMargin=1.65 * cm, bottomMargin=1.75 * cm, title="PROJECT DEVELOPER VIVA GUIDE",
        author="Cyber Threat Detection Project", pageCompression=0,
    )
    story = []
    story.extend([
        Spacer(1, 4.2 * cm),
        P("PROJECT DEVELOPER &amp; VIVA GUIDE", TITLE),
        P("Cyber Threat Detection and Incident Response Dashboard", SUBTITLE),
        Spacer(1, 0.7 * cm),
        P("A codebase-grounded academic guide for development, demonstration, architecture explanation, and viva preparation.", SUBTITLE),
        Spacer(1, 1.1 * cm),
        code("Repository analysed: cyber-threat-dashboard-full/cyber-threat-dashboard"),
        P("Scope: FastAPI • React TypeScript • MongoDB • Elasticsearch • Docker Compose • rule-based detection • Isolation Forest anomaly detection", SUBTITLE),
        Spacer(1, 2.5 * cm),
        P("Prepared from the implementation files in this repository. It distinguishes implemented behavior from future extension points.", SUBTITLE),
        PageBreak(),
    ])
    section(story, "1", "Table of Contents")
    toc = [
        "1. Table of Contents",
        "2. Part A — Module-by-module developer guide",
        "3. Part B — Complete end-to-end workflow",
        "4. Part C — Feature deep-dives",
        "5. Part D — Viva learning guide",
        "6. Appendix — API map, data stores, and demo checklist",
    ]
    story.extend(bullets(toc))
    story.append(P("Reading note: file paths and function/API names are styled in monospaced type throughout. MongoDB collection and Elasticsearch index names are deliberately identified separately because they serve different responsibilities.", BODY))
    story.append(PageBreak())

    section(story, "2", "Part A — Module-by-module developer guide",
            "Every module below answers the ten requested developer questions using the actual project structure and implementation behavior.")
    for i, module in enumerate(MODULES, start=1):
        add_module(story, i, module)
        if i in {4, 8, 12, 16}:
            story.append(PageBreak())

    story.append(PageBreak())
    section(story, "3", "Part B — Complete end-to-end workflow",
            "This traces the implemented route from an authenticated analyst to dashboard analytics, including functions, storage operations, routes, and frontend response shapes.")
    workflow_steps(story)
    story.append(P("End-to-end flow in one line:", H2))
    story.append(code("Login → JWT → Upload → Parser → Normalize → ES → RuleEngine + AI → Mongo detections/alerts → Correlate incidents → Dashboard/Analytics"))

    story.append(PageBreak())
    section(story, "4", "Part C — Feature deep-dives",
            "Use these as standalone explanations during a code walkthrough. Each entry states purpose, problem/importance, what breaks without it, and the exact implementation files.")
    for index, (name, how, importance, files) in enumerate(FEATURES, start=1):
        sub(story, f"4.{index}", name)
        story.append(answer_table([
            ("How in this project", how),
            ("Why / problem / importance / without it", importance),
            ("Files to cite", path(files)),
        ]))

    story.append(PageBreak())
    section(story, "5", "Part C.1 — Parser dossiers",
            "Each parser is documented with the same ten-question developer template. These describe implemented source adapters, not generic log-parser claims.")
    for dossier in PARSER_DOSSIERS:
        add_ten_question_dossier(story, *dossier)
        story.append(PageBreak())

    section(story, "6", "Part C.2 — Detection-rule dossiers",
            "Each of the eight registered rule classes receives its own implementation-grounded explanation. Rule evaluation is invoked through RuleEngine.run, never directly by the frontend.")
    for dossier in RULE_DOSSIERS:
        add_ten_question_dossier(story, *dossier)
        story.append(PageBreak())

    section(story, "7", "Part C.3 — Complete API and frontend walkthrough",
            "The following pages name every backend router route and every routed feature page. They make the REST-to-React contract explicit.")
    for name, filename, routes, behavior, stores in API_DOSSIERS:
        add_ten_question_dossier(
            story, f"API router: {name}", filename, routes, behavior,
            "The corresponding frontend service and authenticated FastAPI router callers.",
            "Validated JSON / response models or HTTP error responses.", "The router is HTTP orchestration; business work stays in services/pipeline.",
            f"/api/v1 → {filename} → service/repository → response.", f"Storage responsibility: {stores}",
        )
        story.append(PageBreak())

    for name, filename, behavior in FRONTEND_DOSSIERS:
        add_ten_question_dossier(
            story, f"Frontend: {name}", filename, "User interaction, route state, and typed service/API data.", behavior,
            "React route layout, AuthContext, and the named frontend service layer.",
            "Rendered controls, tables, charts, upload feedback, or analyst workflow state.",
            "This code never accesses MongoDB or Elasticsearch directly; it uses authenticated REST services.",
            f"AppRouter → {name} → authService/logService/detectionService/incidentService/analyticsService/ruleService as applicable → /api/v1.",
            "The exact matching service depends on the page; keep token refresh and RBAC on the shared client/backend boundary.",
        )
        story.append(PageBreak())

    section(story, "5", "Part D — Viva learning guide")
    sub(story, "5.1", "Beginner explanation")
    story.append(P("This project is a lightweight SIEM-style platform. A user logs in, uploads security logs from Linux, Windows, a firewall, or a web server, and the backend converts unlike source formats into one normalized record. Elasticsearch keeps the searchable raw evidence. Detection rules and an optional AI model turn suspicious behavior into findings. High-severity findings create alerts, related findings become incidents, and the React dashboard presents the operational picture. MongoDB stores the users and the workflow/history data."))
    sub(story, "5.2", "Intermediate explanation")
    story.append(P("The design uses boundaries. FastAPI routers handle HTTP and authorization; the pipeline orchestrates ingestion; parser strategies handle source formats; the normalizer enforces the canonical contract; repositories isolate ES and Mongo; BaseRule and AnomalyModel make detection extensible; the correlator turns events into analyst work. This reduces coupling: adding a parser or rule should not require rewriting controllers, dashboards, or incident logic."))
    sub(story, "5.3", "Technical explanation")
    story.append(P("At startup, lifespan connects Motor, ensures unique/query indexes, connects AsyncElasticsearch/template, restores persisted rule enabled state, and injects the async post-ingest callback. Deterministic SHA-256 IDs plus cross-daily-index ES search implement idempotence. The callback applies fault isolation: rule failures are isolated per rule; ML failure is caught separately; correlation failure cannot roll back indexed logs. ML trains an IsolationForest on a per-IP feature matrix and persists versioned joblib artifacts with JSON metadata."))
    sub(story, "5.4", "How to present each module")
    story.extend(bullets([
        "Start at main.py: explain lifecycle, router mounting, callback wiring, then move inward.",
        "For auth, show login → JWT claims → Axios Bearer interceptor → get_current_user/RBAC.",
        "For ingestion, emphasize the deliberate parser / normalizer / pipeline separation and deterministic IDs.",
        "For data stores, say ES is evidence/search/aggregation; Mongo is identity/workflow/config/audit.",
        "For detection, show a concrete Linux SSH or web SQLi example and name the emitted DetectionEvent fields.",
        "For AI, explain it as a complementary outlier detector, state the eight features, five-entity minimum, version registry, and batch-relative risk limitation honestly.",
        "For incidents, demonstrate correlation key + entity grouping and the no-delete state machine.",
        "For UI, show service layer and dashboard React Query refresh rather than describing React only in general terms.",
    ]))
    sub(story, "5.5", "What to say during the demo")
    story.extend(bullets([
        "Open the dashboard and explain that cards and charts are fed by /analytics endpoints combining ES and Mongo—not hard-coded UI numbers.",
        "Log in with the seeded admin only in a controlled demo; state that default credentials must be changed in any shared deployment.",
        "Upload sample_logs/linux_auth.log as linux. Point out accepted/duplicate counts and the ingestion batch audit trail.",
        "Open Threat Detection or Dashboard recent events. Explain SSHBruteForceRule grouping by source IP and the MITRE T1110 mapping.",
        "Open Incidents. Show INC reference, evidence log IDs, assignment, a note, and a legal status transition.",
        "Upload web_access.log as web_server and explain SQL injection, XSS, and traversal are detected after parsing, not classified by the parser.",
        "Optionally train/predict only after enough distinct IPs exist. Explain no trained model means automatic ML scoring safely returns no result rather than failing ingestion.",
        "End at Docker Compose: demonstrate that Mongo and Elasticsearch have persistent volumes and backend waits for health checks.",
    ]))
    sub(story, "5.6", "Most important parts to understand")
    story.extend(bullets([
        "The complete ingestion chain and deterministic deduplication.",
        "Why the two databases have different roles.",
        "The DetectionEvent contract unifies rule and ML outputs.",
        "RBAC and the frontend token refresh path.",
        "Correlation keys, atomic incident sequence, severity escalation, and status transition rules.",
        "The ML model's honest scope: Isolation Forest is unsupervised, risk is batch-relative, and evaluation uses labeled synthetic data.",
    ]))
    sub(story, "5.7", "Files to study first, in order")
    study = [
        ("backend/app/main.py", "The composition root reveals runtime lifecycle, router map, and ingestion-to-detection wiring."),
        ("backend/app/ingestion/pipeline.py", "It is the central operational flow from upload to indexed/audited/detected data."),
        ("backend/app/ingestion/normalizer.py and models/log_schema.py", "They define the canonical data contract and idempotent log ID."),
        ("backend/app/db/elastic.py and db/mongo.py", "They explain the split storage architecture and exact collections/indices."),
        ("backend/app/detection/engine.py and rules/base_rule.py", "They explain pluggable, fault-isolated rule execution."),
        ("One threshold rule and one web rule", "Study ssh_brute_force.py and sql_injection.py to present both behavioral and signature styles."),
        ("backend/app/detection/ml/feature_extraction.py, training_service.py, prediction_service.py", "These are the technical AI story: features, fit, versioning, scoring, limitations."),
        ("backend/app/incidents/correlator.py and service.py", "They show how detections become managed SOC cases."),
        ("backend/app/api/v1/auth.py and core/security.py/dependencies.py", "They demonstrate authentication, JWT, and RBAC."),
        ("frontend/src/api/client.ts, services/analyticsService.ts, features/dashboard/pages/DashboardPage.tsx", "They demonstrate real frontend-to-backend integration and live rendering."),
        ("docker-compose.yml", "It closes the demo with operational reproducibility."),
    ]
    story.append(answer_table([(f"{i}. {f}", r) for i, (f, r) in enumerate(study, start=1)]))
    sub(story, "5.8", "Expected viva questions and strong answers")
    for i, (question, answer) in enumerate(QA, start=1):
        story.append(KeepTogether([P(f"Q{i}. {escape(question)}", H3), P(f"<b>Strong answer:</b> {escape(answer)}")]))

    story.append(PageBreak())
    section(story, "6", "Appendix — API map, data stores, and demo checklist")
    sub(story, "6.1", "API map")
    story.append(answer_table([
        ("Authentication", "POST /api/v1/auth/login; POST /auth/refresh; POST /auth/register (admin); GET /auth/me"),
        ("Logs", "POST /api/v1/logs/upload; POST /logs/ingest; GET /logs/search; GET /logs/batches"),
        ("Detection and alerts", "GET /api/v1/detections; GET /detections/alerts; GET /detections/rules; POST /detections/run"),
        ("ML", "POST /api/v1/ml/train (admin); POST /ml/predict; GET /ml/models; GET /ml/models/latest; POST /ml/evaluate (admin)"),
        ("Incidents", "GET /api/v1/incidents; GET /incidents/{ref}; PATCH status; POST notes; PATCH assign"),
        ("Analytics", "GET /api/v1/analytics/summary, /top-ips, /severity-distribution, /threat-timeline, /attack-types, /recent-events"),
        ("Rule administration", "GET /api/v1/rules; PATCH /rules/{rule_name} (admin)"),
    ]))
    sub(story, "6.2", "Data-store map")
    story.append(answer_table([
        ("MongoDB", "users, incidents, detection_rules, system_config, ingestion_batches, detections, alerts, counters"),
        ("Elasticsearch", "security-logs-YYYY.MM.DD daily normalized evidence indices queried via security-logs-*"),
        ("Filesystem artifacts", "ml/models/isolation_forest_vN.joblib plus ml/models/registry_index.json; mounted into backend by Compose"),
    ]))
    sub(story, "6.3", "Pre-viva verification checklist")
    story.extend(bullets([
        "Run docker compose up -d --build and confirm backend, frontend, Mongo, and Elasticsearch are healthy.",
        "Call /health and /health/ready; explain liveness versus downstream readiness.",
        "Seed the admin and demo data only if your environment requires it, then change default passwords for shared use.",
        "Prepare each sample source: linux_auth.log, windows_sample.json, firewall_sample.log, web_access.log.",
        "Know one implemented limitation and one future improvement; never claim external alerts, full EVTX binary support, or globally calibrated ML probability when the code does not implement them.",
    ]))
    story.append(Spacer(1, 8))
    story.append(P("End of developer and viva guide.", SUBTITLE))
    doc.build(story, onFirstPage=page_number, onLaterPages=page_number)
    shutil.copy2(DOCS_PDF, ROOT_PDF)
    raw = DOCS_PDF.read_bytes()
    pages = len(re.findall(rb"/Type\s*/Page(?!s)", raw))
    print(f"PDF: {DOCS_PDF} | {DOCS_PDF.stat().st_size:,} bytes | approximately {pages} pages")
    print(f"PDF: {ROOT_PDF} | {ROOT_PDF.stat().st_size:,} bytes | approximately {pages} pages")


if __name__ == "__main__":
    build_pdf()
