#!/usr/bin/env python3
"""
Build final-year project PPTX from college Seminar template.
Preserves theme, logo, fonts, and slide chrome; replaces placeholder text.
"""
from __future__ import annotations

import copy
import shutil
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE, MSO_SHAPE_TYPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn
from pptx.util import Emu, Pt

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "Seminar Ppt .pptx"
OUTPUT = ROOT / "Cyber_Threat_Detection_Incident_Response_Dashboard.pptx"

STUDENT = "RAHUL SWAMI"
ROLL = "22EARCS137"
GUIDE = "DR. VISHAL SHIRVASTAVA"
GUIDE_DESIGNATION = "PROFESSOR"
PROJECT = "Cyber Threat Detection and Incident Response Dashboard"
DEPT = "[Department Name]"
COLLEGE = "[College Name]"
YEAR = "[Academic Year]"

ACCENT = RGBColor(0x1F, 0x4E, 0x79)
PLACEHOLDER_BG = RGBColor(0xE7, 0xEE, 0xF5)
PLACEHOLDER_FG = RGBColor(0x5B, 0x64, 0x78)
BOX_FILL = RGBColor(0xF5, 0xF8, 0xFB)
BOX_LINE = RGBColor(0x1F, 0x4E, 0x79)

CONTENT_TEMPLATE_INDEX = 3  # Introduction slide: logo + title + large body


def set_shape_text(shape, lines: list[str], *, bold_first: bool = False, font_size: int = 14) -> None:
    if not shape.has_text_frame:
        return
    tf = shape.text_frame
    tf.clear()
    tf.word_wrap = True
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.level = 0
        if not p.runs:
            continue
        run = p.runs[0]
        run.font.size = Pt(18 if (bold_first and i == 0) else font_size)
        if bold_first and i == 0:
            run.font.bold = True


def find_title_shape(slide):
    candidates = []
    for shape in slide.shapes:
        if not shape.has_text_frame:
            continue
        if "Placeholder" in shape.name or "Slide Number" in shape.name:
            continue
        if shape.shape_type == MSO_SHAPE_TYPE.PICTURE:
            continue
        top = shape.top or 0
        height = shape.height or 0
        # Title bars in this template sit near top and are relatively short
        if top < Emu(1_500_000) and height < Emu(1_200_000) and (shape.width or 0) > Emu(2_500_000):
            candidates.append((top, -(shape.width or 0), shape))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][2]


def find_body_shape(slide, title_shape):
    best = None
    best_area = 0
    for shape in slide.shapes:
        if shape is title_shape:
            continue
        if not shape.has_text_frame:
            continue
        if "Placeholder" in shape.name or "Slide Number" in shape.name:
            continue
        if shape.shape_type == MSO_SHAPE_TYPE.PICTURE:
            continue
        top = shape.top or 0
        if top < Emu(1_400_000):
            continue
        area = (shape.width or 0) * (shape.height or 0)
        if area > best_area:
            best_area = area
            best = shape
    return best


def set_notes(slide, text: str) -> None:
    slide.notes_slide.notes_text_frame.text = text


def duplicate_slide(prs: Presentation, index: int):
    source = prs.slides[index]
    new_slide = prs.slides.add_slide(source.slide_layout)
    sp_tree = new_slide.shapes._spTree
    for child in list(sp_tree):
        tag = child.tag
        if tag.endswith("}sp") or tag.endswith("}pic") or tag.endswith("}grpSp") or tag.endswith("}cxnSp"):
            sp_tree.remove(child)

    source_part = source.part
    new_part = new_slide.part
    for shape in source.shapes:
        el = copy.deepcopy(shape.element)
        for blip in el.findall(".//" + qn("a:blip")):
            embed = blip.get(qn("r:embed"))
            if not embed:
                continue
            try:
                image_part = source_part.related_parts[embed]
                # python-pptx: get_or_add_image_part
                _, new_rid = new_part.get_or_add_image(image_part.blob)
                blip.set(qn("r:embed"), new_rid)
            except Exception:
                try:
                    image_part = source_part.related_parts[embed]
                    new_rid = new_part.relate_to(image_part, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image")
                    blip.set(qn("r:embed"), new_rid)
                except Exception:
                    pass
        sp_tree.insert_element_before(el, "p:extLst")
    return new_slide


def delete_slide(prs: Presentation, index: int) -> None:
    sldIdLst = prs.slides._sldIdLst
    sldId = sldIdLst[index]
    rId = sldId.get(qn("r:id"))
    sldIdLst.remove(sldId)
    try:
        prs.part.drop_rel(rId)
    except Exception:
        pass


def add_placeholder_box(slide, left, top, width, height, label: str):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = PLACEHOLDER_BG
    shape.line.color.rgb = ACCENT
    tf = shape.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    try:
        shape.text_frame.auto_size = None
    except Exception:
        pass
    p = tf.paragraphs[0]
    p.text = label
    if p.runs:
        p.runs[0].font.size = Pt(13)
        p.runs[0].font.color.rgb = PLACEHOLDER_FG
        p.runs[0].font.italic = True
    return shape


def add_flow_boxes(slide, labels: list[str], top=Emu(5_350_000)):
    n = len(labels)
    margin_l = Emu(600_000)
    slide_w = 12192000
    gap = Emu(80_000)
    arrow_w = Emu(150_000)
    usable = slide_w - 2 * margin_l
    box_w = int((usable - (n - 1) * (gap + arrow_w)) / n)
    box_h = Emu(720_000)
    x = margin_l
    for i, label in enumerate(labels):
        box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, top, box_w, box_h)
        box.fill.solid()
        box.fill.fore_color.rgb = BOX_FILL
        box.line.color.rgb = BOX_LINE
        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = label
        p.alignment = PP_ALIGN.CENTER
        if p.runs:
            p.runs[0].font.size = Pt(10)
            p.runs[0].font.bold = True
            p.runs[0].font.color.rgb = ACCENT
        x += box_w
        if i < n - 1:
            arr = slide.shapes.add_shape(
                MSO_SHAPE.RIGHT_ARROW, x + gap // 2, top + box_h // 3, arrow_w, box_h // 3
            )
            arr.fill.solid()
            arr.fill.fore_color.rgb = ACCENT
            arr.line.fill.background()
            x += gap + arrow_w


SLIDES = [
    {
        "title": "Title",
        "kind": "title",
        "notes": (
            "Introduce yourself, roll number, and project title. "
            "This is a B.Tech final-year SIEM-style dashboard for cyber threat detection "
            "and incident response. Thank the guide."
        ),
    },
    {
        "title": "Problem Statement",
        "bullets": [
            "Organizations generate high volumes of security logs from heterogeneous sources.",
            "Manual log review cannot keep pace with modern attack speed and scale.",
            "Threat signals are scattered across Windows, Linux, firewall, and web logs.",
            "Delayed detection increases dwell time and incident impact.",
            "SOC teams need a unified dashboard for detection, triage, and response.",
        ],
        "notes": "State the core problem: fragmented logs and slow manual analysis.",
    },
    {
        "title": "Motivation",
        "bullets": [
            "Rising frequency of brute-force, web attacks, and anomalous behavior.",
            "Need for an affordable, demonstrable SIEM-like academic platform.",
            "Combine deterministic rules with AI anomaly detection for better coverage.",
            "Enable end-to-end workflow: ingest, detect, correlate, respond.",
            "Provide mentor-ready demo with Dockerized deployment.",
        ],
        "notes": "Explain dual engines: rules for known threats, ML for unknowns.",
    },
    {
        "title": "Objectives",
        "bullets": [
            "Build a modular log ingestion and normalization pipeline.",
            "Implement rule-based detection mapped to MITRE ATT&CK techniques.",
            "Train Isolation Forest model for AI anomaly scoring.",
            "Correlate detections into actionable SOC incidents.",
            "Deliver a React dashboard with live analytics and incident workflow.",
            "Package the full stack with Docker Compose for reproducible demos.",
        ],
        "notes": "Read objectives as measurable outcomes.",
    },
    {
        "title": "Existing System",
        "bullets": [
            "Commercial SIEM platforms (Splunk, Elastic Security, QRadar).",
            "Open-source stacks (ELK + custom rules, Wazuh).",
            "Manual spreadsheet or ticket-based incident tracking in small teams.",
            "Isolated IDS/IPS alerts without unified SOC workflow.",
        ],
        "notes": "Acknowledge commercial tools; position ours as lightweight academic SIEM.",
    },
    {
        "title": "Limitations of Existing System",
        "bullets": [
            "High licensing and infrastructure cost for full commercial SIEM.",
            "Complex setup unsuitable for rapid student demonstration.",
            "Alert fatigue without strong incident correlation.",
            "Limited explainability in black-box detections.",
            "Weak integration between ingestion, AI scoring, and analyst workflow.",
        ],
        "notes": "Justify building a focused academic alternative with explainability.",
    },
    {
        "title": "Proposed System",
        "bullets": [
            "Cyber Threat Detection and Incident Response Dashboard (lightweight SIEM).",
            "Four log sources: Windows, Linux, Firewall, Web Server.",
            "Dual detection: rule engine + Isolation Forest anomaly model.",
            "Incident correlation with status workflow and investigation notes.",
            "JWT/RBAC authentication and analytics-driven React console.",
            "Fully containerized: FastAPI, MongoDB, Elasticsearch, React.",
        ],
        "placeholder": "[Insert Architecture Diagram]",
        "notes": "Summarize the proposed product and Docker Compose deployment.",
    },
    {
        "title": "System Architecture",
        "bullets": [
            "Log Sources to Ingestion API to Parser/Normalizer to Elasticsearch.",
            "Normalized logs to Rule Engine + ML Engine to Detection Events.",
            "Detection Events to Incident Correlator to MongoDB Incidents/Alerts.",
            "React Dashboard consumes REST APIs for auth, logs, detections, incidents, analytics.",
        ],
        "flow": ["Sources", "Ingest", "Detect", "Correlate", "Dashboard"],
        "placeholder": "[Insert Architecture Diagram]",
        "notes": "Walk left-to-right. Mongo for entities, Elasticsearch for logs.",
    },
    {
        "title": "Technology Stack",
        "bullets": [
            "Backend: FastAPI, Python, JWT/RBAC, Motor (MongoDB), Elasticsearch client.",
            "Frontend: React, TypeScript, Vite, TanStack Query, Axios, Recharts, Tailwind.",
            "Data: MongoDB (users, detections, incidents), Elasticsearch (security logs).",
            "ML: scikit-learn Isolation Forest, joblib model registry.",
            "Ops: Docker Compose, Uvicorn, Kibana (optional inspection).",
        ],
        "notes": "Keep stack crisp; justify ES for logs and Mongo for SOC records.",
    },
    {
        "title": "Project Workflow",
        "bullets": [
            "Analyst authenticates with JWT access/refresh tokens.",
            "Uploads sample or production-like log files by source type.",
            "Pipeline parses, normalizes, deduplicates, and indexes logs.",
            "Rules and ML score the batch; detections and alerts persist.",
            "Correlator opens/updates incidents; dashboard analytics refresh.",
        ],
        "flow": ["Login", "Upload", "Detect", "Incident", "Analyze"],
        "notes": "Narrate the demo path mentors will see live in the UI.",
    },
    {
        "title": "Log Collection Pipeline",
        "bullets": [
            "Parsers: Windows JSON, Linux syslog/auth, Firewall ALLOW/DENY, Apache CLF.",
            "Normalizer produces canonical NormalizedLog schema.",
            "Deterministic content-hash log_id for idempotent re-ingestion.",
            "Bulk index into daily Elasticsearch indices (security-logs-YYYY.MM.DD).",
            "Ingestion batch audit trail stored in MongoDB.",
        ],
        "flow": ["Upload", "Parse", "Normalize", "Dedupe", "Index"],
        "placeholder": "[Insert Log Upload Screenshot]",
        "notes": "Stress schema unification so rules/ML stay source-agnostic.",
    },
    {
        "title": "Rule-Based Detection",
        "bullets": [
            "Eight modular rules including SSH brute force, Windows failed login, port scan.",
            "Web attacks: SQL injection, XSS, directory traversal; plus privilege escalation.",
            "MITRE ATT&CK mapping with confidence and severity on each DetectionEvent.",
            "RuleEngine isolates failures so one rule cannot crash the pipeline.",
            "Admin API can enable/disable rules at runtime.",
        ],
        "placeholder": "[Insert Threat Detection Screenshot]",
        "notes": "Give examples: SSH brute force and SQL injection with MITRE mapping.",
    },
    {
        "title": "AI Anomaly Detection",
        "bullets": [
            "Isolation Forest behind a pluggable AnomalyModel interface.",
            "Per-entity feature extraction for IP/user oriented signals.",
            "Versioned model registry with train, predict, and evaluate APIs.",
            "Risk percentage and explanation fields for viva/demo explainability.",
            "Labeled sample dataset supports precision/recall/F1 reporting.",
        ],
        "flow": ["Features", "Train", "Score", "Detect", "Alert"],
        "placeholder": "[Insert AI Detection Screenshot]",
        "notes": "ML complements rules and finds unusual patterns rules may miss.",
    },
    {
        "title": "Incident Response Workflow",
        "bullets": [
            "Correlate detections by entity and threat key (no one-to-one alert spam).",
            "Human-readable IDs: INC-1001, INC-1002, and so on.",
            "Status machine: OPEN to INVESTIGATING to RESOLVED to CLOSED.",
            "Assign analyst, add investigation notes, escalate severity when needed.",
            "Timeline preserved for audit integrity; incidents are closed, not deleted.",
        ],
        "flow": ["OPEN", "INVESTIGATE", "RESOLVE", "CLOSE"],
        "placeholder": "[Insert Incident Management Screenshot]",
        "notes": "Demonstrate assign/resolve on a live incident if time permits.",
    },
    {
        "title": "Dashboard Overview",
        "bullets": [
            "Summary cards: Total Logs, Threats, Incidents, Critical Alerts, AI Anomalies.",
            "Charts: Threat Timeline, Severity Distribution, Attack Types, Top Source IPs.",
            "Recent Events table with engine, entity, severity, and explanation.",
            "Auto-refresh via React Query for a near-live SOC view.",
        ],
        "placeholder": "[Insert Dashboard Screenshot]",
        "notes": "Show the populated dashboard after demo seed.",
    },
    {
        "title": "Backend Architecture",
        "bullets": [
            "FastAPI routers: auth, logs, detections, ml, incidents, analytics, rules.",
            "Dependency Inversion: ingestion triggers detection via on_ingested callback.",
            "Repository layer for Mongo and Elasticsearch.",
            "Structured logging, fault isolation, JWT RBAC (admin / soc_analyst).",
            "Health endpoints: /health and /health/ready.",
        ],
        "notes": "Useful for faculty asking about modularity and SOLID design.",
    },
    {
        "title": "Database Design",
        "bullets": [
            "MongoDB: users, detections, alerts, incidents, ingestion_batches, detection_rules.",
            "Elasticsearch indices: security-logs-* with mapped NormalizedLog fields.",
            "Incidents store detection_ids, evidence_log_ids, notes, assigned_to.",
            "Atomic counters collection for INC-#### sequence generation.",
        ],
        "placeholder": "[Insert Analytics Screenshot]",
        "notes": "Explain polyglot persistence: SOC entities vs searchable log store.",
    },
    {
        "title": "Current Progress",
        "bullets": [
            "Completed: Backend architecture, JWT auth, MongoDB, Elasticsearch, Docker.",
            "Completed: Log ingestion/parsers, rule-based detection, AI anomaly detection.",
            "Completed: Incident management APIs + correlation, analytics APIs.",
            "Completed: React SOC pages wired to live Axios APIs (no mocks).",
            "Validated: 126 backend unit tests; end-to-end upload to detect to incident demo.",
            "Dashboard: functional and demo-populated.",
        ],
        "placeholder": "[Insert Login Page Screenshot]",
        "notes": "Core system is integrated and demonstrable.",
    },
    {
        "title": "Future Scope",
        "bullets": [
            "External alert dispatch (SMTP, Discord, Telegram webhooks).",
            "GeoIP/ASN enrichment and known-bad IP feeds.",
            "Real-time agent/shipper path beyond file upload.",
            "Background ML retrain jobs and larger labeled datasets.",
            "Deeper user administration and notification center in UI.",
        ],
        "notes": "Frame as natural extensions, not missing MVP blockers.",
    },
    {
        "title": "Conclusion",
        "bullets": [
            "Delivered a complete lightweight SIEM-style academic platform.",
            "Unified multi-source logs with rule + AI detection and SOC workflow.",
            "Explainable detections support viva demonstration and mentoring reviews.",
            "Dockerized stack enables reproducible local deployment and demos.",
            "Foundation ready for enrichment, real-time shipping, and alert channels.",
        ],
        "notes": "Restate contribution: end-to-end cyber defense workflow in one dashboard.",
    },
    {
        "title": "Questions",
        "bullets": [
            "Thank you for your attention.",
            "Open for questions from mentor and review committee.",
            "Demo available at: http://localhost:5173 (Docker Compose stack).",
            "API docs: http://localhost:8000/docs",
        ],
        "notes": "Invite questions. Offer to open live dashboard or API docs if asked.",
    },
]


def fill_title_slide(slide, meta):
    for shape in slide.shapes:
        if not shape.has_text_frame:
            continue
        text = shape.text_frame.text
        upper = text.upper()
        if "SEMINAR" in upper or "PRESENTATION" in upper or "Impact" in text or "PROJECT PRESENTATION" in upper:
            set_shape_text(
                shape,
                ["A PROJECT PRESENTATION", "ON", f"“{PROJECT}”"],
                bold_first=True,
                font_size=16,
            )
        elif "SUBMITTED BY" in upper or "ROLL" in upper:
            set_shape_text(
                shape,
                [
                    f"SUBMITTED BY: {STUDENT}",
                    f"ROLL NO.: {ROLL}",
                    f"DEPARTMENT: {DEPT}",
                    f"COLLEGE: {COLLEGE}",
                    f"ACADEMIC YEAR: {YEAR}",
                ],
                font_size=12,
            )
        elif "SUBMITTED TO" in upper or "VISHAL" in upper or "DESIGNATION" in upper:
            set_shape_text(
                shape,
                [
                    "SUBMITTED TO:",
                    f"NAME: {GUIDE}",
                    f"DESIGNATION: {GUIDE_DESIGNATION}",
                ],
                font_size=12,
            )
    set_notes(slide, meta["notes"])


def fill_content_slide(slide, meta):
    title_shape = find_title_shape(slide)
    body_shape = find_body_shape(slide, title_shape)

    if title_shape is not None:
        set_shape_text(title_shape, [meta["title"] + ":"], bold_first=True, font_size=20)

    if body_shape is not None and meta.get("bullets"):
        formatted = [f"- {line}" for line in meta["bullets"]]
        set_shape_text(body_shape, formatted, font_size=13)

    # Shrink body height slightly when adding bottom flow so text does not collide
    if meta.get("flow"):
        add_flow_boxes(slide, meta["flow"])

    if meta.get("placeholder"):
        add_placeholder_box(
            slide,
            Emu(7_700_000),
            Emu(1_650_000),
            Emu(3_900_000),
            Emu(2_400_000),
            meta["placeholder"],
        )

    set_notes(slide, meta["notes"])


def rebuild_deck(prs: Presentation, needed_content: int):
    """
    Keep title slide (0). Duplicate content template many times.
    Delete original seminar content slides 1..N-1, keep title + fresh clones.
    """
    # Duplicate content template enough times first (while original index still valid)
    clones = []
    for _ in range(needed_content):
        clones.append(duplicate_slide(prs, CONTENT_TEMPLATE_INDEX))

    # Delete all slides except slide 0 and the newly appended clones.
    # After appends, original slides are still at the front.
    # Indices: 0=title, 1..14=old, then clones.
    # Remove old content slides from highest index down to 1.
    original_count_before_clones = len(prs.slides) - needed_content
    for idx in range(original_count_before_clones - 1, 0, -1):
        delete_slide(prs, idx)

    # Now: [title] + [clones...]
    assert len(prs.slides) == 1 + needed_content


def main():
    if not TEMPLATE.exists():
        raise SystemExit(f"Template not found: {TEMPLATE}")

    shutil.copy2(TEMPLATE, OUTPUT)
    prs = Presentation(str(OUTPUT))

    content_slides = [s for s in SLIDES if s.get("kind") != "title"]
    rebuild_deck(prs, len(content_slides))

    # Fill title
    fill_title_slide(prs.slides[0], SLIDES[0])

    # Fill content slides 1..N
    for i, meta in enumerate(content_slides):
        fill_content_slide(prs.slides[i + 1], meta)

    prs.save(str(OUTPUT))
    print(f"Wrote {OUTPUT}")
    print(f"Slides: {len(prs.slides)}")


if __name__ == "__main__":
    main()
