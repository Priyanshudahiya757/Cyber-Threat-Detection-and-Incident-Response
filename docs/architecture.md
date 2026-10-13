# Cyber Threat Detection and Incident Response Dashboard
## System Architecture & Development Plan (Phase 1 Deliverable)

---

## 1. Requirements Analysis

### 1.1 What this system actually needs to do
Strip away the buzzwords and this is a **log pipeline with three consumers**:

1. **Ingest** — get logs from Windows, Linux, firewalls, and web servers into one place, in one shape.
2. **Detect** — run that normalized log stream through two parallel engines: deterministic rules (brute force, port scan, SQLi/XSS patterns) and a statistical anomaly model (Isolation Forest).
3. **Respond** — turn detections into incidents that a human (SOC analyst) can triage, investigate, and close, with alerts firing out to email/Discord/Telegram along the way.

Everything else — auth, dashboard, charts — exists to support those three functions. I'm calling this out because it should drive the folder structure: **ingestion, detection, and response are separate services/modules that communicate through the log store and the incident store, not through direct function calls.** That's what makes it "SIEM-like" rather than a CRUD app with a security theme.

### 1.2 Non-functional constraints that shape the design
- **Modularity**: rule-based detection and ML detection must be pluggable — you'll want to add new rules and retrain/swap models without touching ingestion or the dashboard.
- **Scalability on paper, honesty in practice**: for a student project, you won't run a real Kafka cluster, and that's fine. The architecture should be *shaped* like something that could take a message queue later (ingestion → queue → processing → storage), even if Phase 1–4 uses a simpler in-process/cron-based pipeline. I'll show you where the seam is.
- **Explainability**: examiners will ask "why did this get flagged?" — every detection (rule or ML) needs to carry a reason/feature breakdown, not just a severity label.
- **Realistic log sourcing**: real-time agents on live Windows/Linux boxes are a stretch goal. File-upload ingestion (sample log files) is your reliable demo path; I'll design real-time ingestion as an architecture that's *present* but gracefully degrades to file upload for testing.

---

## 2. System Architecture

### 2.1 High-level component diagram (textual)

```
┌─────────────────────────────────────────────────────────────────────┐
│                            LOG SOURCES                                │
│   Windows Event Logs | Linux syslog | Firewall logs | Web server logs │
│        (live agent / Filebeat-style shipper OR manual file upload)    │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │  raw log lines / files
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     LOG INGESTION SERVICE (FastAPI)                   │
│  - /api/logs/upload      (file upload, sync)                          │
│  - /api/logs/stream      (POST endpoint agents push to, async)        │
│  - Writes raw log to a staging queue (in-proc asyncio.Queue initially, │
│    swappable for Redis/Kafka later — same interface)                  │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    LOG PROCESSING PIPELINE (Python)                   │
│  Parser → Normalizer → Enricher → Writer                              │
│  - Source-specific parsers (windows, linux, firewall, web)            │
│  - Normalize into a single canonical JSON schema                      │
│  - Enrich (geoIP stub, ASN stub, known-bad-IP list, severity default) │
│  - Write to Elasticsearch (log store) + emit "normalized_log" event   │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
                 ┌───────────────┴────────────────┐
                 ▼                                 ▼
┌───────────────────────────────┐   ┌───────────────────────────────────┐
│   RULE-BASED DETECTION ENGINE │   │   AI ANOMALY DETECTION ENGINE      │
│  - Sliding-window rule checks │   │  - Feature extraction per entity   │
│    (brute force, port scan,   │   │    (per-IP, per-user, per-session) │
│    suspicious login, SQLi/XSS)│   │  - Isolation Forest scoring        │
│  - Stateless rule definitions │   │  - Periodic retrain job            │
│    in a rules registry        │   │  - Outputs anomaly_score + label   │
└───────────────┬───────────────┘   └────────────────┬────────────────────┘
                │  Detection events (both engines emit the SAME shape)  │
                └───────────────────────┬─────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  INCIDENT & ALERT MANAGER (FastAPI)                   │
│  - Correlates detection events → creates/updates Incident documents   │
│  - Deduplication (don't spawn 50 incidents for 50 failed logins)      │
│  - Severity scoring, status machine (OPEN → INVESTIGATING → RESOLVED) │
│  - Fires alerts: Email (SMTP), Discord/Telegram (webhook)             │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA LAYER                                     │
│  MongoDB: users, incidents, rules config, ML model metadata           │
│  Elasticsearch: normalized_logs (searchable, time-series, dashboards) │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  REACT + TAILWIND SOC DASHBOARD                       │
│  Auth (JWT) → Dashboard / Live Monitoring / Threat Analytics /        │
│  Incident Management — talks to FastAPI over REST, Axios              │
│  Charts via Recharts (severity distribution, attack trends, top IPs)  │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Why Elasticsearch **and** MongoDB (not just one)
This is a real architectural decision, not stack-padding — worth stating explicitly in your report:
- **MongoDB** = system-of-record for structured, low-volume, relational-ish entities: users, roles, incidents, rule definitions, ML model versions. You need transactional-ish CRUD and simple queries here.
- **Elasticsearch** = log store for high-volume, append-only, time-series data that needs full-text/field search and aggregations (top attacking IPs, attack trends over time). Trying to do that in MongoDB means reimplementing what ES gives you for free (inverted indices, date histograms).

If ES setup proves too heavy for your timeline, the fallback is MongoDB with a `time`-indexed `logs` collection — I'll design the log-access layer behind a repository interface so you can swap the backend without touching the detection engines. Worth deciding now which path you want (see question at the end).

### 2.3 Canonical log schema
Everything downstream (rules, ML features, dashboard) depends on parsers agreeing on one shape:

```json
{
  "log_id": "uuid",
  "source_type": "windows | linux | firewall | web_server",
  "source_host": "string",
  "event_category": "authentication | network | web_attack | system",
  "event_type": "failed_login | successful_login | port_scan | sql_injection | ...",
  "severity": "low | medium | high | critical",
  "user": "string | null",
  "source_ip": "string | null",
  "dest_ip": "string | null",
  "dest_port": "int | null",
  "raw_log": "original line, preserved for audit",
  "parsed_fields": { "...": "source-specific extra fields" },
  "timestamp": "ISO 8601",
  "ingested_at": "ISO 8601"
}
```

Detection events (output of both engines) share their own canonical shape too:

```json
{
  "detection_id": "uuid",
  "engine": "rule | ml",
  "rule_name": "brute_force_ssh | null",
  "anomaly_score": "float | null",
  "confidence": "float",
  "severity": "low | medium | high | critical",
  "entity": { "type": "ip | user", "value": "192.168.1.20" },
  "evidence_log_ids": ["log_id", "..."],
  "explanation": "human-readable reason",
  "timestamp": "ISO 8601"
}
```
That `explanation` field is what saves you in the viva when someone asks "why is this an anomaly?"

### 2.4 Detection → Incident correlation logic
This is the piece most student projects skip and examiners notice: raw detections should not equal incidents 1:1. The Incident Manager should:
1. Bucket detection events by `(entity, rule_name/engine, time_window)`.
2. If an OPEN incident already exists for that bucket, append evidence and bump severity if warranted instead of creating a duplicate.
3. Otherwise create a new `Incident` with auto-generated ID (`INC-1001`), initial severity, status `OPEN`.
4. Trigger alert dispatch only on incident *creation* or severity *escalation*, not on every underlying detection — otherwise a brute-force burst spams 40 emails.

---

## 3. Recommended Folder Structure

```
cyber-threat-dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py                      # FastAPI app entrypoint
│   │   ├── core/
│   │   │   ├── config.py                # env config, settings
│   │   │   ├── security.py              # JWT, password hashing
│   │   │   └── dependencies.py          # auth/role dependencies
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── auth.py              # login/register endpoints
│   │   │   │   ├── logs.py              # upload/stream endpoints
│   │   │   │   ├── incidents.py         # incident CRUD/workflow
│   │   │   │   ├── analytics.py         # dashboard aggregation endpoints
│   │   │   │   └── rules.py             # rule config management
│   │   ├── ingestion/
│   │   │   ├── parsers/
│   │   │   │   ├── windows_parser.py
│   │   │   │   ├── linux_parser.py
│   │   │   │   ├── firewall_parser.py
│   │   │   │   └── web_parser.py
│   │   │   ├── normalizer.py
│   │   │   ├── enrichment.py
│   │   │   └── pipeline.py              # orchestrates parse→normalize→enrich→store
│   │   ├── detection/
│   │   │   ├── rules/
│   │   │   │   ├── base_rule.py         # rule interface
│   │   │   │   ├── brute_force.py
│   │   │   │   ├── port_scan.py
│   │   │   │   ├── suspicious_login.py
│   │   │   │   └── web_attack.py
│   │   │   ├── ml/
│   │   │   │   ├── feature_extraction.py
│   │   │   │   ├── isolation_forest_model.py
│   │   │   │   ├── train.py
│   │   │   │   └── model_registry.py    # versioned model artifacts
│   │   │   └── engine.py                # runs both engines, emits detections
│   │   ├── incidents/
│   │   │   ├── correlator.py            # detections → incidents logic
│   │   │   ├── models.py
│   │   │   └── service.py
│   │   ├── alerts/
│   │   │   ├── email_alert.py
│   │   │   ├── webhook_alert.py         # Discord/Telegram
│   │   │   └── dispatcher.py
│   │   ├── db/
│   │   │   ├── mongo.py                 # Mongo client + repositories
│   │   │   └── elastic.py               # ES client + log repository
│   │   └── models/                      # Pydantic schemas (shared contracts)
│   │       ├── log_schema.py
│   │       ├── detection_schema.py
│   │       ├── incident_schema.py
│   │       └── user_schema.py
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── api/                         # Axios instance + endpoint wrappers
│   │   ├── auth/                        # login page, JWT context, route guards
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── LiveMonitoring.jsx
│   │   │   ├── ThreatAnalytics.jsx
│   │   │   └── IncidentManagement.jsx
│   │   ├── components/
│   │   │   ├── charts/                  # Recharts wrappers
│   │   │   ├── tables/
│   │   │   └── layout/                  # sidebar, topbar, SOC theme
│   │   ├── hooks/
│   │   └── App.jsx
│   ├── package.json
│   └── Dockerfile
│
├── ml/
│   ├── notebooks/                       # exploratory training/eval
│   ├── datasets/                        # sample/synthetic training logs
│   └── models/                          # saved .pkl artifacts (mounted into backend)
│
├── sample_logs/                         # test fixtures for file-upload ingestion
│   ├── windows_sample.evtx.json
│   ├── linux_auth.log
│   ├── firewall_sample.log
│   └── web_access.log
│
├── docker-compose.yml                   # backend, frontend, mongo, elasticsearch
├── docs/
│   ├── architecture.md                  # this document
│   ├── api_spec.md
│   └── threat_model.md
└── README.md
```

**Design rule baked into this structure**: `ingestion/`, `detection/`, `incidents/`, and `alerts/` are independent Python packages that only talk to each other through the schemas in `models/` and the repositories in `db/`. No module imports internals from another module directly. This is what lets you say "modular, scalable architecture" in your report and have it actually be true when someone reads the code.

---

## 4. Development Roadmap (mapped to your 8 phases)

| Phase | Deliverable | Key decisions made in this phase |
|---|---|---|
| **1** | Architecture, folder structure, DB schema (docs) | This document + finalized Mongo collections & ES index mappings |
| **2** | Backend skeleton, JWT auth, role-based access (admin/analyst) | `core/security.py`, `api/v1/auth.py`, user schema |
| **3** | Frontend shell, routing, auth-guarded pages, empty dashboard | Login flow wired to backend, Tailwind theme, layout components |
| **4** | Log ingestion + processing pipeline, file upload working end-to-end | Parsers for all 4 source types, canonical schema enforced |
| **5** | Rule-based detection engine live on ingested logs | Brute force, port scan, suspicious login, SQLi/XSS rules |
| **6** | ML anomaly detection: feature extraction, training, scoring | Isolation Forest trained on sample data, integrated into `detection/engine.py` |
| **7** | Incident correlation + alerting | `correlator.py`, email + Discord/Telegram dispatch |
| **8** | Testing, Docker Compose, documentation, polish | Full `docker-compose up` demo, README, threat model writeup |

Each phase produces code you can actually run and demo — by end of Phase 4 you'll have a working ingestion pipeline you can show even before detection exists, which is good for incremental demos to your guide.

---

## 5. Before I write any code — a few decisions worth locking in now

I'd rather get these right upfront than rework them in Phase 4:

1. **Log store**: full Elasticsearch, or MongoDB-only fallback for the log store (simpler ops, weaker search/aggregation)?
2. **Real-time ingestion**: do you want a working live agent (e.g., a small Python shipper tailing `/var/log/auth.log` and POSTing to the API) for the demo, or is file-upload-only sufficient and real-time is just documented as the architecture's intended path?
3. **Deployment scope for Phase 8**: single `docker-compose.yml` on your dev machine, or do you also want it deployable to a small cloud VM?

Answer those (or tell me to just pick sensible defaults) and I'll start Phase 1 for real: Mongo collection schemas + ES index mappings + the FastAPI project skeleton.
