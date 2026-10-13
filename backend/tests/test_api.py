"""
tests/test_api.py

Purpose:
    HTTP-level behaviour not covered by the feature-specific test
    modules: authentication is required everywhere, upload validation
    and size limits, rule configuration, and the dashboard staying up
    when Elasticsearch is not.
"""
import pytest

from app.core.config import settings
from app.detection.engine import default_rule_engine

LINUX_LINES = "\n".join(
    f"Jul 18 09:12:{second:02d} web01 sshd[100]: Failed password for root from 192.168.1.20 port 5{second:04d} ssh2"
    for second in range(5)
)


@pytest.fixture
def fake_elastic(monkeypatch):
    """In-memory stand-in for the Elasticsearch calls the ingestion path makes."""
    indexed = []

    async def fake_check_existing_log_ids(log_ids):
        return {log.log_id for log in indexed} & set(log_ids)

    async def fake_bulk_index_logs(logs):
        indexed.extend(logs)
        return {"accepted": len(logs), "rejected": 0}

    async def fake_search_logs(**kwargs):
        return {"total": len(indexed), "results": [log.model_dump(mode="json") for log in indexed]}

    monkeypatch.setattr("app.ingestion.pipeline.check_existing_log_ids", fake_check_existing_log_ids)
    monkeypatch.setattr("app.ingestion.pipeline.bulk_index_logs", fake_bulk_index_logs)
    monkeypatch.setattr("app.detection.service.elastic.search_logs", fake_search_logs)
    return indexed


@pytest.fixture
def wired_pipeline(monkeypatch):
    """main.py wires detection to ingestion in its lifespan, which ASGITransport does not run."""
    from app.detection import service
    from app.ingestion.pipeline import default_pipeline

    monkeypatch.setattr(service.default_prediction_service, "predict", lambda logs: [])
    monkeypatch.setattr(default_pipeline, "_on_ingested", service.handle_ingested_logs)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/api/v1/logs/search"),
        ("GET", "/api/v1/detections"),
        ("GET", "/api/v1/alerts"),
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/analytics/summary"),
        ("GET", "/api/v1/rules"),
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/ml/models"),
        ("POST", "/api/v1/detections/run"),
        ("POST", "/api/v1/ml/train"),
    ],
)
async def test_endpoints_reject_anonymous_requests(client, method, path):
    assert (await client.request(method, path)).status_code == 401


@pytest.mark.asyncio
async def test_health_is_public(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_upload_runs_ingestion_and_detection(client, auth_headers, mock_db, fake_elastic, wired_pipeline):
    headers = await auth_headers()

    response = await client.post(
        "/api/v1/logs/upload",
        data={"source_type": "linux", "source_host": "web01"},
        files={"file": ("auth.log", LINUX_LINES.encode(), "text/plain")},
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["accepted"] == 5
    assert len(fake_elastic) == 5
    assert await mock_db.incidents.count_documents({}) == 1

    again = await client.post(
        "/api/v1/logs/upload",
        data={"source_type": "linux", "source_host": "web01"},
        files={"file": ("auth.log", LINUX_LINES.encode(), "text/plain")},
        headers=headers,
    )
    assert again.json()["accepted"] == 0
    assert again.json()["duplicates"] == 5


@pytest.mark.asyncio
async def test_upload_rejects_wrong_extension_and_non_utf8(client, auth_headers, fake_elastic):
    headers = await auth_headers()

    exe = await client.post(
        "/api/v1/logs/upload",
        data={"source_type": "linux"},
        files={"file": ("payload.exe", b"MZ", "application/octet-stream")},
        headers=headers,
    )
    assert exe.status_code == 400

    binary = await client.post(
        "/api/v1/logs/upload",
        data={"source_type": "linux"},
        files={"file": ("auth.log", b"\xff\xfe\x00bad", "text/plain")},
        headers=headers,
    )
    assert binary.status_code == 400


@pytest.mark.asyncio
async def test_oversized_content_is_rejected(client, auth_headers, fake_elastic, monkeypatch):
    monkeypatch.setattr(settings, "MAX_UPLOAD_FILE_SIZE_MB", 1)
    headers = await auth_headers()
    too_big = "x" * (1024 * 1024 + 1)

    upload = await client.post(
        "/api/v1/logs/upload",
        data={"source_type": "linux"},
        files={"file": ("big.log", too_big.encode(), "text/plain")},
        headers=headers,
    )
    assert upload.status_code == 413

    ingest = await client.post(
        "/api/v1/logs/ingest", json={"source_type": "linux", "content": too_big}, headers=headers
    )
    assert ingest.status_code == 413
    assert fake_elastic == []


@pytest.mark.asyncio
async def test_ingest_validates_its_body(client, auth_headers, fake_elastic):
    headers = await auth_headers()

    assert (
        await client.post("/api/v1/logs/ingest", json={"source_type": "mainframe", "content": "x"}, headers=headers)
    ).status_code == 422
    assert (
        await client.post("/api/v1/logs/ingest", json={"source_type": "linux", "content": ""}, headers=headers)
    ).status_code == 422

    ok = await client.post(
        "/api/v1/logs/ingest", json={"source_type": "linux", "content": LINUX_LINES}, headers=headers
    )
    assert ok.status_code == 201
    assert ok.json()["accepted"] == 5


@pytest.mark.asyncio
async def test_invalid_windows_json_is_a_422(client, auth_headers, fake_elastic):
    headers = await auth_headers()
    response = await client.post(
        "/api/v1/logs/ingest", json={"source_type": "windows", "content": "not json at all"}, headers=headers
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_rules_listing_and_admin_only_updates(client, auth_headers, mock_db):
    analyst = await auth_headers("soc_analyst")
    admin = await auth_headers("admin")
    rule = default_rule_engine.get_rule("ssh_brute_force")
    original = dict(rule.config)

    try:
        listed = await client.get("/api/v1/rules", headers=analyst)
        assert listed.status_code == 200
        ssh = next(r for r in listed.json()["rules"] if r["rule_name"] == "ssh_brute_force")
        assert ssh["config"] == original
        assert ssh["settings"]["threshold"]["type"] == "integer"

        forbidden = await client.patch("/api/v1/rules/ssh_brute_force", json={"enabled": False}, headers=analyst)
        assert forbidden.status_code == 403

        updated = await client.patch(
            "/api/v1/rules/ssh_brute_force", json={"enabled": False, "config": {"threshold": 8}}, headers=admin
        )
        assert updated.status_code == 200
        assert updated.json()["enabled"] is False
        assert updated.json()["config"]["threshold"] == 8
        assert rule.config["threshold"] == 8

        saved = await mock_db.detection_rules.find_one({"rule_name": "ssh_brute_force"})
        assert saved["enabled"] is False and saved["config"]["threshold"] == 8

        invalid = await client.patch(
            "/api/v1/rules/ssh_brute_force", json={"config": {"threshold": "lots"}}, headers=admin
        )
        assert invalid.status_code == 422
        unknown_setting = await client.patch(
            "/api/v1/rules/ssh_brute_force", json={"config": {"nope": 1}}, headers=admin
        )
        assert unknown_setting.status_code == 422
        assert (await client.patch("/api/v1/rules/nope", json={"enabled": True}, headers=admin)).status_code == 404
    finally:
        rule.enabled = True
        rule.update_config(original)


@pytest.mark.asyncio
async def test_dashboard_summary_survives_elasticsearch_being_down(client, auth_headers):
    headers = await auth_headers()

    summary = await client.get("/api/v1/analytics/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["total_logs"] == 0
    assert summary.json()["active_incidents"] == 0

    severity = await client.get("/api/v1/analytics/severity-distribution", headers=headers)
    assert severity.json() == {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for path in ("top-ips", "attack-types", "recent-events"):
        assert (await client.get(f"/api/v1/analytics/{path}", headers=headers)).status_code == 200


@pytest.mark.asyncio
async def test_threat_timeline_has_one_point_per_hour_including_empty_hours(client, auth_headers, mock_db):
    from app.db.mongo import utcnow

    headers = await auth_headers()
    await mock_db.detections.insert_many([{"timestamp": utcnow(), "engine": "rule"} for _ in range(3)])

    timeline = (await client.get("/api/v1/analytics/threat-timeline", params={"hours": 6}, headers=headers)).json()

    assert timeline["count"] == 6
    assert [point["count"] for point in timeline["items"]] == [0, 0, 0, 0, 0, 3]


@pytest.mark.asyncio
async def test_attack_types_use_readable_labels(client, auth_headers, mock_db):
    from app.db.mongo import utcnow

    headers = await auth_headers()
    await mock_db.detections.insert_many(
        [
            {"timestamp": utcnow(), "engine": "rule", "rule_name": "sql_injection", "mitre_technique": "T1190"},
            {"timestamp": utcnow(), "engine": "rule", "rule_name": "sql_injection", "mitre_technique": "T1190"},
            {"timestamp": utcnow(), "engine": "ml", "rule_name": None},
        ]
    )

    items = (await client.get("/api/v1/analytics/attack-types", headers=headers)).json()["items"]

    assert items == [
        {"threat_type": "SQL Injection", "count": 2, "mitre_technique": "T1190"},
        {"threat_type": "AI Anomaly", "count": 1, "mitre_technique": "N/A"},
    ]
