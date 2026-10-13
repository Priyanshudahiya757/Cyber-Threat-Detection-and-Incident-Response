"""
tests/test_alert_dispatcher.py

Purpose:
    External alert delivery: only configured channels are used, one
    failing channel doesn't stop the others, and the alerts API reports
    channel status. No network calls are made — channel send() methods
    are replaced with fakes.
"""
import pytest

from app.alerts import dispatcher
from app.alerts.channels import AlertChannel, DiscordChannel, EmailChannel, TelegramChannel, format_alert_text
from app.core.config import settings
from app.models.alert_schema import Alert
from app.models.detection_schema import Entity, EntityType
from app.models.log_schema import Severity


def make_alert() -> Alert:
    return Alert(
        title="SSH Brute Force — 203.0.113.50",
        threat_type="ssh_brute_force",
        severity=Severity.CRITICAL,
        entity=Entity(type=EntityType.IP, value="203.0.113.50"),
        detection_id="det-1",
        mitre_technique="T1110 - Brute Force",
        description="12 failed SSH login attempts from 203.0.113.50.",
    )


class _FakeChannel(AlertChannel):
    def __init__(self, name: str, configured: bool = True, fails: bool = False):
        self.name = name
        self._configured = configured
        self._fails = fails
        self.sent = []

    def is_configured(self) -> bool:
        return self._configured

    async def send(self, alert: Alert) -> None:
        if self._fails:
            raise ConnectionError("https://hooks.example/secret-token refused")
        self.sent.append(alert)


def test_alert_text_includes_the_key_facts():
    text = format_alert_text(make_alert())
    assert "[CRITICAL]" in text
    assert "203.0.113.50" in text
    assert "T1110" in text


def test_channels_report_unconfigured_without_credentials(monkeypatch):
    for name in ("SMTP_HOST", "DISCORD_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        monkeypatch.setattr(settings, name, "")
    assert not EmailChannel().is_configured()
    assert not DiscordChannel().is_configured()
    assert not TelegramChannel().is_configured()


def test_channels_report_configured_with_credentials(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "ALERT_EMAIL_FROM", "siem@example.com")
    monkeypatch.setattr(settings, "ALERT_EMAIL_TO", ["soc@example.com"])
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.example/webhook")
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setattr(settings, "TELEGRAM_CHAT_ID", "42")
    assert EmailChannel().is_configured()
    assert DiscordChannel().is_configured()
    assert TelegramChannel().is_configured()


class _FakeSMTP:
    """Records what EmailChannel does with smtplib, without opening a connection."""

    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.calls: list = []
        self.sent = None
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return name == "starttls"

    def starttls(self):
        self.calls.append("starttls")

    def login(self, username, password):
        self.calls.append(("login", username, password))

    def send_message(self, message):
        self.sent = message


@pytest.mark.asyncio
async def test_email_channel_sends_an_authenticated_starttls_message(monkeypatch):
    _FakeSMTP.instances.clear()
    monkeypatch.setattr("app.alerts.channels.smtplib.SMTP", _FakeSMTP)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USERNAME", "siem")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(settings, "ALERT_EMAIL_FROM", "siem@example.com")
    monkeypatch.setattr(settings, "ALERT_EMAIL_TO", ["soc@example.com", "lead@example.com"])

    await EmailChannel().send(make_alert())

    [smtp] = _FakeSMTP.instances
    assert (smtp.host, smtp.port) == ("smtp.example.com", 587)
    assert smtp.calls == ["ehlo", "starttls", "ehlo", ("login", "siem", "secret")]
    assert smtp.sent["Subject"] == "[CRITICAL] SSH Brute Force — 203.0.113.50"
    assert smtp.sent["To"] == "soc@example.com, lead@example.com"
    assert "T1110" in smtp.sent.get_content()


@pytest.mark.asyncio
async def test_email_channel_uses_implicit_tls_on_port_465(monkeypatch):
    _FakeSMTP.instances.clear()
    monkeypatch.setattr("app.alerts.channels.smtplib.SMTP_SSL", _FakeSMTP)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 465)
    monkeypatch.setattr(settings, "SMTP_USERNAME", "")
    monkeypatch.setattr(settings, "ALERT_EMAIL_FROM", "siem@example.com")
    monkeypatch.setattr(settings, "ALERT_EMAIL_TO", ["soc@example.com"])

    await EmailChannel().send(make_alert())

    [smtp] = _FakeSMTP.instances
    assert smtp.calls == ["ehlo"]  # no STARTTLS upgrade, no login without a username
    assert smtp.sent is not None


@pytest.fixture
def webhook_requests(monkeypatch):
    """Route the channels' outbound HTTP calls to an in-memory handler and record them."""
    import httpx

    requests = []
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500 if "fail" in str(request.url) else 200, json={"ok": True})

    monkeypatch.setattr(
        "app.alerts.channels.httpx.AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    return requests


@pytest.mark.asyncio
async def test_discord_channel_posts_the_alert_text(monkeypatch, webhook_requests):
    import json

    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.example/api/webhooks/1/token")

    await DiscordChannel().send(make_alert())

    [request] = webhook_requests
    assert str(request.url) == "https://discord.example/api/webhooks/1/token"
    assert "[CRITICAL] SSH Brute Force" in json.loads(request.content)["content"]


@pytest.mark.asyncio
async def test_telegram_channel_posts_to_the_bot_api(monkeypatch, webhook_requests):
    import json

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(settings, "TELEGRAM_CHAT_ID", "-100200")

    await TelegramChannel().send(make_alert())

    [request] = webhook_requests
    assert str(request.url) == "https://api.telegram.org/bot123:abc/sendMessage"
    body = json.loads(request.content)
    assert body["chat_id"] == "-100200"
    assert "203.0.113.50" in body["text"]


@pytest.mark.asyncio
async def test_webhook_http_error_is_reported_as_a_failed_delivery(monkeypatch, webhook_requests):
    monkeypatch.setattr(settings, "DISCORD_WEBHOOK_URL", "https://discord.example/fail/secret-token")
    monkeypatch.setattr(dispatcher, "CHANNELS", [DiscordChannel()])

    [result] = await dispatcher.dispatch_alert(make_alert())

    assert result.delivered is False
    assert result.error == "HTTPStatusError"
    assert "secret-token" not in (result.error or "")


@pytest.mark.asyncio
async def test_dispatch_uses_configured_channels_and_isolates_failures(monkeypatch):
    working = _FakeChannel("working")
    broken = _FakeChannel("broken", fails=True)
    unconfigured = _FakeChannel("unconfigured", configured=False)
    monkeypatch.setattr(dispatcher, "CHANNELS", [broken, working, unconfigured])

    results = {r.channel: r for r in await dispatcher.dispatch_alert(make_alert())}

    assert results["working"].delivered is True
    assert len(working.sent) == 1

    assert results["broken"].delivered is False
    # The error must not leak the webhook URL (which embeds a secret).
    assert results["broken"].error == "ConnectionError"

    assert results["unconfigured"].configured is False
    assert unconfigured.sent == []


@pytest.mark.asyncio
async def test_background_dispatch_records_delivered_channels(mock_db, monkeypatch):
    from app.db.mongo import save_alert

    channel = _FakeChannel("working")
    monkeypatch.setattr(dispatcher, "CHANNELS", [channel])
    alert = make_alert()
    await save_alert(alert)

    await dispatcher._dispatch_and_record(alert)

    stored = await mock_db.alerts.find_one({"detection_id": "det-1"})
    assert stored["dispatched_channels"] == ["working"]


@pytest.mark.asyncio
async def test_channels_endpoint_and_test_alert(client, auth_headers, monkeypatch):
    channel = _FakeChannel("working")
    monkeypatch.setattr(dispatcher, "CHANNELS", [channel, _FakeChannel("off", configured=False)])

    analyst = await auth_headers("soc_analyst")
    status_response = await client.get("/api/v1/alerts/channels", headers=analyst)
    assert status_response.json() == {
        "channels": [{"channel": "working", "configured": True}, {"channel": "off", "configured": False}]
    }

    # Only admins may trigger outbound test messages.
    assert (await client.post("/api/v1/alerts/test", headers=analyst)).status_code == 403

    admin = await auth_headers("admin")
    sent = await client.post("/api/v1/alerts/test", headers=admin)
    assert sent.status_code == 200
    assert sent.json()["results"][0] == {
        "channel": "working",
        "configured": True,
        "delivered": True,
        "error": None,
    }
    assert len(channel.sent) == 1


@pytest.mark.asyncio
async def test_list_and_acknowledge_alerts(client, auth_headers, mock_db):
    from app.db.mongo import save_alert

    alert = make_alert()
    await save_alert(alert)
    headers = await auth_headers("soc_analyst")

    listed = await client.get("/api/v1/alerts", params={"acknowledged": "false"}, headers=headers)
    assert listed.json()["count"] == 1
    assert listed.json()["unacknowledged_total"] == 1

    acked = await client.post(f"/api/v1/alerts/{alert.id}/acknowledge", headers=headers)
    assert acked.status_code == 200
    assert acked.json()["acknowledged_by"] == "soc_analyst_user"

    after = await client.get("/api/v1/alerts", params={"acknowledged": "false"}, headers=headers)
    assert after.json()["count"] == 0
    assert (await client.post("/api/v1/alerts/not-an-id/acknowledge", headers=headers)).status_code == 404
