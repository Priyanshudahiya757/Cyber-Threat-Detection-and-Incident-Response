"""
app/alerts/channels.py

Purpose:
    One class per external alert destination (Strategy pattern, mirroring
    ingestion/parsers and detection/rules). A channel knows two things:
    whether its credentials are configured, and how to deliver one Alert.
    Adding a destination (Slack, PagerDuty, ...) means adding one class
    here and listing it in alerts/dispatcher.py.

Connects to:
    - core/config.py for SMTP / webhook credentials
    - alerts/dispatcher.py fans an alert out to every configured channel
"""
import asyncio
import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage

import httpx

from app.core.config import settings
from app.models.alert_schema import Alert

_TIMEOUT_SECONDS = 10


def format_alert_text(alert: Alert) -> str:
    """Plain-text rendering shared by every channel."""
    lines = [
        f"[{str(alert.severity).upper()}] {alert.title}",
        f"Entity: {alert.entity.value} ({alert.entity.type})",
    ]
    if alert.mitre_technique:
        lines.append(f"MITRE ATT&CK: {alert.mitre_technique}")
    lines.append("")
    lines.append(alert.description)
    return "\n".join(lines)


class AlertChannel(ABC):
    #: Short identifier stored in Alert.dispatched_channels and shown in the UI.
    name: str

    @abstractmethod
    def is_configured(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def send(self, alert: Alert) -> None:
        """Deliver `alert`. Raises on any delivery failure."""
        raise NotImplementedError


class EmailChannel(AlertChannel):
    name = "email"

    def is_configured(self) -> bool:
        return bool(settings.SMTP_HOST and settings.ALERT_EMAIL_FROM and settings.ALERT_EMAIL_TO)

    async def send(self, alert: Alert) -> None:
        message = EmailMessage()
        message["Subject"] = f"[{str(alert.severity).upper()}] {alert.title}"
        message["From"] = settings.ALERT_EMAIL_FROM
        message["To"] = ", ".join(settings.ALERT_EMAIL_TO)
        message.set_content(format_alert_text(alert))
        # smtplib is blocking; keep it off the event loop.
        await asyncio.to_thread(self._send_blocking, message)

    @staticmethod
    def _send_blocking(message: EmailMessage) -> None:
        # Port 465 expects TLS from the first byte; other ports upgrade with STARTTLS.
        implicit_tls = settings.SMTP_PORT == 465
        smtp_class = smtplib.SMTP_SSL if implicit_tls else smtplib.SMTP
        with smtp_class(settings.SMTP_HOST, settings.SMTP_PORT, timeout=_TIMEOUT_SECONDS) as smtp:
            smtp.ehlo()
            if not implicit_tls and smtp.has_extn("starttls"):
                smtp.starttls()
                smtp.ehlo()
            if settings.SMTP_USERNAME:
                smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            smtp.send_message(message)


class DiscordChannel(AlertChannel):
    name = "discord"

    def is_configured(self) -> bool:
        return bool(settings.DISCORD_WEBHOOK_URL)

    async def send(self, alert: Alert) -> None:
        # Discord rejects messages longer than 2000 characters.
        payload = {"content": format_alert_text(alert)[:1900]}
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(settings.DISCORD_WEBHOOK_URL, json=payload)
            response.raise_for_status()


class TelegramChannel(AlertChannel):
    name = "telegram"

    def is_configured(self) -> bool:
        return bool(settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID)

    async def send(self, alert: Alert) -> None:
        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": settings.TELEGRAM_CHAT_ID, "text": format_alert_text(alert)[:4000]}
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
