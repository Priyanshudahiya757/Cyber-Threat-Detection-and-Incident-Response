"""
app/alerts/dispatcher.py

Purpose:
    Delivers an Alert to every configured external channel and reports
    what happened per channel. One channel failing (SMTP down, webhook
    revoked) never stops delivery to the others and never raises to the
    caller — alert delivery is best-effort and must not break detection.

Connects to:
    - alerts/channels.py for the channel implementations
    - detection/alerting.py dispatches each newly created alert in the background
    - api/v1/alerts.py exposes channel status and a "send test alert" action
"""
import asyncio
from typing import List, Optional, Set

from pydantic import BaseModel

from app.alerts.channels import AlertChannel, DiscordChannel, EmailChannel, TelegramChannel
from app.core.logging_config import get_logger
from app.db.mongo import set_alert_dispatched_channels
from app.models.alert_schema import Alert

logger = get_logger(__name__)

CHANNELS: List[AlertChannel] = [EmailChannel(), DiscordChannel(), TelegramChannel()]

#: Strong references to in-flight background deliveries; asyncio only
#: keeps weak ones, so an unreferenced task could be garbage-collected.
_background_tasks: Set[asyncio.Task] = set()


class ChannelResult(BaseModel):
    channel: str
    configured: bool
    delivered: bool = False
    error: Optional[str] = None


def channel_status() -> List[ChannelResult]:
    """Which channels have credentials configured (no delivery attempted)."""
    return [ChannelResult(channel=c.name, configured=c.is_configured()) for c in CHANNELS]


async def _deliver(channel: AlertChannel, alert: Alert) -> ChannelResult:
    if not channel.is_configured():
        return ChannelResult(channel=channel.name, configured=False)
    try:
        await channel.send(alert)
    except Exception as exc:
        logger.error(f"AlertDispatcher: {channel.name} delivery failed: {exc}")
        # Exception text can embed the request URL, which for webhooks
        # contains the secret token — report only the error type.
        return ChannelResult(channel=channel.name, configured=True, error=type(exc).__name__)
    return ChannelResult(channel=channel.name, configured=True, delivered=True)


async def dispatch_alert(alert: Alert) -> List[ChannelResult]:
    """Send `alert` to all channels concurrently and return one result per channel."""
    return list(await asyncio.gather(*(_deliver(channel, alert) for channel in CHANNELS)))


async def _dispatch_and_record(alert: Alert) -> None:
    results = await dispatch_alert(alert)
    delivered = [r.channel for r in results if r.delivered]
    if delivered and alert.id:
        try:
            await set_alert_dispatched_channels(alert.id, delivered)
        except Exception as exc:
            logger.error(f"AlertDispatcher: could not record delivery for alert {alert.id}: {exc}")


def dispatch_in_background(alert: Alert) -> None:
    """
    Fire-and-forget delivery for a persisted alert, so slow SMTP servers or
    webhooks never delay the ingestion request that produced the alert.
    No-op when no channel is configured.
    """
    if not any(channel.is_configured() for channel in CHANNELS):
        return
    task = asyncio.create_task(_dispatch_and_record(alert))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
