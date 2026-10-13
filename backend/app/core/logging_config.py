"""
app/core/logging_config.py

Purpose:
    Configures logging for the entire backend. A SIEM has to log its
    own operational and security events reliably, so this sets up:
      - Console logging (human-readable, dev)
      - Rotating file logging (JSON-ish, for later ingestion/audit)
      - A dedicated "audit" logger for security-relevant app events
        (login attempts, role changes, incident status changes) separate
        from general app logs.

Connects to:
    - Called once from main.py at startup (setup_logging())
    - `get_logger(__name__)` is used across api/, ingestion/, detection/,
      incidents/, alerts/ instead of raw `logging.getLogger`.
"""
import json
import logging
import logging.handlers
import os
import sys

LOG_DIR = os.getenv("LOG_DIR", "./logs")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

_CONSOLE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_AUDIT_FORMAT = '{"time": "%(asctime)s", "audit": %(message)s}'


def setup_logging() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    root.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(_CONSOLE_FORMAT))
    root.addHandler(console_handler)

    app_file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "app.log"), maxBytes=5_000_000, backupCount=5
    )
    app_file_handler.setFormatter(logging.Formatter(_CONSOLE_FORMAT))
    root.addHandler(app_file_handler)

    # The Elasticsearch transport logs every request at INFO, which drowns
    # out the application's own messages.
    logging.getLogger("elastic_transport").setLevel(logging.WARNING)

    # Dedicated audit trail: auth events, role/permission changes,
    # incident status transitions. Kept separate so it can be shipped
    # to the SIEM's own log pipeline later ("eating our own dog food").
    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    audit_handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "audit.log"), maxBytes=5_000_000, backupCount=10
    )
    audit_handler.setFormatter(logging.Formatter(_AUDIT_FORMAT))
    audit_logger.addHandler(audit_handler)
    audit_logger.addHandler(console_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def audit_event(event: str, **fields: object) -> None:
    """
    Write one security-relevant event to the audit trail. Fields are
    JSON-encoded here, so user-controlled values (usernames, notes) can
    never break out of their field or forge additional ones.
    """
    logging.getLogger("audit").info(json.dumps({"event": event, **fields}, default=str))
