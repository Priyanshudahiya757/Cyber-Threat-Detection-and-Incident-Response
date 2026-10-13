"""
app/ingestion/parsers/base_parser.py

Purpose:
    Defines the contract every source-specific parser must implement
    (Strategy pattern). This is the seam that satisfies the Open/Closed
    Principle for ingestion: adding a new log source (e.g. a cloud
    provider's audit log) means writing one new class here and
    registering it in ingestion/pipeline.py's parser registry — no
    existing parser, and nothing in the pipeline orchestration, changes.

    Parsers deliberately do NOT produce NormalizedLog directly. They
    produce ParsedEvent, a source-agnostic-but-schema-light intermediate
    representation. Mapping ParsedEvent -> NormalizedLog is the
    responsibility of ingestion/normalizer.py. Splitting these two
    concerns (extraction vs. schema-mapping) means a parsing bug fix
    never risks touching normalization logic and vice versa (SRP).

Connects to:
    - Implemented by linux_parser.py, windows_parser.py, firewall_parser.py,
      web_parser.py
    - Consumed by ingestion/pipeline.py, which selects the correct parser
      via PARSER_REGISTRY keyed on SourceType
    - ParsedEvent is consumed by ingestion/normalizer.py
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.log_schema import EventCategory, SourceType


class LogParsingError(Exception):
    """
    Raised when a parser cannot make sense of a line/record at all
    (as opposed to a line that parses but fails schema validation later,
    which is handled by the normalizer/pipeline as a per-record rejection).
    """


class ParsedEvent(BaseModel):
    """
    Source-agnostic intermediate representation. Every parser emits a
    list of these; the normalizer turns each one into a NormalizedLog.
    Fields mirror NormalizedLog closely on purpose, but `severity` and
    `log_id` are deliberately absent here — severity defaulting and ID
    assignment are normalization/pipeline concerns, not parsing concerns.
    """
    event_category: EventCategory
    event_type: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    raw_log: str
    parsed_fields: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
    severity_hint: Optional[str] = Field(
        default=None,
        description="Optional parser-suggested severity; normalizer may override via rules.",
    )


class BaseLogParser(ABC):
    """
    Abstract parser contract. Subclasses must be stateless and thread-safe
    (no mutable instance state beyond what's set in __init__), since a
    single parser instance is reused across every file/request of its
    source type for the lifetime of the process.
    """

    #: Overridden by each subclass; used by the pipeline's parser registry
    #: and included in log messages / error responses.
    source_type: SourceType

    @abstractmethod
    def parse(self, raw_content: str, source_host: Optional[str] = None) -> List[ParsedEvent]:
        """
        Parse raw log text (one or more records) into a list of ParsedEvent.

        Implementations MUST NOT raise on a single malformed line/record —
        skip it and continue, so one bad line doesn't discard an entire
        upload. Only raise LogParsingError if the content as a whole is
        unparseable (e.g. invalid JSON where JSON was required).

        Args:
            raw_content: Full raw text of the uploaded file or JSON body.
            source_host: Optional hostname/identifier of the log source,
                used to populate NormalizedLog.source_host downstream.

        Returns:
            List of ParsedEvent, one per recognized log record. May be
            empty if nothing in raw_content matched this parser's format.
        """
        raise NotImplementedError
