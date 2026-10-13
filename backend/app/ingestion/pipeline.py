"""
app/ingestion/pipeline.py

Purpose:
    Orchestrates the full ingestion flow for a single upload/ingest
    request: select parser -> parse -> normalize -> validate -> dedupe ->
    bulk-index into Elasticsearch -> persist batch metadata into MongoDB.

    This is intentionally the ONLY place that sequences those steps.
    Callers (the API layer) never touch parsers, the normalizer, or the
    ES/Mongo repositories directly — they call `IngestionPipeline.process()`
    and get back a LogUploadResponse. This keeps the API layer thin and
    means the ingestion sequence can be unit-tested independently of
    FastAPI (see tests/test_ingestion_pipeline.py).

    Dependency injection: the pipeline is constructed with its parser
    registry and (optionally) an `on_ingested` callback, rather than
    importing detection/analytics logic directly. This keeps ingestion
    decoupled from detection (Dependency Inversion — the pipeline depends
    on an abstract callback, not on the concrete rule engine), and the
    `on_ingested` hook is what Phase 3 wires up to trigger detection
    automatically after new logs land — see app/main.py for the wiring.

Connects to:
    - api/v1/logs.py calls IngestionPipeline.process()
    - ingestion/parsers/* supply the PARSER_REGISTRY
    - ingestion/normalizer.py for ParsedEvent -> NormalizedLog
    - db/elastic.py for dedup check + bulk indexing
    - db/mongo.py for batch metadata persistence
"""
import uuid
from typing import Awaitable, Callable, Dict, List, Optional

from pydantic import ValidationError

from app.core.logging_config import get_logger
from app.db.elastic import bulk_index_logs, check_existing_log_ids
from app.db.mongo import save_ingestion_batch
from app.ingestion.normalizer import normalize
from app.ingestion.parsers.base_parser import BaseLogParser, LogParsingError
from app.ingestion.parsers.firewall_parser import FirewallLogParser
from app.ingestion.parsers.linux_parser import LinuxAuthLogParser
from app.ingestion.parsers.web_parser import WebServerLogParser
from app.ingestion.parsers.windows_parser import WindowsEventLogParser
from app.models.log_schema import IngestionBatch, LogUploadResponse, NormalizedLog, SourceType

logger = get_logger(__name__)

#: Parser registry (Strategy pattern). Adding a new source type means
#: adding one entry here — nothing else in this file changes.
PARSER_REGISTRY: Dict[SourceType, BaseLogParser] = {
    SourceType.LINUX: LinuxAuthLogParser(),
    SourceType.WINDOWS: WindowsEventLogParser(),
    SourceType.FIREWALL: FirewallLogParser(),
    SourceType.WEB_SERVER: WebServerLogParser(),
}

#: Type of the optional post-ingestion hook (e.g. triggering rule-based
#: and ML detection on the freshly ingested batch). Registered by
#: app/main.py at startup so ingestion never imports detection directly.
OnIngestedCallback = Callable[[List[NormalizedLog]], Awaitable[None]]


class IngestionPipelineError(Exception):
    """Raised for unrecoverable pipeline failures (unknown source type, etc.)."""


class IngestionPipeline:
    """
    Orchestrates parse -> normalize -> validate -> dedupe -> store for a
    single ingestion request. Stateless aside from the injected parser
    registry and callback, so a single instance is safe to reuse (and to
    construct fresh in tests with a mock registry).
    """

    def __init__(
        self,
        parser_registry: Optional[Dict[SourceType, BaseLogParser]] = None,
        on_ingested: Optional[OnIngestedCallback] = None,
    ):
        self._parsers = parser_registry if parser_registry is not None else PARSER_REGISTRY
        self._on_ingested = on_ingested

    def register_on_ingested_callback(self, callback: OnIngestedCallback) -> None:
        """
        Registers the post-ingestion hook. Called once from app/main.py at
        startup to wire up the detection engine (Phase 3) without
        ingestion importing detection directly (Dependency Inversion).
        """
        self._on_ingested = callback

    async def process(
        self,
        raw_content: str,
        source_type: SourceType,
        uploaded_by: str,
        source_host: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> LogUploadResponse:
        """
        Run the full ingestion pipeline on raw log content.

        Never raises for per-record problems (malformed lines, schema
        validation failures) — those are collected into the response's
        `errors` list. Only raises IngestionPipelineError for structural
        problems (unknown source_type, or content unparseable as a whole).
        """
        batch_id = str(uuid.uuid4())
        parser = self._get_parser(source_type)

        parsed_events, parse_errors = self._parse_safely(parser, raw_content, source_host)

        normalized_logs, normalize_errors = self._normalize_safely(parsed_events, source_type, source_host)

        deduped_logs, duplicate_count = await self._deduplicate(normalized_logs)

        if deduped_logs:
            index_result = await bulk_index_logs(deduped_logs)
            logger.info(
                f"IngestionPipeline: batch={batch_id} source={source_type} "
                f"indexed={index_result['accepted']} index_rejected={index_result['rejected']}"
            )
        else:
            logger.info(f"IngestionPipeline: batch={batch_id} source={source_type} nothing new to index")

        all_errors = parse_errors + normalize_errors
        response = LogUploadResponse(
            accepted=len(deduped_logs),
            rejected=len(all_errors),
            duplicates=duplicate_count,
            errors=all_errors[:50],  # cap response size; full errors are in logs
            log_ids=[log.log_id for log in deduped_logs],
            batch_id=batch_id,
        )

        await self._persist_batch_metadata(
            batch_id=batch_id,
            source_type=source_type,
            source_host=source_host,
            filename=filename,
            uploaded_by=uploaded_by,
            total_records=len(parsed_events) + len(parse_errors),
            response=response,
        )

        if deduped_logs and self._on_ingested is not None:
            try:
                await self._on_ingested(deduped_logs)
            except Exception as exc:
                # Detection failures must never roll back or fail an
                # otherwise-successful ingestion — logs are already safely
                # stored. Log loudly and move on.
                logger.error(f"IngestionPipeline: on_ingested callback failed for batch={batch_id}: {exc}")

        return response

    def _get_parser(self, source_type: SourceType) -> BaseLogParser:
        parser = self._parsers.get(source_type)
        if parser is None:
            raise IngestionPipelineError(f"No parser registered for source type '{source_type}'")
        return parser

    def _parse_safely(self, parser: BaseLogParser, raw_content: str, source_host: Optional[str]):
        try:
            events = parser.parse(raw_content, source_host=source_host)
        except LogParsingError as exc:
            logger.error(f"IngestionPipeline: parser {type(parser).__name__} failed: {exc}")
            raise IngestionPipelineError(str(exc)) from exc
        return events, []

    def _normalize_safely(self, parsed_events, source_type: SourceType, source_host: Optional[str]):
        normalized: List[NormalizedLog] = []
        errors: List[str] = []

        for idx, event in enumerate(parsed_events):
            try:
                normalized.append(normalize(event, source_type=source_type, source_host=source_host))
            except ValidationError as exc:
                error_msg = f"Record {idx}: normalization failed - {exc.errors()[0]['msg']}"
                logger.warning(f"IngestionPipeline: {error_msg}")
                errors.append(error_msg)

        return normalized, errors

    async def _deduplicate(self, normalized_logs: List[NormalizedLog]):
        if not normalized_logs:
            return [], 0

        existing_ids = await check_existing_log_ids([log.log_id for log in normalized_logs])
        new_logs = [log for log in normalized_logs if log.log_id not in existing_ids]
        duplicate_count = len(normalized_logs) - len(new_logs)

        if duplicate_count:
            logger.info(f"IngestionPipeline: {duplicate_count} duplicate log(s) skipped")

        return new_logs, duplicate_count

    async def _persist_batch_metadata(
        self,
        batch_id: str,
        source_type: SourceType,
        source_host: Optional[str],
        filename: Optional[str],
        uploaded_by: str,
        total_records: int,
        response: LogUploadResponse,
    ) -> None:
        batch = IngestionBatch(
            batch_id=batch_id,
            source_type=source_type,
            source_host=source_host,
            filename=filename,
            uploaded_by=uploaded_by,
            total_records=total_records,
            accepted=response.accepted,
            rejected=response.rejected,
            duplicates=response.duplicates,
            errors=response.errors,
        )
        try:
            await save_ingestion_batch(batch)
        except Exception as exc:
            # Metadata persistence failure shouldn't fail the ingestion
            # response — the logs are already safely in Elasticsearch.
            logger.error(f"IngestionPipeline: failed to persist batch metadata for {batch_id}: {exc}")


#: Process-wide singleton used by the API layer (app/api/v1/logs.py) and
#: configured with the detection callback at startup (app/main.py). A
#: singleton is appropriate here since the pipeline is stateless beyond
#: its registry/callback references.
default_pipeline = IngestionPipeline()
