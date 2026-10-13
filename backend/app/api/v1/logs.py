"""
app/api/v1/logs.py

Purpose:
    Log ingestion and search endpoints. Routes are thin controllers that
    validate input, delegate to ingestion.pipeline.default_pipeline /
    db.elastic, and shape the response. No parsing, normalization, or
    storage logic lives here.

Connects to:
    - ingestion/pipeline.py::default_pipeline for upload/ingest processing
    - db/elastic.py::search_logs for the Live Monitoring / investigation view
    - db/mongo.py::list_ingestion_batches for the ingestion audit trail
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.core.logging_config import get_logger
from app.db.elastic import MAX_RESULT_WINDOW, search_logs
from app.db.mongo import list_ingestion_batches
from app.ingestion.pipeline import IngestionPipelineError, default_pipeline
from app.models.log_schema import LogUploadResponse, Severity, SourceType
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/logs", tags=["Log Ingestion"])
logger = get_logger(__name__)

_ALLOWED_EXTENSIONS = {".log", ".txt", ".json"}
_READ_CHUNK_BYTES = 1024 * 1024
_TOO_LARGE = HTTPException(
    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    detail=f"Content exceeds the maximum size of {settings.MAX_UPLOAD_FILE_SIZE_MB}MB",
)


class LogIngestRequest(BaseModel):
    source_type: SourceType
    source_host: Optional[str] = Field(default=None, max_length=255)
    content: str = Field(..., min_length=1, description="Raw log text, or a JSON array as a string")


async def _read_limited(file: UploadFile) -> bytes:
    """Read an upload in chunks, aborting as soon as it exceeds the size limit."""
    chunks, total = [], 0
    while chunk := await file.read(_READ_CHUNK_BYTES):
        total += len(chunk)
        if total > settings.max_upload_bytes:
            raise _TOO_LARGE
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_extension(filename: Optional[str]) -> None:
    extension = "." + filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else ""
    if extension not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type. Allowed extensions: {sorted(_ALLOWED_EXTENSIONS)}",
        )


async def _ingest(
    content: str, source_type: SourceType, source_host: Optional[str], filename: Optional[str], user: UserInDB
) -> LogUploadResponse:
    try:
        return await default_pipeline.process(
            raw_content=content,
            source_type=source_type,
            uploaded_by=user.username,
            source_host=source_host or None,
            filename=filename,
        )
    except IngestionPipelineError as exc:
        logger.error(f"Ingestion failed for user={user.username} source={source_type.value}: {exc}")
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


@router.post("/upload", response_model=LogUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_log_file(
    source_type: SourceType = Form(..., description="windows | linux | firewall | web_server"),
    source_host: Optional[str] = Form(default=None, max_length=255),
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Accepts a log file (.log, .txt, .json) for a given source type and
    runs it through the full ingestion pipeline: parse -> normalize ->
    dedupe -> store in Elasticsearch -> detect, with batch metadata
    recorded in MongoDB.
    """
    _validate_extension(file.filename)
    raw_bytes = await _read_limited(file)

    try:
        content = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File must be UTF-8 encoded text")

    return await _ingest(content, source_type, source_host, file.filename, current_user)


@router.post("/ingest", response_model=LogUploadResponse, status_code=status.HTTP_201_CREATED)
async def ingest_raw_logs(body: LogIngestRequest, current_user: UserInDB = Depends(get_current_user)):
    """JSON-body ingestion — for programmatic use or a log shipper that POSTs instead of uploading a file."""
    if len(body.content.encode("utf-8")) > settings.max_upload_bytes:
        raise _TOO_LARGE
    return await _ingest(body.content, body.source_type, body.source_host, None, current_user)


@router.get("/search")
async def search_logs_endpoint(
    query: Optional[str] = Query(default=None, max_length=500, description="Free-text search over the raw log line"),
    source_type: Optional[SourceType] = None,
    severity: Optional[Severity] = None,
    source_ip: Optional[str] = Query(default=None, max_length=45),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    size: int = Query(default=50, ge=1, le=500),
    from_: int = Query(default=0, ge=0, le=MAX_RESULT_WINDOW - 500, alias="from"),
    current_user: UserInDB = Depends(get_current_user),
):
    """Powers the Live Monitoring / investigation search UI."""
    try:
        return await search_logs(
            query=query,
            source_type=source_type.value if source_type else None,
            severity=severity.value if severity else None,
            source_ip=source_ip,
            start_time=start_time,
            end_time=end_time,
            size=size,
            from_=from_,
        )
    except Exception as exc:
        # e.g. `source_ip` that is not a valid IP makes Elasticsearch reject the query.
        logger.warning(f"Log search failed: {exc}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Search could not be run with these filters")


@router.get("/batches")
async def list_batches(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: UserInDB = Depends(get_current_user),
):
    """Ingestion audit trail — recent upload/ingest batches with outcome counts."""
    return {"batches": await list_ingestion_batches(limit=limit)}
