"""
app/api/v1/logs.py

Purpose:
    Log ingestion and search endpoints. Phase 2 implementation — routes
    are thin controllers that validate input, delegate to
    ingestion.pipeline.default_pipeline / db.elastic, and shape the
    response. No parsing, normalization, or storage logic lives here
    (Single Responsibility — this module's only job is HTTP concerns).

Connects to:
    - ingestion/pipeline.py::default_pipeline for upload/ingest processing
    - db/elastic.py::search_logs for the Live Monitoring / investigation view
    - db/mongo.py::list_ingestion_batches for ingestion audit trail
    - Protected by core/dependencies.py (all authenticated users can
      ingest and search; no role restriction at this layer since both
      admin and SOC analyst need to feed test data and investigate)
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.core.logging_config import get_logger
from app.db.elastic import search_logs
from app.db.mongo import list_ingestion_batches
from app.ingestion.pipeline import IngestionPipelineError, default_pipeline
from app.models.log_schema import LogUploadResponse, SourceType
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/logs", tags=["Log Ingestion"])
logger = get_logger(__name__)

_ALLOWED_EXTENSIONS = {".log", ".txt", ".json"}
_MAX_UPLOAD_BYTES = settings.MAX_UPLOAD_FILE_SIZE_MB * 1024 * 1024


class JSONIngestRequest:
    """
    Documented here rather than as a Pydantic model because the ingest
    body is intentionally schema-flexible (raw text blob for line-based
    sources, or a JSON array for Windows events) — see the /ingest
    endpoint below for the actual accepted shape via a plain dict body.
    """


@router.post("/upload", response_model=LogUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_log_file(
    source_type: SourceType = Form(..., description="windows | linux | firewall | web_server"),
    source_host: Optional[str] = Form(default=None),
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Accepts a log file (.log, .txt, .json) for a given source type and
    runs it through the full ingestion pipeline: parse -> normalize ->
    validate -> dedupe -> store in Elasticsearch, with batch metadata
    recorded in MongoDB.
    """
    _validate_extension(file.filename)

    raw_bytes = await file.read()
    if len(raw_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds max upload size of {settings.MAX_UPLOAD_FILE_SIZE_MB}MB",
        )

    try:
        raw_content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File must be UTF-8 encoded text")

    try:
        result = await default_pipeline.process(
            raw_content=raw_content,
            source_type=source_type,
            uploaded_by=current_user.username,
            source_host=source_host,
            filename=file.filename,
        )
    except IngestionPipelineError as exc:
        logger.error(f"Ingestion failed for user={current_user.username} file={file.filename}: {exc}")
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return result


@router.post("/ingest", response_model=LogUploadResponse, status_code=status.HTTP_201_CREATED)
async def ingest_raw_logs(
    body: dict,
    current_user: UserInDB = Depends(get_current_user),
):
    """
    JSON-body ingestion path — for programmatic testing or a future
    real-time shipper agent that POSTs instead of uploading a file.

    Expected body shape:
        {
          "source_type": "linux" | "windows" | "firewall" | "web_server",
          "source_host": "optional-hostname",
          "content": "raw log text OR JSON array as a string"
        }
    """
    try:
        source_type = SourceType(body.get("source_type"))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or invalid 'source_type'. Must be one of: "
            f"{[s.value for s in SourceType]}",
        )

    content = body.get("content")
    if not content or not isinstance(content, str):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="'content' must be a non-empty string")

    try:
        result = await default_pipeline.process(
            raw_content=content,
            source_type=source_type,
            uploaded_by=current_user.username,
            source_host=body.get("source_host"),
            filename=None,
        )
    except IngestionPipelineError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return result


@router.get("/search")
async def search_logs_endpoint(
    query: Optional[str] = Query(default=None, description="Free-text search over raw_log"),
    source_type: Optional[SourceType] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    size: int = Query(default=50, ge=1, le=500),
    from_: int = Query(default=0, ge=0, alias="from"),
    current_user: UserInDB = Depends(get_current_user),
):
    """Powers the Live Monitoring / investigation search UI."""
    result = await search_logs(
        query=query,
        source_type=source_type.value if source_type else None,
        severity=severity,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
        size=size,
        from_=from_,
    )
    return result


@router.get("/batches")
async def list_batches(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: UserInDB = Depends(get_current_user),
):
    """Ingestion audit trail — recent upload/ingest batches with outcome counts."""
    batches = await list_ingestion_batches(limit=limit)
    for b in batches:
        b["_id"] = str(b["_id"])
    return {"batches": batches}


def _validate_extension(filename: Optional[str]) -> None:
    if not filename or "." not in filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename must include an extension")

    ext = "." + filename.rsplit(".", 1)[-1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Allowed: {sorted(_ALLOWED_EXTENSIONS)}",
        )
