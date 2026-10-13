"""
tests/test_ingestion_pipeline.py

Purpose:
    Tests the pipeline orchestration logic (parse -> normalize -> dedupe
    -> store -> callback) in isolation from real Elasticsearch/MongoDB,
    by monkeypatching the repository functions the pipeline calls. This
    is the pattern documented in tests/conftest.py for anything that
    touches Elasticsearch: mock at the function boundary rather than
    standing up a fake ES.
"""
import pytest

from app.ingestion.pipeline import IngestionPipeline, IngestionPipelineError
from app.models.log_schema import SourceType

LINUX_SAMPLE = (
    "Jul 18 09:12:03 web01 sshd[14231]: Failed password for root from 192.168.1.20 port 51422 ssh2\n"
    "Jul 18 09:12:05 web01 sshd[14231]: Failed password for root from 192.168.1.20 port 51424 ssh2\n"
)


@pytest.fixture
def mock_elastic(monkeypatch):
    """Mocks db.elastic functions used by the pipeline; records calls for assertions."""
    calls = {"indexed": [], "checked": []}

    async def fake_check_existing_log_ids(log_ids):
        calls["checked"].append(list(log_ids))
        return set()  # nothing exists yet by default

    async def fake_bulk_index_logs(logs):
        calls["indexed"].append(list(logs))
        return {"accepted": len(logs), "rejected": 0}

    monkeypatch.setattr("app.ingestion.pipeline.check_existing_log_ids", fake_check_existing_log_ids)
    monkeypatch.setattr("app.ingestion.pipeline.bulk_index_logs", fake_bulk_index_logs)
    return calls


@pytest.fixture
def mock_mongo_batches(monkeypatch):
    saved = []

    async def fake_save_ingestion_batch(batch):
        saved.append(batch)

    monkeypatch.setattr("app.ingestion.pipeline.save_ingestion_batch", fake_save_ingestion_batch)
    return saved


@pytest.mark.asyncio
class TestIngestionPipeline:
    async def test_process_parses_and_indexes_new_logs(self, mock_elastic, mock_mongo_batches):
        pipeline = IngestionPipeline()

        response = await pipeline.process(
            raw_content=LINUX_SAMPLE,
            source_type=SourceType.LINUX,
            uploaded_by="analyst1",
            source_host="web01",
        )

        assert response.accepted == 2
        assert response.rejected == 0
        assert response.duplicates == 0
        assert len(response.log_ids) == 2
        assert len(mock_elastic["indexed"]) == 1
        assert len(mock_elastic["indexed"][0]) == 2

    async def test_process_persists_batch_metadata(self, mock_elastic, mock_mongo_batches):
        pipeline = IngestionPipeline()
        await pipeline.process(
            raw_content=LINUX_SAMPLE,
            source_type=SourceType.LINUX,
            uploaded_by="analyst1",
            source_host="web01",
            filename="auth.log",
        )

        assert len(mock_mongo_batches) == 1
        batch = mock_mongo_batches[0]
        assert batch.uploaded_by == "analyst1"
        assert batch.filename == "auth.log"
        assert batch.accepted == 2

    async def test_process_skips_duplicates(self, mock_elastic, mock_mongo_batches, monkeypatch):
        # Simulate both log_ids already existing in ES.
        from app.ingestion.normalizer import compute_log_id

        async def fake_check_existing_all_exist(log_ids):
            return set(log_ids)

        monkeypatch.setattr(
            "app.ingestion.pipeline.check_existing_log_ids", fake_check_existing_all_exist
        )

        pipeline = IngestionPipeline()
        response = await pipeline.process(
            raw_content=LINUX_SAMPLE,
            source_type=SourceType.LINUX,
            uploaded_by="analyst1",
            source_host="web01",
        )

        assert response.accepted == 0
        assert response.duplicates == 2
        assert len(mock_elastic["indexed"]) == 0  # nothing new to index

    async def test_unknown_source_type_raises(self, mock_elastic, mock_mongo_batches):
        pipeline = IngestionPipeline(parser_registry={})  # empty registry

        with pytest.raises(IngestionPipelineError):
            await pipeline.process(
                raw_content=LINUX_SAMPLE,
                source_type=SourceType.LINUX,
                uploaded_by="analyst1",
            )

    async def test_on_ingested_callback_invoked_with_new_logs(self, mock_elastic, mock_mongo_batches):
        received = []

        async def callback(logs):
            received.extend(logs)

        pipeline = IngestionPipeline(on_ingested=callback)
        await pipeline.process(
            raw_content=LINUX_SAMPLE,
            source_type=SourceType.LINUX,
            uploaded_by="analyst1",
        )

        assert len(received) == 2

    async def test_on_ingested_callback_not_invoked_when_nothing_new(
        self, mock_elastic, mock_mongo_batches, monkeypatch
    ):
        async def fake_check_existing_all_exist(log_ids):
            return set(log_ids)

        monkeypatch.setattr(
            "app.ingestion.pipeline.check_existing_log_ids", fake_check_existing_all_exist
        )

        called = {"count": 0}

        async def callback(logs):
            called["count"] += 1

        pipeline = IngestionPipeline(on_ingested=callback)
        await pipeline.process(
            raw_content=LINUX_SAMPLE,
            source_type=SourceType.LINUX,
            uploaded_by="analyst1",
        )

        assert called["count"] == 0

    async def test_callback_failure_does_not_fail_ingestion(self, mock_elastic, mock_mongo_batches):
        async def failing_callback(logs):
            raise RuntimeError("detection engine exploded")

        pipeline = IngestionPipeline(on_ingested=failing_callback)
        response = await pipeline.process(
            raw_content=LINUX_SAMPLE,
            source_type=SourceType.LINUX,
            uploaded_by="analyst1",
        )

        # Ingestion still succeeds even though the callback raised.
        assert response.accepted == 2

    async def test_malformed_lines_are_skipped_not_fatal(self, mock_elastic, mock_mongo_batches):
        content = LINUX_SAMPLE + "this is garbage that matches nothing\n"
        pipeline = IngestionPipeline()

        response = await pipeline.process(
            raw_content=content,
            source_type=SourceType.LINUX,
            uploaded_by="analyst1",
        )

        # The garbage line is silently skipped by the parser (by design —
        # syslog mixes many subsystems), so it never becomes a ParsedEvent
        # and therefore isn't counted as rejected; it just isn't ingested.
        assert response.accepted == 2
