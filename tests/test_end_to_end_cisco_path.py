"""
tests/test_end_to_end_cisco_path.py

Automated tests for GitHub Issue #12 covering all 8 acceptance criteria:
1. Original event remains unchanged.
2. Raw-event hash can be verified.
3. Parser and schema versions are recorded.
4. Normalized output links back to raw event.
5. Event is visible in analytical visibility / searchable store.
6. Normalized JSON output is produced.
7. Invalid logs are retained and marked, not silently discarded.
8. Data lake export produces partitioned files and manifest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from core.engine import ParsingEngine
from src.collection.archive import RawEventArchive
from src.collection.pipeline import CollectionPipeline
from src.collection.publisher import InMemoryPublisher
from src.normalization import UniversalNormalizer, default_registry
from src.pipeline.exporter import DataLakeExporter
from src.pipeline.runner import PipelineRunner
from src.pipeline.storage import AnalyticalVisibilityStore
from src.validation.validate_unified_event import validate_event


@pytest.fixture
def clean_runner(tmp_path: Path):
    store = AnalyticalVisibilityStore()
    exporter = DataLakeExporter(base_dir=tmp_path / "lake_exports")
    return PipelineRunner(
        collector=CollectionPipeline(
            publisher=InMemoryPublisher(),
            archive=RawEventArchive(tmp_path / "raw_archive"),
        ),
        engine=ParsingEngine(Path("source_packs")),
        normalizer=UniversalNormalizer(default_registry()),
        store=store,
        exporter=exporter,
    )


def process(runner: PipelineRunner, raw_log: bytes | str):
    return runner.process(raw_log, transport="file", source_id="cisco-test")


def test_criterion_1_and_2_raw_payload_unchanged_and_hash_verified(clean_runner):
    """Criteria 1 & 2: Payload unchanged and SHA-256 is verified."""
    raw_log = (
        "<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
        "Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.5/443 "
        'by access-group "OUTSIDE_IN"'
    )
    raw_bytes = raw_log.encode("utf-8")
    expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    result = process(clean_runner, raw_log)
    ue = result.unified

    # Criterion 1: Unchanged payload preserved
    assert ue["traceability"]["raw_event"]["content"] == raw_log

    # Criterion 2: Verified hash
    assert result.raw_event.raw_sha256 == expected_sha256
    assert ue["traceability"]["raw_sha256"] == expected_sha256


def test_criterion_3_parser_and_schema_versions_recorded(clean_runner):
    """Criterion 3: Parser, source pack, and schema versions are explicitly recorded."""
    raw_log = (
        "<166>Oct 12 2023 14:23:05 asa-fw1 : %ASA-6-302013: "
        "Built inbound TCP connection 123456 for outside:203.0.113.5/54321 "
        "to inside:10.0.0.5/443"
    )
    result = process(clean_runner, raw_log)
    ue = result.unified

    assert ue["schema_version"] == "1.0.0"
    assert ue["traceability"]["source_pack"]["version"] == "1.0.0"
    assert ue["traceability"]["parser"]["version"] == "1.0.0"


def test_criterion_4_normalized_output_links_to_raw_event(clean_runner):
    """Criterion 4: Normalized event links back to the raw event by ID and hash."""
    raw_log = (
        "<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
        "Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.5/443 "
        'by access-group "OUTSIDE_IN"'
    )
    result = process(clean_runner, raw_log)
    ue = result.unified

    assert "raw_event_id" in ue["traceability"]
    assert "raw_sha256" in ue["traceability"]
    assert ue["traceability"]["raw_sha256"] == result.raw_event.raw_sha256


def test_criterion_5_analytical_visibility_and_search(clean_runner):
    """Criterion 5: Event is indexed and visible in analytical search and aggregations."""
    logs = [
        (
            "<166>Oct 12 2023 14:23:01 fw1 : %ASA-4-106023: Deny tcp "
            'src outside:203.0.113.10/5000 dst inside:10.0.0.1/80 by access-group "ACL1"'
        ),
        (
            "<166>Oct 12 2023 14:23:05 fw1 : %ASA-6-302013: Built inbound TCP connection 101 "
            "for outside:203.0.113.20/6000 to inside:10.0.0.2/443"
        ),
    ]
    clean_runner.process_batch(logs, transport="file", source_id="cisco-batch")

    # Search by action
    denies = clean_runner.store.search(action="deny")
    assert len(denies) == 1
    assert denies[0]["action"]["normalized"] == "deny"

    # Search by IP
    ip_search = clean_runner.store.search(query="203.0.113.20")
    assert len(ip_search) == 1

    # Aggregations
    aggs = clean_runner.store.get_aggregations()
    assert aggs["total_events"] == 2
    assert aggs["allow_vs_deny"]["allow_count"] == 1
    assert aggs["allow_vs_deny"]["deny_count"] == 1


def test_criterion_6_normalized_json_schema_valid(clean_runner):
    """Criterion 6: Normalized JSON output strictly satisfies UnifiedEvent schema v1.0.0."""
    raw_log = (
        "<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
        "Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.5/443 "
        'by access-group "OUTSIDE_IN"'
    )
    result = process(clean_runner, raw_log)
    ue = result.unified

    # Verify JSON serializability
    json_str = json.dumps(ue)
    assert json_str is not None

    # Validate against schema
    val_res = validate_event(ue)
    assert val_res.valid is True, f"Schema validation issues: {val_res.issues}"


def test_criterion_7_invalid_logs_retained_and_marked(clean_runner):
    """Criterion 7: Unrecognized logs are retained with quality warnings and never dropped."""
    corrupt_log = "<134>1 2023-10-12T14:23:25Z corrupt random non-syslog line \x00\x01\x02"
    result = process(clean_runner, corrupt_log)
    ue = result.unified

    assert result.parsed.status.value in {"unrecognized", "failed"}
    assert ue["quality"]["status"] in {"invalid", "partial", "unknown"}
    assert len(ue["quality"]["warnings"]) > 0
    # Payload is preserved verbatim
    assert ue["traceability"]["raw_event"]["content"] == corrupt_log

    # Stored in visibility store
    found = clean_runner.store.get_by_raw_hash(result.raw_event.raw_sha256)
    assert found is not None


def test_criterion_8_data_lake_export_and_manifest(clean_runner, tmp_path: Path):
    """Criterion 8: Events exported to JSONL data lake with manifest verification."""
    logs = [
        (
            "<166>Oct 12 2023 14:23:01 fw1 : %ASA-4-106023: Deny tcp "
            'src outside:203.0.113.10/5000 dst inside:10.0.0.1/80 by access-group "ACL1"'
        ),
        "corrupt-garbage-log-data-not-dropped",
    ]
    clean_runner.process_batch(logs, transport="file", source_id="cisco-batch")

    export_dir = clean_runner.exporter.base_dir
    valid_file = export_dir / "ulpf_lake_normalized.jsonl"
    quarantine_file = export_dir / "ulpf_lake_quarantine.jsonl"
    manifest_file = export_dir / "ulpf_lake_manifest.json"

    assert valid_file.exists()
    assert quarantine_file.exists()
    assert manifest_file.exists()

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest["total_events"] == 2
    assert manifest["valid_events"]["count"] == 1
    assert manifest["quarantine_events"]["count"] == 1
