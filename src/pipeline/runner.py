"""
src/pipeline/runner.py

Orchestrates the complete end-to-end path:
Raw Log -> RawEventEnvelope + Hash -> Source Pack -> UnifiedEvent -> Analytical Store -> Lake.
"""

from __future__ import annotations

import hashlib
from typing import Any

from core.cisco_asa_pack import CiscoASASourcePack, RawEvent
from src.pipeline.exporter import DataLakeExporter
from src.pipeline.normalizer import normalize_cisco_asa_event
from src.pipeline.storage import AnalyticalVisibilityStore, global_visibility_store
from src.validation.validate_unified_event import validate_event


class CiscoASAPipelineRunner:
    """End-to-end pipeline runner for Cisco ASA security logs."""

    def __init__(
        self,
        store: AnalyticalVisibilityStore | None = None,
        exporter: DataLakeExporter | None = None,
    ) -> None:
        self.pack = CiscoASASourcePack()
        self.store = store or global_visibility_store
        self.exporter = exporter or DataLakeExporter()

    def process_raw_log(self, raw_input: bytes | str) -> dict[str, Any]:
        """
        Executes the complete processing lifecycle for one raw log record:
        1. Capture raw bytes and verify SHA-256 hash
        2. Detect and parse via CiscoASASourcePack
        3. Normalize to UnifiedEvent v1.0.0
        4. Validate against UnifiedEvent schema
        5. Index into Analytical Store
        """
        # Step 1: Raw Bytes & Cryptographic Hash
        if isinstance(raw_input, str):
            raw_bytes = raw_input.encode("utf-8")
        else:
            raw_bytes = raw_input

        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        raw_event_capture = RawEvent.from_bytes(raw_bytes)

        # Confirm hash integrity
        assert raw_event_capture.sha256 == raw_sha256

        # Step 2: Source Pack Detection & Parsing
        detection = self.pack.detect(raw_bytes)
        parsed = self.pack.parse(raw_bytes)

        # Step 3: UnifiedEvent Normalization
        unified = normalize_cisco_asa_event(parsed)

        # Ensure traceability connects back to raw event
        assert unified["traceability"]["raw_sha256"] == raw_sha256

        # Step 4: Schema & Semantic Validation
        validation_result = validate_event(unified)
        if not validation_result.valid:
            # If structural validation fails, mark as invalid quality rather than dropping
            unified["quality"]["status"] = "invalid"
            unified["quality"]["warnings"].extend([i.message for i in validation_result.issues])

        # Step 5: Index in Analytical Store for Visibility
        self.store.add_event(unified)

        return {
            "raw_sha256": raw_sha256,
            "detection": {"matched": detection.matched, "confidence": detection.confidence},
            "parsed_status": parsed.parse_status.value,
            "unified_event": unified,
            "validation_passed": validation_result.valid,
        }

    def process_batch(self, raw_logs: list[bytes | str]) -> list[dict[str, Any]]:
        """Processes a batch of logs and automatically exports them to the data lake."""
        results = [self.process_raw_log(log) for log in raw_logs]
        events_to_export = [r["unified_event"] for r in results]
        self.exporter.export_events(events_to_export)
        return results
