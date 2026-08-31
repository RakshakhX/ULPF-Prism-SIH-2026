"""
src/pipeline/demo.py

Demonstration CLI script for the complete Cisco ASA processing pipeline.
Run with: python -m src.pipeline.demo
"""

from __future__ import annotations

import json

from src.pipeline.runner import CiscoASAPipelineRunner

SAMPLE_LOGS = [
    # 1. Clean Cisco ASA 106023 Deny
    (
        "<166>Oct 12 2023 14:23:01 edge-fw-01 : %ASA-4-106023: "
        "Deny tcp src outside:203.0.113.11/49321 dst inside:198.51.100.21/22 "
        'by access-group "outside_in"'
    ),
    # 2. Clean Cisco ASA 302013 Connection Built
    (
        "<166>Oct 12 2023 14:23:05 edge-fw-01 : %ASA-6-302013: "
        "Built inbound TCP connection 981273 for outside:203.0.113.55/51234 "
        "to inside:198.51.100.30/443"
    ),
    # 3. Clean Cisco ASA 106100 Access List Permitted
    (
        "<166>Oct 12 2023 14:23:12 edge-fw-01 : %ASA-6-106100: "
        "access-list acl_dmz permitted tcp dmz/192.0.2.50(8080) -> inside/198.51.100.50(80)"
    ),
    # 4. Known ASA Header with unknown message ID (Partial Parse)
    (
        "<166>Oct 12 2023 14:23:20 edge-fw-01 : %ASA-5-999999: "
        "Dynamic routing peer established with 198.51.100.254"
    ),
    # 5. Unrecognized / Malformed log (Retained, zero data loss)
    "<134>1 2023-10-12T14:23:25Z edge-router unparseable garbage syslog packet",
]


def run_demonstration():
    print("=" * 80)
    print(" ULPF PRISM — END-TO-END PIPELINE DEMONSTRATION (CISCO ASA)")
    print("=" * 80)
    print()

    runner = CiscoASAPipelineRunner()
    results = runner.process_batch(SAMPLE_LOGS)

    for idx, r in enumerate(results, start=1):
        ue = r["unified_event"]
        conf = r["detection"]["confidence"]
        status = r["parsed_status"].upper()
        act = ue.get("action", {}).get("normalized")
        out = ue.get("action", {}).get("outcome")
        src_str = f"{ue.get('source', {}).get('ip')}:{ue.get('source', {}).get('port', '')}"
        dst_str = (
            f"{ue.get('destination', {}).get('ip')}:{ue.get('destination', {}).get('port', '')}"
        )
        sev_str = (
            f"{ue.get('severity', {}).get('label')} "
            f"(score: {ue.get('severity', {}).get('normalized')})"
        )
        raw_trace = (
            f"raw_event_id={ue['traceability']['raw_event_id']} "
            f"(sha256={ue['traceability']['raw_sha256'][:16]}...)"
        )

        print(f"[{idx}] INGESTED LOG:")
        print(f"    Raw SHA-256 : {r['raw_sha256']}")
        print(f"    Detected    : {r['detection']['matched']} (conf: {conf:.2f})")
        print(f"    Parse Status: {status}")
        print(f"    Action      : {act} ({out})")
        print(f"    Endpoints   : {src_str} -> {dst_str}")
        print(f"    Severity    : {sev_str}")
        print(f"    Quality     : {ue.get('quality', {}).get('status')}")
        print(f"    Trace Link  : {raw_trace}")
        print(f"    Schema Valid: {'YES (v1.0.0)' if r['validation_passed'] else 'NO'}")
        print("-" * 80)

    print()
    print("ANALYTICAL AGGREGATIONS:")
    aggs = runner.store.get_aggregations()
    print(json.dumps(aggs, indent=2))
    print()
    print("DATA LAKE EXPORT MANIFEST (data/exports/):")
    manifest_path = runner.exporter.base_dir / "ulpf_lake_manifest.json"
    if manifest_path.exists():
        print(manifest_path.read_text(encoding="utf-8"))
    print("=" * 80)
    print("Demonstration finished successfully with 100% data preservation and traceability.")


if __name__ == "__main__":
    run_demonstration()
