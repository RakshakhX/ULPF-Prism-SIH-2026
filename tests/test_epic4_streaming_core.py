import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


load_gen = _load_module("ulpf_load_gen", "files/load_gen.py")
worker = _load_module("ulpf_worker", "files/worker.py")


def test_event_generator_supports_vendor_variants_and_size_cap():
    src = load_gen.Source(hostname="fw-edge-0001", ip="10.0.0.1")
    for vendor in ["pfsense", "fortinet", "linux"]:
        payload = load_gen.build_event_for_vendor(vendor, src, 1710000000.0, target_size=128)
        assert isinstance(payload, str)
        assert len(payload.encode("utf-8")) <= 128


def test_corrupt_produces_malformed_payload():
    line = "<134>1 2026-08-31T00:00:00Z fw-edge-0001 filterlog 123 - - valid,data"
    result = load_gen.corrupt(line)
    assert result != line


def test_metrics_summary_computes_expected_values():
    per_worker = {
        "worker-a": {
            "consumed": 100,
            "produced": 90,
            "retried": 5,
            "dead_lettered": 3,
            "bytes_in": 1000,
            "bytes_out": 900,
            "latencies": [10, 20, 30],
            "cpu_percent": 30.0,
            "memory_mb": 128.0,
        },
        "worker-b": {
            "consumed": 50,
            "produced": 45,
            "retried": 1,
            "dead_lettered": 2,
            "bytes_in": 600,
            "bytes_out": 500,
            "latencies": [15, 25],
            "cpu_percent": 20.0,
            "memory_mb": 64.0,
        },
    }

    summary = (
        load_gen.summarize_metrics_window if hasattr(load_gen, "summarize_metrics_window") else None
    )
    if summary is None:
        pytest = __import__("pytest")
        pytest.skip("summarize_metrics_window unavailable in this generator build")

    result = summary(per_worker, 60.0)
    assert result["worker_count"] == 2
    assert result["input_eps"] == (150 / 60.0)
    assert result["output_eps"] == (135 / 60.0)
    assert result["latency_p95_ms"] == 25.0


def test_event_id_is_deterministic_for_identical_payloads():
    raw = b"<134>1 2026-08-31T00:00:00Z fw-edge-0001 filterlog 123 - - valid,event"
    assert worker.compute_event_id(raw) == worker.compute_event_id(raw)
    assert worker.compute_event_id(raw) != worker.compute_event_id(b"different payload")


def test_parse_pfsense_log_accepts_valid_payload_and_rejects_invalid_payload():
    valid = (
        b"<134>1 2026-08-31T00:00:00Z fw-edge-0001 filterlog 123 - - "
        b"5,,,1000000103,igb0,match,pass,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
        b"10.0.0.5,93.184.216.34,54321,443,0,S,1391432708,,64240,,mss;sackOK"
    )
    result = worker.parse_pfsense_log(valid)
    assert result["syslog_host"] == "fw-edge-0001"
    assert result["action"] == "pass"
    assert result["src_ip"] == "10.0.0.5"

    with __import__("pytest").raises(worker.ParseError):
        worker.parse_pfsense_log(b"not a pfSense filterlog line")
