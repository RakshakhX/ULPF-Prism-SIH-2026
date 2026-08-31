from __future__ import annotations


def summarize_metrics_window(per_worker: dict, window_seconds: float) -> dict:
    total_consumed = sum(w["consumed"] for w in per_worker.values())
    total_produced = sum(w["produced"] for w in per_worker.values())
    total_retried = sum(w["retried"] for w in per_worker.values())
    total_dead = sum(w["dead_lettered"] for w in per_worker.values())
    total_bytes_in = sum(w["bytes_in"] for w in per_worker.values())
    total_bytes_out = sum(w["bytes_out"] for w in per_worker.values())
    all_latencies = [v for w in per_worker.values() for v in w.get("latencies", [])]
    sorted_latencies = sorted(all_latencies)
    if not sorted_latencies:
        p50 = p95 = p99 = 0.0
    else:
        p50 = sorted_latencies[max(0, int((0.50 * (len(sorted_latencies) - 1))))]
        p95 = sorted_latencies[max(0, int((0.95 * (len(sorted_latencies) - 1))))]
        p99 = sorted_latencies[max(0, int((0.99 * (len(sorted_latencies) - 1))))]
    cpu_total = sum(w.get("cpu_percent", 0.0) for w in per_worker.values())
    mem_total = sum(w.get("memory_mb", 0.0) for w in per_worker.values())
    workers = max(len(per_worker), 1)
    scale = max(window_seconds, 1e-6)
    return {
        "worker_count": len(per_worker),
        "input_eps": total_consumed / scale,
        "output_eps": total_produced / scale,
        "retry_eps": total_retried / scale,
        "dead_letter_eps": total_dead / scale,
        "bytes_in_per_s": total_bytes_in / scale,
        "bytes_out_per_s": total_bytes_out / scale,
        "cpu_percent_avg": cpu_total / workers,
        "memory_mb_avg": mem_total / workers,
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "latency_p99_ms": p99,
    }
