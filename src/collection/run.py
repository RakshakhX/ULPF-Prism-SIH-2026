"""Wires the UDP + TCP collectors to the shared pipeline, publisher, archive."""

import os
import threading
from pathlib import Path

from .archive import RawEventArchive
from .config import AppConfig
from .pipeline import CollectionPipeline, CollectorConfig
from .publisher import FileStreamPublisher, KafkaStreamPublisher, RawEventPublisher
from .rejected import RejectedEventLog
from .tcp_collector import TCPCollector
from .udp_collector import UDPCollector


def build_pipeline(cfg: AppConfig) -> CollectionPipeline:
    publisher: RawEventPublisher
    brokers = os.environ.get("ULPF_KAFKA_BROKERS")
    if brokers:
        from confluent_kafka import Producer

        publisher = KafkaStreamPublisher(
            Producer(
                {
                    "bootstrap.servers": brokers,
                    "acks": "all",
                    "enable.idempotence": True,
                    "compression.type": "zstd",
                }
            )
        )
    else:
        publisher = FileStreamPublisher(Path(cfg.stream_file))
    archive = RawEventArchive(Path(cfg.archive_dir))
    rejected_log = RejectedEventLog(Path(cfg.archive_dir) / "rejected")
    pipeline_cfg = CollectorConfig(
        max_event_size_bytes=cfg.max_event_size_bytes,
        dedup_max_entries=cfg.dedup_max_entries,
        latency_window_size=cfg.latency_window_size,
    )
    return CollectionPipeline(
        publisher=publisher,
        archive=archive,
        rejected_log=rejected_log,
        config=pipeline_cfg,
    )


def main() -> None:
    config_path = Path(os.environ.get("ULPF_COLLECTOR_CONFIG", "config/collector.example.json"))
    cfg = AppConfig.from_json(config_path) if config_path.exists() else AppConfig()
    cfg.archive_dir = os.environ.get("ULPF_ARCHIVE_DIR", cfg.archive_dir)
    cfg.udp_port = int(os.environ.get("ULPF_UDP_PORT", cfg.udp_port))
    cfg.tcp_port = int(os.environ.get("ULPF_TCP_PORT", cfg.tcp_port))
    pipeline = build_pipeline(cfg)

    udp = UDPCollector(
        pipeline, cfg.udp_host, cfg.udp_port, cfg.resolve_source_id, cfg.reverse_dns_timeout
    )
    tcp = TCPCollector(
        pipeline,
        cfg.tcp_host,
        cfg.tcp_port,
        cfg.resolve_source_id,
        cfg.reverse_dns_timeout,
        cfg.tcp_read_timeout_seconds,
    )
    udp.start()
    tcp.start()

    print(f"UDP collector listening on {cfg.udp_host}:{cfg.udp_port}")
    print(f"TCP collector listening on {cfg.tcp_host}:{cfg.tcp_port}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        udp.stop()
        tcp.stop()


if __name__ == "__main__":
    main()
