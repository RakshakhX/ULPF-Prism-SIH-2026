"""Wires the UDP + TCP collectors to the shared pipeline, publisher, archive."""

from pathlib import Path

from .archive import RawEventArchive
from .config import AppConfig
from .pipeline import CollectionPipeline, CollectorConfig
from .publisher import FileStreamPublisher
from .rejected import RejectedEventLog
from .tcp_collector import TCPCollector
from .udp_collector import UDPCollector


def build_pipeline(cfg: AppConfig) -> CollectionPipeline:
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
    cfg = AppConfig.from_json(Path("config/collector.example.json"))
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
        while True:
            pass
    except KeyboardInterrupt:
        udp.stop()
        tcp.stop()


if __name__ == "__main__":
    main()
