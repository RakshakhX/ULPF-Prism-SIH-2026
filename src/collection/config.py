import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AppConfig:
    udp_host: str = "0.0.0.0"
    udp_port: int = 5514
    tcp_host: str = "0.0.0.0"
    tcp_port: int = 5601
    max_event_size_bytes: int = 65536
    archive_dir: str = "archive_store"
    stream_file: str = "raw_event_stream.ndjson"
    resolve_source_id: bool = False  # off by default: reverse DNS adds latency
    reverse_dns_timeout: float = 0.3

    @classmethod
    def from_json(cls, path: Path) -> "AppConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**{**cls().__dict__, **data})
