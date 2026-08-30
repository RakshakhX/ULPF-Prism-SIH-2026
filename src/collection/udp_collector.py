import socket
import threading

from .identity import resolve_source_id
from .pipeline import CollectionPipeline


class UDPCollector:
    def __init__(
        self,
        pipeline: CollectionPipeline,
        host: str,
        port: int,
        resolve_source_id_flag: bool = False,
        dns_timeout: float = 0.3,
    ) -> None:
        self.pipeline = pipeline
        self.host, self.port = host, port
        self.resolve_source_id_flag = resolve_source_id_flag
        self.dns_timeout = dns_timeout
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._sock.bind((self.host, self.port))
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                break
            source_id = (
                resolve_source_id(addr[0], self.dns_timeout)
                if self.resolve_source_id_flag
                else None
            )
            self.pipeline.ingest(
                raw=data,
                transport="udp",
                source_ip=addr[0],
                source_id=source_id,
                metadata={"source_port": addr[1]},
            )

    def stop(self) -> None:
        self._running = False
        self._sock.close()
        if self._thread:
            self._thread.join(timeout=1)