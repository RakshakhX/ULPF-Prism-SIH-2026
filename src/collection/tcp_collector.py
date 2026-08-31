import socket
import threading

from .identity import resolve_source_id
from .pipeline import CollectionPipeline

# Syslog-over-TCP frames are newline-delimited (RFC 6587 non-transparent framing).
DELIMITER = b"\n"


class TCPCollector:
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
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._sock.bind((self.host, self.port))
        self._sock.listen(50)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn: socket.socket, addr) -> None:
        source_id = (
            resolve_source_id(addr[0], self.dns_timeout) if self.resolve_source_id_flag else None
        )
        buffer = b""
        with conn:
            while True:
                try:
                    chunk = conn.recv(65535)
                except OSError:
                    break
                if not chunk:
                    if buffer:
                        self._emit(buffer, addr, source_id)
                    break
                buffer += chunk
                while DELIMITER in buffer:
                    line, buffer = buffer.split(DELIMITER, 1)
                    self._emit(line, addr, source_id)

    def _emit(self, raw: bytes, addr, source_id: str | None) -> None:
        self.pipeline.ingest(
            raw=raw,
            transport="tcp",
            source_ip=addr[0],
            source_id=source_id,
            metadata={"source_port": addr[1]},
        )

    def stop(self) -> None:
        self._running = False
        self._sock.close()
        if self._thread:
            self._thread.join(timeout=1)
