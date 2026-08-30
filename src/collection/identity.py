import socket


def resolve_source_id(source_ip: str, timeout: float = 0.3) -> str | None:
    """Best-effort reverse DNS lookup for device identity. Never raises,
    never blocks longer than `timeout`. Returns None if unresolved —
    this is NOT vendor parsing, just an optional identity hint."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(source_ip)
        return hostname
    except (TimeoutError, socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)