"""Creation of the receiver's one IPv6-only loopback listener."""

from __future__ import annotations

import socket


def create_ipv6_listener(port: int = 8767) -> socket.socket:
    """Bind only ::1 and refuse IPv4-mapped connections and port takeover."""
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(("::1", port))
        listener.listen(128)
        listener.setblocking(False)
        if listener.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) != 1:
            raise OSError("receiver socket is not IPv6-only")
        return listener
    except BaseException:
        listener.close()
        raise
