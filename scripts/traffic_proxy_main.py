"""Run the pinned proxy with TCP keepalive on its actual upstream sockets."""

import asyncio
import socket
from typing import Any

from mitmproxy.tools.main import mitmdump

KEEPALIVE_IDLE_SECONDS = 30
KEEPALIVE_INTERVAL_SECONDS = 5
KEEPALIVE_PROBES = 3
_open_connection = asyncio.open_connection


async def open_connection(
    *args: Any, **kwargs: Any
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Keep silent native responses connected across the Azure egress idle limit."""
    reader, writer = await _open_connection(*args, **kwargs)
    connection = writer.get_extra_info("socket")
    if connection is None:
        writer.close()
        await writer.wait_closed()
        message = "proxy upstream transport has no TCP socket"
        raise RuntimeError(message)
    try:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        connection.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE_SECONDS
        )
        connection.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL_SECONDS
        )
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_PROBES)
    except OSError:
        writer.close()
        await writer.wait_closed()
        raise
    return reader, writer


def main() -> None:
    """Apply socket options before Mitmproxy opens any upstream connection."""
    asyncio.open_connection = open_connection
    mitmdump()


if __name__ == "__main__":
    main()
