"""Verify the actual proxy socket keeps its TCP connection alive without extra HTTP."""

import asyncio
import socket
import unittest

from traffic_proxy_main import open_connection


class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_upstream_socket_and_response_bytes(self):
        async def respond(reader, writer):
            request = await reader.readexactly(4)
            assert request == b"test"
            writer.write(b"native-response")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(respond, "127.0.0.1", 0)
        try:
            reader, writer = await open_connection(
                "127.0.0.1", server.sockets[0].getsockname()[1]
            )
            connection = writer.get_extra_info("socket")
            assert connection.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
            assert connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 30
            assert connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL) == 5
            assert connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT) == 3
            writer.write(b"test")
            await writer.drain()
            assert await reader.read() == b"native-response"
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
