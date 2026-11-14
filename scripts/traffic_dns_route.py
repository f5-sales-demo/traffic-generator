"""Bind a run's resolved IPv4 route while preserving TLS SNI and hostname checks."""

import http.client
import ipaddress
import socket
import ssl
from typing import Any
from urllib.request import HTTPSHandler, Request


def bind_https_route(connection: http.client.HTTPSConnection, address: str) -> None:
    """Change only socket destination; HTTPSConnection retains its original hostname."""
    ipaddress.IPv4Address(address)
    host = connection.host

    def connect(
        target: tuple[str, int], timeout: float, source_address: tuple | None = None
    ) -> socket.socket:
        if target != (host, 443):
            message = "HTTPS route changed outside the declared host and port"
            raise ValueError(message)
        return socket.create_connection((address, 443), timeout, source_address)

    connection.__dict__["_create_connection"] = connect


class RoutedHTTPSHandler(HTTPSHandler):
    """Use only the declared run route; keep standard certificate validation."""

    def __init__(self, routes: dict[str, str], context: ssl.SSLContext) -> None:
        """Retain the exact startup routes and validating TLS context."""
        super().__init__(context=context)
        self.routes = routes
        self.tls_context = context

    def https_open(self, req: Request) -> Any:
        """Construct native HTTPS with original host, SNI and certificate checks."""

        def connection(host: str, **kwargs: Any) -> http.client.HTTPSConnection:
            result = http.client.HTTPSConnection(host, **kwargs)
            if result.host not in self.routes:
                message = "HTTPS filler host lacks a declared run route"
                raise ValueError(message)
            bind_https_route(result, self.routes[result.host])
            return result

        return self.do_open(connection, req, context=self.tls_context)
