"""Resolved run routes avoid DNS churn while retaining SNI and hostname validation."""

import http.client
from unittest.mock import Mock, patch

import pytest
from traffic_dns_route import bind_https_route


def test_resolved_route_keeps_original_hostname_for_tls():
    context = Mock()
    context.check_hostname = True
    context.verify_mode = 2
    connection = http.client.HTTPSConnection(
        "www.example.test", context=context, timeout=10
    )
    bind_https_route(connection, "192.0.2.10")
    with patch("traffic_dns_route.socket.create_connection") as connect:
        connection.connect()
    connect.assert_called_once_with(("192.0.2.10", 443), 10, None)
    context.wrap_socket.assert_called_once_with(
        connect.return_value, server_hostname="www.example.test"
    )
    assert connection.host == "www.example.test"
    assert context.check_hostname
    assert context.verify_mode == 2


def test_resolved_route_rejects_other_host_port_or_invalid_address():
    connection = http.client.HTTPSConnection("www.example.test", timeout=10)
    with pytest.raises(ValueError, match="Expected 4 octets"):
        bind_https_route(connection, "not-an-address")
    bind_https_route(connection, "192.0.2.10")
    with pytest.raises(ValueError, match="declared host and port"):
        connection.__dict__["_create_connection"](("other.example.test", 443), 10)
    with pytest.raises(ValueError, match="declared host and port"):
        connection.__dict__["_create_connection"](("www.example.test", 80), 10)


def test_run_route_uses_numeric_destination_when_public_dns_is_unavailable():
    connection = http.client.HTTPSConnection("www.example.test", timeout=10)
    bind_https_route(connection, "192.0.2.10")
    socket_object = Mock()
    with patch(
        "traffic_dns_route.socket.create_connection", return_value=socket_object
    ) as connect:
        assert (
            connection.__dict__["_create_connection"](("www.example.test", 443), 10)
            is socket_object
        )
    connect.assert_called_once_with(("192.0.2.10", 443), 10, None)
