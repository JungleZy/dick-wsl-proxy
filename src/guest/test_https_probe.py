"""Tests for the HTTPS readiness probe; no guest or network operation is performed.

The probe script runs against a local socket pair standing in for the TLS
connection, so only its HTTP handling is exercised.
"""

import contextlib
import http.client  # noqa: F401  (imported before the fakes, keeps the real socket module)
import io
import pathlib
import socket
import sys
import types
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).with_name("https_probe.py").read_text(encoding="ascii")


class _Raw:
    """Stands in for the plain TCP socket the probe connects first."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        pass

    def connect(self, peer):
        pass


def _fakes(client):
    fake_socket = types.ModuleType("socket")
    fake_socket.AF_INET = socket.AF_INET
    fake_socket.SOCK_STREAM = socket.SOCK_STREAM
    fake_socket.getaddrinfo = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443))]
    fake_socket.socket = lambda *args: _Raw()

    class Context:
        def wrap_socket(self, raw, server_hostname):
            return client

    fake_ssl = types.ModuleType("ssl")
    fake_ssl.SSLError = type("SSLError", (OSError,), {})
    fake_ssl.create_default_context = lambda: Context()
    return {"socket": fake_socket, "ssl": fake_ssl}


def run_probe(reply):
    """Runs the probe against a server that sends `reply` and then closes."""
    client, server = socket.socketpair()
    try:
        server.sendall(reply)
        server.shutdown(socket.SHUT_WR)
        output = io.StringIO()
        with patch.dict(sys.modules, _fakes(client)), contextlib.redirect_stdout(output):
            exec(compile("name = 'health.example'\n" + SCRIPT, "https_probe.py", "exec"), {"__name__": "__main__"})
        request = server.recv(4096)
    finally:
        client.close()
        server.close()
    return output.getvalue(), request


class HttpsProbeTests(unittest.TestCase):
    def test_head_reply_with_content_length_and_no_body(self):
        output, request = run_probe(b"HTTP/1.1 200 OK\r\nContent-Length: 1256\r\nConnection: close\r\n\r\n")
        self.assertEqual(output, "192.0.2.10 200\n")
        self.assertTrue(request.startswith(b"HEAD / HTTP/1.1\r\nHost: health.example\r\n"))

    def test_head_reply_with_chunked_framing_and_no_body(self):
        output, _ = run_probe(b"HTTP/1.1 301 Moved Permanently\r\nTransfer-Encoding: chunked\r\nLocation: /\r\n\r\n")
        self.assertEqual(output, "192.0.2.10 301\n")

    def test_head_reply_without_length(self):
        output, _ = run_probe(b"HTTP/1.1 204 No Content\r\n\r\n")
        self.assertEqual(output, "192.0.2.10 204\n")

    def test_bytes_after_the_head_reply_are_drained(self):
        # A server that wrongly sends a body still has it read before close.
        output, _ = run_probe(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
        self.assertEqual(output, "192.0.2.10 200\n")


if __name__ == "__main__":
    unittest.main()
