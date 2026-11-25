# name is an ASCII hostname supplied as data by the controller.
import socket, ssl
from http.client import HTTPException, HTTPResponse

addresses = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
peer = addresses[0][4]
context = ssl.create_default_context()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
    raw.settimeout(12)
    raw.connect(peer)
    with context.wrap_socket(raw, server_hostname=name) as tls:
        tls.sendall(('HEAD / HTTP/1.1\r\nHost: ' + name + '\r\nConnection: close\r\n\r\n').encode('ascii'))
        # A HEAD reply has no body even when it carries Content-Length or
        # chunked framing; parsed as GET, the read below would wait for a body
        # that never comes and fail the probe.
        response = HTTPResponse(tls, method="HEAD")
        response.begin()
        print(peer[0], response.status, flush=True)
        # Read the server's close before closing: a socket closed with unread
        # data is reset, which the forwarding path counts as an aborted
        # connection. The status is already out, so a failure here is ignored.
        try:
            tls.settimeout(2)
            response.read()
            while tls.recv(4096):
                pass
        except (ssl.SSLError, OSError, HTTPException):
            pass
