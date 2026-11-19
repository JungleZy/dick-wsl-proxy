# name is an ASCII hostname supplied as data by the controller.
import socket, ssl
from http.client import HTTPResponse

addresses = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
peer = addresses[0][4]
context = ssl.create_default_context()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
    raw.settimeout(12)
    raw.connect(peer)
    with context.wrap_socket(raw, server_hostname=name) as tls:
        tls.sendall(('HEAD / HTTP/1.1\r\nHost: ' + name + '\r\nConnection: close\r\n\r\n').encode('ascii'))
        response = HTTPResponse(tls)
        response.begin()
        print(peer[0], response.status)
