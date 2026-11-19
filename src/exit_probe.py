# Opt-in measurement only. Do not log the raw IPPure document or trust proxy environment settings.
import http.client, ipaddress, json, socket, ssl
name = 'my.ippure.com'
peer = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(12)
    sock.connect(peer)
    with ssl.create_default_context().wrap_socket(sock, server_hostname=name) as tls:
        tls.sendall(b'GET /v1/info HTTP/1.1\r\nHost: my.ippure.com\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n')
        response = http.client.HTTPResponse(tls)
        response.begin()
        if response.status != 200:
            raise ValueError('exit probe HTTP failure')
        body = response.read(16385)
        if len(body) > 16384:
            raise ValueError('exit probe response too large')
        data = json.loads(body)
        country = data.get('countryCode', '')
        print(json.dumps({'peer': peer[0], 'ip': str(ipaddress.IPv4Address(data['ip'])), 'country': country if isinstance(country, str) and len(country)==2 and country.isascii() and country.isalpha() else ''}))
