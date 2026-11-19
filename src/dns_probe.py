# The caller supplies only a generated name, a validated resolver IPv4 and a Boolean transport.
import os, socket, struct
transaction = os.urandom(2)
encoded = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'
question = encoded + b'\x00\x01\x00\x01'
packet = transaction + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question

def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ValueError('short response')
        data.extend(chunk)
    return data

with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
    client.settimeout(16)
    client.connect((server, 53))
    if tcp:
        client.sendall(struct.pack('!H', len(packet)) + packet)
        reply = read_exact(client, struct.unpack('!H', read_exact(client, 2))[0])
    else:
        client.sendall(packet)
        reply = client.recv(65535)
    if (len(reply) < 12 or reply[:2] != transaction or not reply[2] & 128
            or reply[3] & 15 not in (0, 3) or reply[4:6] != b'\x00\x01'
            or reply[12:12 + len(question)].lower() != question):
        raise ValueError('invalid probe answer')
    print('ok')
