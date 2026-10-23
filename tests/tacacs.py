"""
Minimal TACACS+ client (RFC 8907), written apart from the extension's, to
check passwords on the TACACS+ test server independently of it:

  tacacs.py HOST PORT KEY login USER PASSWORD       -> PASS or FAIL
  tacacs.py HOST PORT KEY chpass USER OLD NEW       -> PASS, FAIL or ERROR

ASCII authentication: the server asks for what it needs (GETUSER, GETPASS,
GETDATA) and each prompt is answered in turn. -v prints the dialogue.
Run inside the test server's container (see tests/lib.sh), with no port
published.
"""
import hashlib, os, socket, struct, sys

AUTHEN = 0x01
LOGIN, CHPASS = 0x01, 0x02
ASCII = 0x01
SERVICE_LOGIN = 0x01
STATUS = {1: 'PASS', 2: 'FAIL', 3: 'GETDATA', 4: 'GETUSER', 5: 'GETPASS', 6: 'RESTART', 7: 'ERROR', 0x21: 'FOLLOW'}

def pad(session_id, key, version, seq, length):
    out, prev = b'', b''
    while len(out) < length:
        prev = hashlib.md5(struct.pack('!I', session_id) + key + bytes([version, seq]) + prev).digest()
        out += prev
    return out[:length]

def packet(session_id, key, seq, body, version=0xc0):
    obfuscated = bytes(a ^ b for a, b in zip(body, pad(session_id, key, version, seq, len(body))))
    return struct.pack('!BBBBII', version, AUTHEN, seq, 0, session_id, len(body)) + obfuscated

def recv(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError('connection closed')
        data += chunk
    return data

def read_reply(sock, key):
    version, _, seq, flags, session_id, length = struct.unpack('!BBBBII', recv(sock, 12))
    body = recv(sock, length)
    body = bytes(a ^ b for a, b in zip(body, pad(session_id, key, version, seq, length)))
    status, _, msg_len, _ = struct.unpack('!BBHH', body[:6])
    return seq, STATUS.get(status, hex(status)), body[6:6 + msg_len].decode(errors='replace')

def run(host, port, key, action, user, answers, verbose):
    key = key.encode()
    session_id = struct.unpack('!I', os.urandom(4))[0]
    sock = socket.create_connection((host, int(port)), timeout=10)
    u, port_name = user.encode(), b'tests'
    start = struct.pack('!BBBBBBBB', action, 1, ASCII, SERVICE_LOGIN, len(u), len(port_name), 0, 0) + u + port_name
    sock.sendall(packet(session_id, key, 1, start))
    answers = list(answers)
    while True:
        seq, status, message = read_reply(sock, key)
        if verbose:
            print('  server: %-8s %r' % (status, message))
        if status not in ('GETUSER', 'GETPASS', 'GETDATA'):
            return status
        answer = (user if status == 'GETUSER' else answers.pop(0) if answers else '').encode()
        sock.sendall(packet(session_id, key, seq + 1, struct.pack('!HHB', len(answer), 0, 0) + answer))

if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if a != '-v']
    host, port, key, action, user = args[:5]
    try:
        print(run(host, port, key, LOGIN if action == 'login' else CHPASS, user, args[5:], '-v' in sys.argv))
    except (OSError, EOFError) as e:
        print('UNREACHABLE', e)
