"""
forwarder.py
Forward HTTP requests to destination host. Supports:
- Regular HTTP requests: parses Host header and forwards.
- CONNECT (HTTPS) requests: establishes TCP tunnel and relays raw bytes.

This is a simple demo forwarder and not a robust proxy implementation.
"""

import socket
import threading

def parse_host_from_http_request(req_bytes: bytes):
    try:
        text = req_bytes.decode('utf-8', errors='ignore')
        lines = text.splitlines()
        for line in lines:
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
                # might include port
                if ':' in host:
                    h, p = host.split(':', 1)
                    return h.strip(), int(p)
                return host, 80
    except Exception:
        pass
    return None, None

def forward_http_request(raw_request: bytes, timeout: float = 5.0) -> bytes:
    """
    For simple HTTP GET/POST: forward and return server response bytes.
    For CONNECT method: this function will return a special marker indicating
    that caller should perform a CONNECT relay. Caller will detect CONNECT.
    """
    try:
        text = raw_request.decode('utf-8', errors='ignore')
    except Exception:
        text = ''

    first_line = text.splitlines()[0] if text else ''
    if first_line.upper().startswith('CONNECT'):
        # CONNECT <host:port> HTTP/1.1
        parts = first_line.split()
        if len(parts) >= 2:
            hostport = parts[1]
            if ':' in hostport:
                host, port = hostport.split(':', 1)
                return b'__CONNECT__' + f"{host}:{port}".encode()
        return b'HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request'

    host, port = parse_host_from_http_request(raw_request)
    if not host:
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request"

    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(raw_request)
        resp = b''
        s.settimeout(2.0)
        while True:
            try:
                part = s.recv(4096)
                if not part:
                    break
                resp += part
                if len(part) < 4096:
                    # heuristic end
                    break
            except socket.timeout:
                break
        s.close()
        return resp
    except Exception as e:
        msg = f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(str(e))}\r\n\r\n{e}"
        return msg.encode()

def relay_tcp(sock1: socket.socket, sock2: socket.socket):
    """
    Relay data bidirectionally between sock1 and sock2 until one side closes.
    """
    def pipe(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t1 = threading.Thread(target=pipe, args=(sock1, sock2), daemon=True)
    t2 = threading.Thread(target=pipe, args=(sock2, sock1), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
