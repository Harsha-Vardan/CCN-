"""
vpn_server.py
SOCKS-style backend for encrypted SOCKS5 client.
Usage:
  python src\\vpn_server.py --host 0.0.0.0 --port 9000
Optional:
  --key <hexkey>  # optional AES key in hex (16/24/32 bytes)
"""

import argparse
import socket
import threading
from aes_util import AESCipher
from common import recv_encrypted, send_encrypted, recv_msg, send_msg

# Control message types (simple)
# CONNECT message structure (sent by client as first encrypted frame):
#   1 byte: 0x01 (CONNECT)
#   1 byte: ATYP (1=IPv4,3=DOMAIN,4=IPv6)
#   if ATYP==1: 4 bytes IPv4
#   if ATYP==3: 1 byte len, then domain bytes
#   if ATYP==4: 16 bytes ipv6
#   2 bytes: port (network order)
#
# Server responds (as encrypted frame) with:
#   1 byte: 0x02 (CONNECT_RESP)
#   1 byte: status (0x00 success, non-zero error)
#   optional: if success, optionally BND.ADDR/BND.PORT (we send zeros)

CONNECT = 0x01
CONNECT_RESP = 0x02

def parse_connect_payload(payload: bytes):
    if not payload or payload[0] != CONNECT:
        return None
    idx = 1
    if idx >= len(payload):
        return None
    atyp = payload[idx]; idx += 1
    addr = None
    if atyp == 1:  # IPv4
        if idx + 4 > len(payload): return None
        addr = socket.inet_ntoa(payload[idx:idx+4]); idx += 4
    elif atyp == 3:  # domain
        if idx >= len(payload): return None
        l = payload[idx]; idx += 1
        if idx + l > len(payload): return None
        addr = payload[idx:idx+l].decode(); idx += l
    elif atyp == 4:  # IPv6
        if idx + 16 > len(payload): return None
        addr = socket.inet_ntop(socket.AF_INET6, payload[idx:idx+16]); idx += 16
    else:
        return None
    if idx + 2 > len(payload): return None
    port = int.from_bytes(payload[idx:idx+2], 'big')
    return (addr, port)

def handle_client(conn: socket.socket, addr, cipher: AESCipher):
    print(f"[+] Encrypted client connected: {addr}")
    try:
        # First encrypted frame must be CONNECT control
        payload = recv_encrypted(conn, cipher)
        if not payload:
            print("[*] client closed before CONNECT")
            conn.close(); return
        parsed = parse_connect_payload(payload)
        if not parsed:
            print("[!] invalid CONNECT payload from", addr)
            send_encrypted(conn, bytes([CONNECT_RESP, 0x01]), cipher)  # error
            conn.close(); return
        dest_host, dest_port = parsed
        print(f"[*] Client {addr} wants to connect to {dest_host}:{dest_port}")

        # Attempt to connect to destination
        try:
            remote = socket.create_connection((dest_host, dest_port), timeout=8)
        except Exception as e:
            print(f"[!] Could not connect to {dest_host}:{dest_port} -> {e}")
            send_encrypted(conn, bytes([CONNECT_RESP, 0x02]), cipher)  # cannot connect
            conn.close(); return

        # Success -> send CONNECT_RESP success
        send_encrypted(conn, bytes([CONNECT_RESP, 0x00]), cipher)
        print(f"[+] Connected to {dest_host}:{dest_port}, starting relay for {addr}")

        # Start two threads: client->remote and remote->client
        def client_to_remote():
            try:
                while True:
                    data = recv_encrypted(conn, cipher)
                    if not data:
                        break
                    remote.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    remote.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        def remote_to_client():
            try:
                while True:
                    chunk = remote.recv(4096)
                    if not chunk:
                        break
                    send_encrypted(conn, chunk, cipher)
            except Exception:
                pass
            finally:
                try:
                    conn.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=client_to_remote, daemon=True)
        t2 = threading.Thread(target=remote_to_client, daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        remote.close()
        print(f"[-] Relay finished for {addr} -> {dest_host}:{dest_port}")
    except Exception as e:
        print(f"[!] error handling client {addr}: {e}")
    finally:
        try: conn.close()
        except Exception: pass

def start_server(host: str, port: int, cipher: AESCipher):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)
    print(f"[+] VPN server (socks backend) listening on {host}:{port}")
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, cipher), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[!] shutting down")
    finally:
        s.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--key', help='Optional AES key in hex')
    args = parser.parse_args()
    key_bytes = bytes.fromhex(args.key) if args.key else None
    cipher = AESCipher(key_bytes) if key_bytes else AESCipher()
    start_server(args.host, args.port, cipher)

if __name__ == '__main__':
    main()
