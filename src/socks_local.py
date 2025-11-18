"""
socks_local.py
Local SOCKS5 proxy that tunnels connections (encrypted) to remote vpn_server.py.

Usage:
  python src\\socks_local.py --server <VPN_SERVER_IP> --port 9000 --listen-port 1080

How it works:
- Accepts SOCKS5 handshake from local app.
- Parses target address.
- Opens encrypted TCP connection to VPN server.
- Sends CONNECT control frame (encrypted).
- Waits for server CONNECT_RESP success.
- If success: replies to local app with SOCKS5 success and starts relaying:
    local_app <--> socks_local (encrypt+frame) <--> server (decrypt) <--> target host
"""

import socket
import threading
import argparse
from aes_util import AESCipher
from common import send_encrypted, recv_encrypted


# SOCKS5 constants
SOCKS_VERSION = 5
NO_AUTH = 0
CMD_CONNECT = 1
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

# Control codes for VPN protocol
CONNECT = 0x01
CONNECT_RESP = 0x02


def read_exact(sock, n):
    """Read exactly n bytes or return empty bytes if disconnected."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf


def handle_local_client(local_sock: socket.socket, client_addr, server_addr, server_port, cipher: AESCipher):
    remote = None   # avoid NameError in finally
    try:
        # -------------------------------
        # 1) SOCKS5 handshake
        # -------------------------------
        data = read_exact(local_sock, 2)
        if not data:
            local_sock.close()
            return

        ver, nmethods = data[0], data[1]
        methods = read_exact(local_sock, nmethods)

        # Reply: NO AUTH
        local_sock.sendall(bytes([SOCKS_VERSION, NO_AUTH]))

        # -------------------------------
        # 2) SOCKS5 CONNECT request
        # -------------------------------
        header = read_exact(local_sock, 4)
        if not header:
            local_sock.close()
            return

        ver, cmd, rsv, atyp = header[0], header[1], header[2], header[3]
        if ver != SOCKS_VERSION or cmd != CMD_CONNECT:
            # Command not supported
            local_sock.sendall(bytes([SOCKS_VERSION, 0x07, 0x00, 1, 0,0,0,0, 0,0]))
            local_sock.close()
            return

        # Parse address
        if atyp == ATYP_IPV4:
            addr_bytes = read_exact(local_sock, 4)
            addr = socket.inet_ntoa(addr_bytes)

        elif atyp == ATYP_DOMAIN:
            alen_b = read_exact(local_sock, 1)
            alen = alen_b[0]
            domain = read_exact(local_sock, alen)
            addr = domain.decode()

        elif atyp == ATYP_IPV6:
            addr_bytes = read_exact(local_sock, 16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)

        else:
            local_sock.close()
            return

        port_bytes = read_exact(local_sock, 2)
        port = int.from_bytes(port_bytes, "big")

        print(f"[*] Local client requested {addr}:{port}", flush=True)

        # -------------------------------
        # 3) Connect to VPN server
        # -------------------------------
        remote = socket.create_connection((server_addr, server_port), timeout=8)

        # Build CONNECT frame
        payload = bytearray()
        payload.append(CONNECT)

        # Address type
        try:
            socket.inet_aton(addr)
            payload.append(ATYP_IPV4)
            payload += socket.inet_aton(addr)

        except Exception:
            # Domain
            payload.append(ATYP_DOMAIN)
            addr_bytes = addr.encode()
            if len(addr_bytes) > 255:
                print("[!] domain too long", flush=True)
                local_sock.sendall(bytes([SOCKS_VERSION, 0x04, 0, 1, 0,0,0,0, 0,0]))
                remote.close()
                local_sock.close()
                return
            payload.append(len(addr_bytes))
            payload += addr_bytes

        payload += port.to_bytes(2, "big")

        # Send encrypted CONNECT to server
        send_encrypted(remote, bytes(payload), cipher)

        # Wait for CONNECT_RESP
        resp = recv_encrypted(remote, cipher)
        if not resp or resp[0] != CONNECT_RESP or resp[1] != 0x00:
            print("[!] CONNECT failed on server side", flush=True)
            local_sock.sendall(bytes([SOCKS_VERSION, 0x05, 0, 1, 0,0,0,0, 0,0]))
            remote.close()
            local_sock.close()
            return

        # SOCKS5 reply: success
        local_sock.sendall(bytes([
            SOCKS_VERSION, 0x00, 0x00, 0x01,
            0,0,0,0,  # BND.ADDR = 0.0.0.0
            0,0       # BND.PORT = 0
        ]))

        # -------------------------------
        # 4) Relay data (bi-directional)
        # -------------------------------
        def local_to_remote():
            try:
                while True:
                    chunk = local_sock.recv(4096)
                    if not chunk:
                        break
                    send_encrypted(remote, chunk, cipher)
            except:
                pass
            finally:
                try:
                    remote.shutdown(socket.SHUT_WR)
                except:
                    pass

        def remote_to_local():
            try:
                while True:
                    data = recv_encrypted(remote, cipher)
                    if not data:
                        break
                    local_sock.sendall(data)
            except:
                pass
            finally:
                try:
                    local_sock.shutdown(socket.SHUT_WR)
                except:
                    pass

        t1 = threading.Thread(target=local_to_remote, daemon=True)
        t2 = threading.Thread(target=remote_to_local, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        print(f"[!] socks handler error: {e}", flush=True)

    finally:
        try: local_sock.close()
        except: pass
        try:
            if remote:
                remote.close()
        except:
            pass
        print("[*] connection closed", flush=True)


def start_socks(local_listen: str, local_port: int, server_addr: str, server_port: int, cipher: AESCipher):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((local_listen, local_port))
    s.listen(64)
    print(f"[+] Local SOCKS5 proxy listening on {local_listen}:{local_port}", flush=True)

    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(
                target=handle_local_client,
                args=(conn, addr, server_addr, server_port, cipher),
                daemon=True
            )
            t.start()

    except KeyboardInterrupt:
        print("\n[!] shutting down local socks", flush=True)
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=1080)
    parser.add_argument("--key")
    args = parser.parse_args()

    key_bytes = bytes.fromhex(args.key) if args.key else None
    cipher = AESCipher(key_bytes) if key_bytes else AESCipher()

    start_socks(args.listen, args.listen_port, args.server, args.port, cipher)


if __name__ == "__main__":
    main()
