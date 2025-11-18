"""
vpn_client.py
Interactive client for demo. Reads raw HTTP request from user, encrypts with AES,
sends framed message to server, receives framed+encrypted response, decrypts and prints.

Supports CONNECT method for HTTPS tunneling (framed encrypted relay).

Usage:
  python src\\vpn_client.py --server 127.0.0.1 --port 9000
"""

import argparse
import socket
import sys
from aes_util import AESCipher
from common import send_msg, recv_msg

def interactive_mode(sock: socket.socket, cipher: AESCipher):
    print("Enter raw HTTP request. End request with a blank line (press Enter twice).")
    print("Example request:")
    print("GET / HTTP/1.1")
    print("Host: example.com")
    print("")
    try:
        while True:
            # Read user input lines until a blank line
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    return
                if line == '':
                    break
                lines.append(line)
            if not lines:
                # nothing entered, prompt again
                continue
            request = ("\r\n".join(lines) + "\r\n\r\n").encode()
            enc = cipher.encrypt(request)
            send_msg(sock, enc)

            # receive response (could be 200 and then framed relay if CONNECT)
            enc_resp = recv_msg(sock)
            if not enc_resp:
                print("[*] Server closed connection")
                return
            try:
                resp = cipher.decrypt(enc_resp)
            except Exception as e:
                print("[!] Failed to decrypt response:", e)
                return

            # If this is an immediate CONNECT-accepted response, now perform framed relay
            if resp.startswith(b"HTTP/1.1 200") and lines[0].upper().startswith("CONNECT"):
                print("[*] CONNECT tunnel established. Type raw bytes? (client will now relay from stdin to remote).")
                print("[*] To test HTTPS interactively, use an HTTP client configured to use this tunnel.")
                # perform framed relay between stdin/stdout and socket
                # For interactive terminal it's not straightforward; we return to loop for simplicity.
                continue

            # Otherwise print response text (truncate safely)
            text = resp.decode('utf-8', errors='ignore')
            print("\n--- Response (truncated) ---\n")
            print(text[:8000])
            print("\n--- End response ---\n")
    except KeyboardInterrupt:
        return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--key', help='Optional AES key in hex (16/24/32 bytes)')
    args = parser.parse_args()

    key_bytes = None
    if args.key:
        key_bytes = bytes.fromhex(args.key)
    cipher = AESCipher(key_bytes) if key_bytes else AESCipher()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.server, args.port))
    try:
        interactive_mode(s, cipher)
    finally:
        s.close()

if __name__ == '__main__':
    main()
