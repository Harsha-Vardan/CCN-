"""
common.py
Length-prefixed message framing helpers + encrypted helpers.

Format: 4-byte big-endian unsigned int length, followed by payload bytes.
"""

import struct
import socket
from typing import Optional
from aes_util import AESCipher

LEN_STRUCT = '!I'   # network byte order 4-byte unsigned int
LEN_BYTES = struct.calcsize(LEN_STRUCT)

def send_msg(sock: socket.socket, data: bytes) -> None:
    total = len(data)
    header = struct.pack(LEN_STRUCT, total)
    sock.sendall(header + data)

def recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf

def recv_msg(sock: socket.socket) -> bytes:
    header = recv_all(sock, LEN_BYTES)
    if not header:
        return b''
    (payload_len,) = struct.unpack(LEN_STRUCT, header)
    if payload_len == 0:
        return b''
    payload = recv_all(sock, payload_len)
    return payload

# ---------- Encrypted framed helpers ----------
def send_encrypted(sock: socket.socket, plaintext: bytes, cipher: AESCipher) -> None:
    """
    Encrypt plaintext (AES EAX) then send framed message.
    """
    blob = cipher.encrypt(plaintext)
    send_msg(sock, blob)

def recv_encrypted(sock: socket.socket, cipher: AESCipher) -> bytes:
    """
    Receive framed encrypted blob, decrypt and return plaintext.
    Returns b'' on EOF.
    """
    blob = recv_msg(sock)
    if not blob:
        return b''
    return cipher.decrypt(blob)
