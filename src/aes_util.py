"""
aes_util.py
AES-256 encryption wrapper using EAX (authenticated encryption).
Keep key management simple for demo: pre-shared key in DEFAULT_KEY.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Optional

# Demo key (32 bytes for AES-256). Replace for better security.
DEFAULT_KEY = b'This_is_a_demo_key_for_AES_256!!!!!'[:32]  # ensure 32 bytes

class AESCipher:
    def __init__(self, key: Optional[bytes] = None):
        key = DEFAULT_KEY if key is None else key
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes")
        if len(key) not in (16, 24, 32):
            raise ValueError("Key length must be 16, 24 or 32 bytes")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Returns bytes: nonce(16) + tag(16) + ciphertext
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce + tag + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        """
        Expects blob: nonce(16) + tag(16) + ciphertext
        Returns plaintext bytes or raises ValueError (on auth failure).
        """
        if len(blob) < 32:
            raise ValueError("Encrypted blob too short")
        nonce = blob[:16]
        tag = blob[16:32]
        ciphertext = blob[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
