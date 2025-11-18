# Architecture

Client <---encrypted framed TCP---> Server ---> Forward to Internet

Client:
- AES encrypts payload bytes
- Sends framed message to server: [4-byte len][cipher_blob]

Server:
- Accepts framed encrypted messages, decrypts
- If HTTP request: forwards to destination host (read Host header)
- If CONNECT: establishes TCP connection and performs framed relay

Security:
- AES-EAX provides confidentiality + authentication
- Key currently pre-shared; add RSA key exchange for secure key negotiation

Limitations:
- No OS-level routing/TUN on Windows (demo mode)
- Forwarder is a simplified HTTP forwarder, not a full proxy
