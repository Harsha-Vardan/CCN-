# Secure VPN Project (Windows-compatible)

Simple educational VPN: AES-encrypted TCP tunnel between client and server.
This project simulates VPN-like behavior (tunneling + encryption + forwarding)
without requiring OS-level TUN/TAP drivers (works on Windows).

## Folder structure
src/         : Python source code
run/         : Windows batch scripts to start server/client
docs/        : Documentation and viva Qs
demo/        : sample requests

## Setup (Windows)
1. Open PowerShell (or cmd) in project folder.
2. Create virtualenv:
   python -m venv venv
3. Activate:
   venv\\Scripts\\activate
4. Install:
   pip install -r requirements.txt

## Run
Start server:
  run\\start_server.bat

Start client:
  run\\start_client.bat

(You can also run python src\\vpn_server.py and python src\\vpn_client.py directly.)

## Notes
- For demo we use a pre-shared AES key in `src/aes_util.py`. For real usage implement RSA key exchange.
- This project demonstrates CCN concepts: encryption, tunneling, framing, forwarding.

