# Secure Gate — Zero-Trust TLS 1.3 Encrypted Proxy & Windows Client

**Secure Gate** is an open-source, self-hosted Zero-Trust network gateway and Windows desktop proxy client built in Python. It encrypts system-wide HTTP/HTTPS traffic over **TLS 1.3**, prevents **QUIC / UDP port 443 leaks** via Windows Firewall rules, and provides a real-time web admin dashboard for packet inspection and domain access control.

## Why Secure Gate?
- **End-to-End TLS 1.3 Tunneling:** Wraps local browser and application traffic inside an authenticated TLS 1.3 socket tunnel to your cloud server (Azure, AWS, DigitalOcean, or any Linux VPS).
- **Windows System Proxy & QUIC Leak Protection:** Automatically configures WinINet system proxy settings and blocks outbound UDP 443 traffic so browsers cannot bypass the encrypted tunnel.
- **Native High-DPI Windows Desktop App:** Built with Tkinter and Pillow featuring a 3D rotating status globe, account authentication, live gateway latency, system tray mode, and automatic Windows Start Menu registration.
- **Real-Time Web Admin Console (/sg-admin):** Multi-threaded dashboard with live connected user tracking, root-domain packet grouping, bandwidth telemetry, and instant domain allow/block policies.

## Quick Start & Installation
1. **Deploy the Linux Gateway Server:** Generate a self-signed TLS certificate (server.crt and server.key), update ADMIN_PASS in server/server.py, and run python3 server.py.
2. **Build the Windows Desktop Client:** Place server.crt inside client/, set AZURE_SERVER_IP in client/client.py, install dependencies (pip install -r client/requirements.txt), and compile SecureGate.exe with PyInstaller.
