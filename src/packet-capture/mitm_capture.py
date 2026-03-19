"""
Aion 2 MITM TLS Proxy Capture
- Uses mitmproxy to intercept TLS traffic from the game
- No injection into game process (avoids GameGuard)
- Captures decrypted HTTP/TCP data and forwards to analysis server

Requirements (Windows):
  pip install mitmproxy websockets

Setup:
  1. pip install mitmproxy
  2. Run: mitmdump --mode transparent --showhost
     (this generates CA cert at ~/.mitmproxy/mitmproxy-ca-cert.pem)
  3. Install the CA cert: double-click mitmproxy-ca-cert.cer -> Install ->
     Local Machine -> Trusted Root Certification Authorities
  4. Route game traffic through proxy (see instructions below)

Usage:
  python mitm_capture.py --dump
  python mitm_capture.py --server wss://xxxx.ngrok-free.app/capture
"""

import asyncio
import argparse
import logging
import struct
import sys
import time
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("aion2-mitm")

try:
    from mitmproxy import ctx, tcp, options
    from mitmproxy.tools import dump
    HAS_MITM = True
except ImportError:
    HAS_MITM = False

try:
    import websockets
except ImportError:
    pass

# Game server IPs (TLS)
GAME_SERVERS = {
    "216.107.253.19",
    "216.107.254.84",
    "209.35.114.69",
}


class Aion2Addon:
    """mitmproxy addon that captures game traffic"""

    def __init__(self, dump_mode=False, server_url=None):
        self.dump_mode = dump_mode
        self.server_url = server_url
        self.count = 0

    def request(self, flow):
        """HTTP request intercepted"""
        if flow.request.host in GAME_SERVERS or "216.107" in flow.request.host:
            self.count += 1
            body = flow.request.get_content()
            logger.info(
                f"[C2S] #{self.count} {flow.request.method} {flow.request.url} "
                f"body={len(body)}B"
            )

    def response(self, flow):
        """HTTP response intercepted"""
        if flow.request.host in GAME_SERVERS or "216.107" in flow.request.host:
            self.count += 1
            body = flow.response.get_content()
            logger.info(
                f"[S2C] #{self.count} {flow.response.status_code} {flow.request.url} "
                f"body={len(body)}B"
            )
            if body:
                head = body[:32].hex(" ")
                logger.info(f"  data=[{head}]")

    def tcp_message(self, flow: tcp.TCPFlow):
        """Raw TCP message (non-HTTP TLS)"""
        message = flow.messages[-1]
        self.count += 1
        direction = "S2C" if message.from_client is False else "C2S"
        data = message.content
        if data:
            head = data[:32].hex(" ")
            logger.info(
                f"[{direction}] #{self.count} TCP {len(data)}B [{head}]"
            )


def run_mitm_standalone():
    """Run as standalone mitmproxy script"""
    print("""
============================================
  Aion2 MITM TLS Proxy
============================================

This script runs as a mitmproxy addon.

SETUP (one-time):
  1. Install mitmproxy: pip install mitmproxy
  2. Generate CA cert:
     mitmdump --mode regular -p 8888 -q
     (press Ctrl+C after a few seconds)
  3. Install CA cert:
     - Open: %USERPROFILE%\\.mitmproxy\\mitmproxy-ca-cert.cer
     - Double-click -> Install Certificate
     - Select "Local Machine"
     - Select "Trusted Root Certification Authorities"
     - Finish

RUN:
  Method A (transparent proxy - requires admin + route setup):
    mitmdump --mode transparent -p 8888 -s mitm_capture.py

  Method B (SOCKS proxy - easier):
    mitmdump --mode socks5 -p 8888 -s mitm_capture.py
    Then use Proxifier to route Aion2.exe through socks5://127.0.0.1:8888

  Method C (regular proxy):
    mitmdump --mode regular -p 8888 -s mitm_capture.py
    Then set system proxy to 127.0.0.1:8888

GAME SERVER IPs TO WATCH:
  216.107.253.19:443
  216.107.254.84:443
""")


# mitmproxy addon entry point
addons = [Aion2Addon(dump_mode=True)]


if __name__ == "__main__":
    run_mitm_standalone()
