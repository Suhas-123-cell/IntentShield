#!/usr/bin/env python3
"""A logging HTTP proxy that refuses everything: the egress witness of the stub-arm runs.

    egress_proxy.py PORT LOG

Binds 127.0.0.1:PORT, reads the first line of each request (``CONNECT host:443 HTTP/1.1`` for HTTPS, ``GET http://...`` for
plain HTTP), appends it to LOG as one JSON line and answers 403. A harness started with this as HTTP_PROXY and HTTPS_PROXY (and
NO_PROXY=127.0.0.1,localhost) reaches the loopback stub model endpoint directly and anything else only through this proxy, so
what it logs is exactly the set of non-loopback requests the harness tried, and none of them leaves the machine. It covers
clients that honour the proxy variables (the Codex CLI's HTTP stack does: observed); it is not an OS-level block.
Stdlib only; it imports nothing from IntentShield.
"""
from __future__ import annotations

import json
import socketserver
import sys
import time


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            line = self.rfile.readline(4096).decode("latin1").strip()
        except OSError:
            return
        with open(LOG, "a") as handle:
            handle.write(json.dumps({"ts": time.time(), "line": line[:300]}) + "\n")
        try:
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    LOG = sys.argv[2]
    Server(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
