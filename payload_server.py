#!/usr/bin/env python3
"""
payload_server.py — CyberSentinel AI payload/exfil endpoint.

Runs inside the "payload" docker-compose service, on the same
docker-compose network as Cowrie. Serves two roles:

  GET  /<file>    — serves whatever attack1.sh's Phase 3 wrote here
                     (normally payload.sh), for T1105/T1204.
  POST /upload     — accepts the file Phase 13's exfiltration attempt
                     sends, and writes it to ./uploads/, for T1041.
                     (python's http.server doesn't handle POST at all,
                     which is why this exists instead of just
                     `python3 -m http.server`.)

Deliberately dependency-free (stdlib only) so the python:3.12-alpine
image needs no pip install step.
"""
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SRV_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(SRV_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberSentinelPayload/1.0"

    def log_message(self, fmt, *args):
        print(f"[payload_server] {self.address_string()} - {fmt % args}")

    def do_GET(self):
        path = self.path.lstrip("/").split("?", 1)[0]
        if not path or ".." in path:
            self.send_error(404)
            return
        full = os.path.join(SRV_DIR, path)
        if not os.path.isfile(full):
            self.send_error(404)
            return
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        # Accepts anything POSTed to /upload — raw body or multipart, we
        # don't bother parsing multipart boundaries; for the purposes of
        # demonstrating T1041 (Exfiltration Over C2 Channel) what matters
        # is that data leaves the compromised host and lands here, not
        # that we reconstruct a perfect multipart form.
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        fname = f"exfil_{int(time.time())}.bin"
        out_path = os.path.join(UPLOAD_DIR, fname)
        with open(out_path, "wb") as f:
            f.write(body)
        print(f"[payload_server] received {len(body)} bytes -> uploads/{fname}")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[payload_server] serving {SRV_DIR} on 0.0.0.0:{port} (GET static, POST /upload)")
    srv.serve_forever()
