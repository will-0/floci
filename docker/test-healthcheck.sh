#!/bin/sh
# Exercise the health probe against a real HTTP listener on a nondefault port.
set -eu
python3 - "$(dirname "$0")/healthcheck.sh" <<'PY'
import http.server
import os
import subprocess
import sys
import threading

class Ready(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.path == '/_floci/init'
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ready":true}')
    def log_message(self, *args):
        pass

with http.server.HTTPServer(('127.0.0.1', 0), Ready) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    result = subprocess.run(['bash', sys.argv[1]], env={**os.environ, 'FLOCI_PORT': str(server.server_port)}, timeout=5)
    assert result.returncode == 0, 'Custom-port health probe must reach the ready endpoint'
    server.shutdown()
print('PASS: health probe honors FLOCI_PORT')
PY
