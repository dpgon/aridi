"""Test webhook of the phase 6 acceptance (service "hook" of compose.acceptance.yaml).

POST: keeps the JSON body. GET: answers the list of bodies received. Standard library.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

received = []
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with lock:
            received.append(body)
        print("hook: received", body.get("text"), flush=True)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        with lock:
            data = json.dumps(received).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
