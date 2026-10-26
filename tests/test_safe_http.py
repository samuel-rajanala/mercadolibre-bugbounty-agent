"""Offline tests for redirect handling; no external hosts are contacted."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request
from scripts.safe_http import safe_open


def test_safe_open_returns_redirect_without_following_it():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/destination")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"destination reached")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(f"http://127.0.0.1:{server.server_port}/start")
        response = safe_open(request, timeout=2)
        assert response.code == 302
        assert response.headers["Location"] == "/destination"
        assert hits == ["/start"]
        response.close()
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
