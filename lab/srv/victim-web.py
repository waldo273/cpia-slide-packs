#!/usr/bin/env python3
"""The victim web service, inside the same container.

Small on purpose: it exists so drills can fingerprint a real banner, fetch a page and read an
access log, without a second machine and without touching the internet.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("VICTIM_PORT", "8080"))
LOG = "/var/log/victim-web.log"

PAGE = b"""<!DOCTYPE html><html lang="en-GB"><head><meta charset="utf-8">
<title>Northwind Supplies: portal</title></head><body>
<h1>Northwind Supplies</h1>
<p>Staff portal. Invoice queries: accounts@northwind-supplies.example</p>
<ul><li><a href="/status">Service status</a></li><li><a href="/robots.txt">robots.txt</a></li></ul>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.52"
    sys_version = "(Debian)"

    def log_message(self, fmt, *args):
        with open(LOG, "a") as fh:
            fh.write("%s %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path == "/robots.txt":
            body, ctype = b"User-agent: *\nDisallow: /admin\n", "text/plain"
        elif self.path == "/status":
            body, ctype = b"ok: portal, mail, files\n", "text/plain"
        else:
            body, ctype = PAGE, "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
