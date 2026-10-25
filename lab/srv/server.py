#!/usr/bin/env python3
"""Evidence server and flag checker for the CPIA Kali lab.

Serves, on port 8010:
    /                the lab index and flag entry page
    /artifacts/...   the read-only practice corpus
    /work/...        the case files, disk images, memory and logs
    /api/submit      POST {"lab":"L07","value":"..."}  -> {"ok":true|false}
    /api/progress    GET -> {"done":[...], "attempts":n}

Flag answers are checked against salted SHA-256 digests, so the page source never
carries a spoiler.
"""
import hashlib
import json
import os
import posixpath
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

PORT = int(os.environ.get("EVIDENCE_PORT", "8010"))
ROOT = "/labs"
FLAGS = "/usr/local/share/cpia/flags.json"
PROGRESS = os.path.join(ROOT, "reports", "progress.json")
LOCK = threading.Lock()

TYPES = {".html": "text/html; charset=utf-8", ".txt": "text/plain; charset=utf-8",
         ".md": "text/plain; charset=utf-8", ".json": "application/json",
         ".png": "image/png", ".pdf": "application/pdf", ".csv": "text/csv",
         ".pcap": "application/vnd.tcpdump.pcap", ".log": "text/plain; charset=utf-8"}


def read_progress():
    try:
        return json.load(open(PROGRESS))
    except Exception:
        return {"done": [], "attempts": 0}


def write_progress(p):
    os.makedirs(os.path.dirname(PROGRESS), exist_ok=True)
    json.dump(p, open(PROGRESS, "w"), indent=1)


class Handler(BaseHTTPRequestHandler):
    server_version = "CPIA-Lab/1.0"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/progress":
            return self.send_json(read_progress())
        if path == "/api/flags":
            # titles only, never the digests
            f = json.load(open(FLAGS))
            return self.send_json({k: {"title": v["title"]} for k, v in f.items()})
        if path in ("/", "/index.html", "/labs"):
            path = "/labs.html"
        target = posixpath.normpath(unquote(path))
        if target == "/labs.html":
            fs = os.path.join(ROOT, "labs.html")
        else:
            fs = posixpath.join(ROOT, target.lstrip("/"))
        if not os.path.isfile(fs):
            return self.send_error(404, "not found")
        ext = os.path.splitext(fs)[1].lower()
        ctype = TYPES.get(ext, "application/octet-stream")
        try:
            data = open(fs, "rb").read()
        except Exception:
            return self.send_error(403, "not readable")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if urlparse(self.path).path != "/api/submit":
            return self.send_error(404)
        n = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self.send_json({"ok": False, "error": "bad json"}, 400)
        lab = str(payload.get("lab", "")).upper()
        value = str(payload.get("value", ""))
        flags = json.load(open(FLAGS))
        if lab not in flags:
            return self.send_json({"ok": False, "error": "unknown lab"}, 400)
        e = flags[lab]
        got = hashlib.sha256((e["salt"] + value.strip().lower()).encode()).hexdigest()
        with LOCK:
            prog = read_progress()
            prog["attempts"] = prog.get("attempts", 0) + 1
            ok = got == e["sha256"]
            if ok and lab not in prog["done"]:
                prog["done"].append(lab)
                write_progress(prog)
            else:
                write_progress(prog)
            done = len(prog["done"])
        self.send_json({"ok": ok, "done": done, "complete": prog["done"]})


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[lab] evidence and flag server on http://127.0.0.1:{PORT}/")
    srv.serve_forever()


if __name__ == "__main__":
    main()
