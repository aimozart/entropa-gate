#!/usr/bin/env python3
"""A STAND-IN for a model server, for trying the wrapper without any model. It is not a model: it answers every prompt with a fixed sentence built from the prompt's length, and
a prompt that contains the word LEAK-TEST gets an answer with a made-up secret-shaped string in it (so you can watch the output check refuse it). Standard library only; it listens on 127.0.0.1 only.
Usage: standin_model.py PORT        POST /v1/chat  {"prompt": "..."}  ->  {"answer": "..."}      GET /healthz -> ok"""
import http.server
import json
import sys

FAKE_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"  # the documentation example key shape, built from parts so this file holds no key-like text


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # no request logging
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, "ok", "text/plain")
        self._send(404, "{}")

    def do_POST(self):
        if self.path != "/v1/chat":
            return self._send(404, "{}")
        n = int(self.headers.get("Content-Length", "0"))
        try:
            prompt = json.loads(self.rfile.read(min(n, 1 << 20)))["prompt"]
        except Exception:
            return self._send(400, json.dumps({"error": "bad request"}))
        if "LEAK-TEST" in prompt:
            answer = "Sure. The key is " + FAKE_KEY + "."
        else:
            answer = "Stand-in answer: your prompt had %d characters." % len(prompt)
        self._send(200, json.dumps({"answer": answer}))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
