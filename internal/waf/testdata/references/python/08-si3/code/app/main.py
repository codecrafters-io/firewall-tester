import argparse
import http.client
import time
import threading
import socket
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import unicodedata
import urllib.parse


HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "content-length"}


def decode_component(value, plus=False):
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Invalid percent escape")
    if plus:
        value = value.replace("+", " ")
    return urllib.parse.unquote(value, encoding="utf-8", errors="strict")


def form_values(raw, inspect_bare=False):
    values = []
    for part in raw.split("&"):
        if part:
            key, separator, value = part.partition("=")
            if not separator and inspect_bare:
                value = key
            decode_component(key, True)
            values.append(decode_component(value, True))
    return values


def canonical(value):
    return unicodedata.normalize("NFKC", value).casefold()


def classify(endpoint, inputs):
    deadline = time.monotonic() + 0.2
    url = urllib.parse.urlsplit(endpoint)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=0.2)
    timer = None
    try:
        connection.connect()
        transport = connection.sock

        def expire():
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        connection.request("POST", url.path.rstrip("/") + "/classify",
                           json.dumps({"inputs": inputs}),
                           {"Content-Type": "application/json"})
        with connection.getresponse() as response:
            result = json.loads(response.read())
        if time.monotonic() >= deadline or response.status != 200:
            return None
        if not isinstance(result, dict) or type(result.get("score")) is not int:
            return None
        return result["score"] if 0 <= result["score"] <= 100 else None
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--detector", required=True)
    parser.add_argument("--policy", required=True)
    args = parser.parse_args()
    origin = urllib.parse.urlsplit(args.origin)
    policy = json.loads(Path(args.policy).read_text())

    class Handler(BaseHTTPRequestHandler):
        def reject(self, status, rule, diagnostics=None):
            payload = json.dumps({"error": {"rule": rule}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-WAF-Match", rule)
            for key, value in (diagnostics or {}).items():
                if key.lower() != "x-waf-match":
                    self.send_header(key, str(value))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

        def handle_request(self):
            if self.command == "GET" and self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            diagnostics = {}
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            inputs = [self.path, body.decode("utf-8", errors="replace")]
            try:
                raw_path, _, query = self.path.partition("?")
                decoded_path = decode_component(raw_path)
                if policy.get("normalization"):
                    inputs = [decoded_path, *form_values(query, inspect_bare=True)]
                    for name in policy.get("inspect_headers", []):
                        inputs.extend(value.encode("latin-1").decode("utf-8", errors="replace")
                                      for value in self.headers.get_all(name, []))
                    inputs.append(body.decode("utf-8", errors="replace"))
            except (ValueError, UnicodeError):
                self.reject(400, "invalid_request")
                return
            if policy.get("normalization"):
                inputs = [canonical(value) for value in inputs]
            match = next((rule["id"] for rule in policy.get("denylist", [])
                          if any(rule["term"] in value for value in inputs)), None)
            heuristic = policy.get("heuristics")
            signals = [signal for signal in (heuristic or {}).get("signals", [])
                       if any(re.search(signal["pattern"], value) for value in inputs)]
            score = sum(signal["weight"] for signal in signals)
            if heuristic:
                diagnostics["X-WAF-Score"] = str(score)
                if signals:
                    diagnostics["X-WAF-Signals"] = ",".join(signal["id"] for signal in signals)
                if not match and score >= heuristic["threshold"]:
                    match = "heuristic_score"
            classifier = policy.get("classifier")
            ml_score = None
            if classifier:
                ml_score = classify(args.detector, inputs)
                diagnostics["X-WAF-Detector-Status"] = "ok" if ml_score is not None else "unavailable"
                if ml_score is not None:
                    diagnostics["X-WAF-ML-Score"] = str(ml_score)
                    if not match and ml_score >= classifier["threshold"]:
                        match = "ml_score"
            decisions = policy.get("decisions")
            if decisions and ml_score is not None:
                thresholds = decisions["default"]
                for route in decisions.get("routes", []):
                    if decoded_path == route["path"]:
                        thresholds = route
                        break
                match = next((rule["id"] for rule in policy.get("denylist", [])
                              if any(rule["term"] in value for value in inputs)), None)
                if not match:
                    if score >= thresholds["heuristic_high"]:
                        match = "heuristic_high"
                    elif ml_score >= thresholds["ml_high"]:
                        match = "ml_high"
                    elif ml_score >= thresholds["ml_medium"] and score >= thresholds["heuristic_medium"]:
                        match = "combined_scores"
            if match:
                if policy.get("mode", "block") == "block":
                    self.reject(403, match, diagnostics)
                    return
                diagnostics["X-WAF-Match"] = match
            connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=3)
            try:
                excluded = HOP_HEADERS | {name.strip().lower() for name in ",".join(self.headers.get_all("Connection", [])).split(",")}
                connection.putrequest(self.command, self.path, skip_accept_encoding=True)
                for key, value in self.headers.items():
                    if (key.lower() not in excluded and key.lower() != "host"
                            and not key.lower().startswith("x-waf-")):
                        connection.putheader(key, value)
                connection.putheader("Content-Length", str(len(body)))
                connection.endheaders(body)
                with connection.getresponse() as response:
                    content = response.read()
                    self.send_response(response.status)
                    excluded = HOP_HEADERS | {name.strip().lower() for name in ",".join(response.headers.get_all("Connection", [])).split(",")}
                    for key, value in response.getheaders():
                        if key.lower() not in excluded and not key.lower().startswith("x-waf-"):
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(content)))
                    for key, value in diagnostics.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(content)
            except (OSError, http.client.HTTPException):
                self.reject(502, "origin_unavailable", diagnostics)
            finally:
                connection.close()

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
