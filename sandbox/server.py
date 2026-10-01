"""Single-purpose internal sandbox service with no host mounts or credentials."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


def run(command: str, timeout: int) -> dict:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            [sys.executable, "/app/exec.py", command], stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, cwd="/tmp", start_new_session=True,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C"},
        )
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        stdout.seek(0)
        stderr.seek(0)
        return {
            "exit_code": process.returncode, "timed_out": timed_out,
            "stdout": stdout.read(4096).decode("utf-8", errors="replace"),
            "stderr": stderr.read(4096).decode("utf-8", errors="replace"),
        }


class Handler(BaseHTTPRequestHandler):
    def respond(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self.respond(200, {"status": "ok"})
        else:
            self.respond(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/execute":
            return self.respond(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 2048:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(length))
            uuid.UUID(payload["call_id"])
            command, timeout = payload["command"], payload["timeout_seconds"]
            if not isinstance(command, str) or not 1 <= len(command) <= 1000 or "\x00" in command:
                raise ValueError("Invalid command")
            if type(timeout) is not int or not 1 <= timeout <= 5:
                raise ValueError("Invalid timeout")
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return self.respond(422, {"error": "invalid_request"})
        self.respond(200, run(command, timeout))

    def log_message(self, format: str, *args) -> None:
        # Commands and output are deliberately absent from service logs.
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
