"""Exercise the workflow's curl download against transient HTTP failures."""
import contextlib
import http.server
import pathlib
import re
import shlex
import subprocess
import tempfile
import threading
import unittest

WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/static.yml"
BODY = b"verified download payload\n"


class DownloadRetry(unittest.TestCase):
    def download(self, statuses):
        responses = list(statuses)
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                code = responses.pop(0) if responses else statuses[-1]
                seen.append(code)
                self.send_response(code)
                self.end_headers()
                if code == 200:
                    self.wfile.write(BODY)

            def log_message(self, format: str, *args: object) -> None:
                pass

        source = WORKFLOW.read_text(encoding="utf-8")
        match = re.search(r'(?m)^\s*(curl -fsSL .*?\n\s*"https://github\.com/gitleaks/[^\n]+")',
                          source, re.DOTALL)
        if match is None:
            raise AssertionError("gitleaks curl invocation missing")
        command = shlex.split(match.group(1).replace("\\\n", " "))
        with contextlib.ExitStack() as stack:
            server = stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(thread.join)
            stack.callback(server.shutdown)
            directory = stack.enter_context(tempfile.TemporaryDirectory())
            output = pathlib.Path(directory) / "archive"
            command = [str(output) if arg == "$archive" else arg for arg in command]
            command[-1] = f"http://127.0.0.1:{server.server_port}/archive"
            result = subprocess.run(command, capture_output=True, timeout=20, check=False)
            return result, seen, output.read_bytes() if output.exists() else b""

    def test_transient_errors_then_success(self):
        result, seen, payload = self.download([503, 504, 200])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(seen, [503, 504, 200])
        self.assertEqual(payload, BODY)

    def test_persistent_errors_fail(self):
        result, seen, payload = self.download([504])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(seen, [504, 504, 504, 504])
        self.assertEqual(payload, b"")


if __name__ == "__main__":
    unittest.main()
