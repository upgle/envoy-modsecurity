#!/usr/bin/env python3

import argparse
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


STARTUP_TIMEOUT_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 5


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-template", required=True)
    parser.add_argument("--envoy-binary", required=True)
    args, unittest_args = parser.parse_known_args()
    sys.argv = [sys.argv[0], *unittest_args]
    return args


ARGS = parse_args()


class RecordingUpstream(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), UpstreamHandler)
        self._requests = []
        self._requests_lock = threading.Lock()

    def record(self, method, path, body):
        with self._requests_lock:
            self._requests.append((method, path, body))

    def request_count(self):
        with self._requests_lock:
            return len(self._requests)

    def last_request(self):
        with self._requests_lock:
            return self._requests[-1] if self._requests else None


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        request_body = self._read_request_body()
        self.server.record(self.command, self.path, request_body)

        if self.headers.get("upgrade", "").lower() == "websocket":
            self.send_response(101)
            self.send_header("connection", "Upgrade")
            self.send_header("upgrade", "websocket")
            self.end_headers()
            self.close_connection = True
            return

        if self.path == "/large-response":
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("content-length", str(1024 * 1024 + 1))
            self.end_headers()
            return

        if self.path == "/chunked-response":
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("transfer-encoding", "chunked")
            self.send_header("trailer", "x-checksum")
            self.end_headers()
            for chunk in (b"upstream-", b"secret"):
                self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
                self.wfile.write(chunk + b"\r\n")
            self.wfile.write(b"0\r\nx-checksum: complete\r\n\r\n")
            return

        if self.path == "/events":
            response_body = b"data: ready\n\n"
            content_type = "text/event-stream"
        elif self.path == "/grpc-stream":
            response_body = b"\x00\x00\x00\x00\x02ok"
            content_type = "application/grpc"
        else:
            response_body = (
                b"upstream-secret" if self.path == "/response-blocked" else b"upstream-ok"
            )
            content_type = "text/plain"
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def _read_request_body(self):
        if self.headers.get("transfer-encoding", "").lower() != "chunked":
            length = int(self.headers.get("content-length", "0"))
            return self.rfile.read(length) if length else b""

        body = bytearray()
        while True:
            size_line = self.rfile.readline().strip()
            size = int(size_line.split(b";", 1)[0], 16)
            if size == 0:
                while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
                return bytes(body)
            body.extend(self.rfile.read(size))
            self.rfile.read(2)

    def log_message(self, _format, *_args):
        pass


class EnvoyHttpIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tempdir = tempfile.TemporaryDirectory(
            prefix="envoy-modsecurity-http-", dir=os.environ.get("TEST_TMPDIR")
        )
        try:
            cls._workdir = Path(cls._tempdir.name)
            cls._upstream = RecordingUpstream()
            cls._upstream_thread = threading.Thread(
                target=cls._upstream.serve_forever, daemon=True
            )
            cls._upstream_thread.start()

            template = Path(ARGS.config_template).read_text(encoding="utf-8")
            config = template.replace("__UPSTREAM_PORT__", str(cls._upstream.server_port))
            cls._config_path = cls._workdir / "bootstrap.yaml"
            cls._config_path.write_text(config, encoding="utf-8")
            cls._admin_address_path = cls._workdir / "admin-address.txt"
            cls._envoy_log_path = cls._workdir / "envoy.log"
            cls._envoy_log = cls._envoy_log_path.open("w", encoding="utf-8")

            validation = subprocess.run(
                [ARGS.envoy_binary, "--mode", "validate", "-c", str(cls._config_path)],
                capture_output=True,
                check=False,
                text=True,
                timeout=STARTUP_TIMEOUT_SECONDS,
            )
            if validation.returncode != 0:
                raise RuntimeError(
                    "custom Envoy rejected the integration bootstrap:\n"
                    f"stdout:\n{validation.stdout}\nstderr:\n{validation.stderr}"
                )

            cls._envoy = subprocess.Popen(
                [
                    ARGS.envoy_binary,
                    "-c",
                    str(cls._config_path),
                    "--admin-address-path",
                    str(cls._admin_address_path),
                    "--concurrency",
                    "1",
                    "--disable-hot-restart",
                    "--log-level",
                    "warning",
                    "--file-flush-interval-msec",
                    "10",
                ],
                stdout=cls._envoy_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            cls._admin_host, cls._admin_port = cls._wait_for_admin()
            cls._listener_port = cls._discover_listener_port()
        except Exception:
            cls._stop_envoy()
            cls._stop_upstream()
            cls._tempdir.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls._stop_envoy()
        cls._stop_upstream()
        cls._tempdir.cleanup()

    @classmethod
    def _stop_envoy(cls):
        envoy = getattr(cls, "_envoy", None)
        if envoy is not None and envoy.poll() is None:
            envoy.terminate()
            try:
                envoy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                envoy.kill()
                envoy.wait(timeout=5)
        envoy_log = getattr(cls, "_envoy_log", None)
        if envoy_log is not None and not envoy_log.closed:
            envoy_log.close()

    @classmethod
    def _stop_upstream(cls):
        upstream = getattr(cls, "_upstream", None)
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()
        upstream_thread = getattr(cls, "_upstream_thread", None)
        if upstream_thread is not None:
            upstream_thread.join(timeout=5)

    @classmethod
    def _envoy_logs(cls):
        envoy_log = getattr(cls, "_envoy_log", None)
        if envoy_log is not None and not envoy_log.closed:
            envoy_log.flush()
        log_path = getattr(cls, "_envoy_log_path", None)
        if log_path is None or not log_path.exists():
            return "<no Envoy log>"
        return log_path.read_text(encoding="utf-8")

    @classmethod
    def _access_log_entries(cls):
        entries = []
        for line in cls._envoy_logs().splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict) and "path" in entry:
                entries.append(entry)
        return entries

    def _wait_for_security_event(self, path):
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            matching = [
                entry
                for entry in self._access_log_entries()
                if entry.get("path") == path and isinstance(entry.get("modsecurity"), dict)
            ]
            if matching:
                return matching[-1]["modsecurity"]
            time.sleep(0.01)
        self.fail(f"no ModSecurity access-log metadata for {path}:\n{self._envoy_logs()}")

    @classmethod
    def _wait_for_admin(cls):
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        last_error = None
        while time.monotonic() < deadline:
            if cls._envoy.poll() is not None:
                raise RuntimeError(
                    f"custom Envoy exited with {cls._envoy.returncode}:\n{cls._envoy_logs()}"
                )
            if cls._admin_address_path.exists():
                address = cls._admin_address_path.read_text(encoding="utf-8").strip()
                if address:
                    try:
                        host, port = address.rsplit(":", 1)
                        host = host.strip("[]")
                        status, _body = cls._admin_request(host, int(port), "/ready")
                        if status == 200:
                            return host, int(port)
                    except (
                        ConnectionError,
                        OSError,
                        ValueError,
                        http.client.HTTPException,
                    ) as error:
                        last_error = error
            time.sleep(0.05)
        raise RuntimeError(
            f"custom Envoy admin did not become ready: {last_error}\n{cls._envoy_logs()}"
        )

    @staticmethod
    def _admin_request(host, port, path):
        connection = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    @classmethod
    def _discover_listener_port(cls):
        status, body = cls._admin_request(
            cls._admin_host, cls._admin_port, "/listeners?format=json"
        )
        if status != 200:
            raise RuntimeError(f"listener discovery failed with HTTP {status}: {body!r}")
        listeners = json.loads(body)["listener_statuses"]
        for listener in listeners:
            if listener["name"] == "modsecurity_integration_listener":
                return listener["local_address"]["socket_address"]["port_value"]
        raise RuntimeError(f"integration listener was not found: {listeners!r}")

    @classmethod
    def _wait_for_zero_modsecurity_gauges(cls, *suffixes):
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        last_values = {}
        while time.monotonic() < deadline:
            status, body = cls._admin_request(
                cls._admin_host, cls._admin_port, "/stats?filter=modsecurity&format=json"
            )
            if status != 200:
                raise RuntimeError(f"stats query failed with HTTP {status}: {body!r}")
            stats = json.loads(body)["stats"]
            last_values = {
                suffix: [
                    stat["value"]
                    for stat in stats
                    if "name" in stat
                    and "value" in stat
                    and stat["name"].endswith(f".{suffix}")
                ]
                for suffix in suffixes
            }
            if all(
                values and all(value == 0 for value in values)
                for values in last_values.values()
            ):
                return
            time.sleep(0.05)
        raise AssertionError(f"ModSecurity gauges did not return to zero: {last_values}")

    @classmethod
    def _request(cls, method, path, body=None, content_type=None):
        headers = {"host": "integration.test"}
        if body is not None:
            headers["content-type"] = content_type or "application/x-www-form-urlencoded"
        connection = http.client.HTTPConnection(
            "127.0.0.1", cls._listener_port, timeout=REQUEST_TIMEOUT_SECONDS
        )
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    @classmethod
    def _chunked_request(cls, path, chunks, trailers=None, content_type=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", cls._listener_port, timeout=REQUEST_TIMEOUT_SECONDS
        )
        try:
            connection.putrequest("POST", path)
            connection.putheader("host", "integration.test")
            connection.putheader(
                "content-type", content_type or "application/x-www-form-urlencoded"
            )
            connection.putheader("transfer-encoding", "chunked")
            if trailers:
                connection.putheader("trailer", ", ".join(trailers))
            connection.endheaders()
            for chunk in chunks:
                encoded = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
                connection.send(f"{len(encoded):x}\r\n".encode("ascii"))
                connection.send(encoded)
                connection.send(b"\r\n")
            connection.send(b"0\r\n")
            for name, value in (trailers or {}).items():
                connection.send(f"{name}: {value}\r\n".encode("ascii"))
            connection.send(b"\r\n")
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    @classmethod
    def _websocket_handshake(cls, path):
        connection = http.client.HTTPConnection(
            "127.0.0.1", cls._listener_port, timeout=REQUEST_TIMEOUT_SECONDS
        )
        try:
            connection.putrequest("GET", path)
            connection.putheader("host", "integration.test")
            connection.putheader("connection", "Upgrade")
            connection.putheader("upgrade", "websocket")
            connection.putheader("sec-websocket-version", "13")
            connection.putheader("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            connection.endheaders()
            response = connection.getresponse()
            return response.status
        finally:
            connection.close()

    def assertResponse(self, method, path, expected_status, expected_body, body=None):
        status, response_body = self._request(method, path, body)
        self.assertEqual(expected_status, status, self._envoy_logs())
        self.assertIn(expected_body, response_body, self._envoy_logs())

    def test_allows_safe_request_to_upstream(self):
        before = self._upstream.request_count()
        self.assertResponse("GET", "/allowed", 200, b"upstream-ok")
        self.assertEqual(before + 1, self._upstream.request_count())

    def test_blocks_phase_one_before_upstream(self):
        before = self._upstream.request_count()
        self.assertResponse(
            "GET", "/request-blocked/resource", 418, b"request blocked by ModSecurity"
        )
        self.assertEqual(before, self._upstream.request_count())
        event = self._wait_for_security_event("/request-blocked/resource")
        self.assertEqual("blocked", event["outcome"])
        self.assertEqual("rule_intervention", event["reason"])
        self.assertEqual(418, event["http_status"])
        self.assertEqual("9100001", event["rules"][0]["id"])
        self.assertTrue(event["rules"][0]["disruptive"])

    def test_blocks_phase_two_before_upstream(self):
        before = self._upstream.request_count()
        self.assertResponse(
            "POST", "/submit", 406, b"request blocked by ModSecurity", "value=attack-token"
        )
        self.assertEqual(before, self._upstream.request_count())

    def test_chunked_request_with_trailers_is_reassembled(self):
        before = self._upstream.request_count()
        status, response_body = self._chunked_request(
            "/submit", ["value=", "safe"], {"x-checksum": "complete"}
        )
        self.assertEqual(200, status, self._envoy_logs())
        self.assertIn(b"upstream-ok", response_body, self._envoy_logs())
        self.assertEqual(before + 1, self._upstream.request_count())
        self.assertEqual(b"value=safe", self._upstream.last_request()[2])

    def test_chunk_boundary_does_not_hide_phase_two_match(self):
        before = self._upstream.request_count()
        status, response_body = self._chunked_request(
            "/submit", ["value=att", "ack-to", "ken"], {"x-checksum": "complete"}
        )
        self.assertEqual(406, status, self._envoy_logs())
        self.assertIn(b"request blocked by ModSecurity", response_body, self._envoy_logs())
        self.assertEqual(before, self._upstream.request_count())

    def test_grpc_stream_is_header_only_and_not_buffered(self):
        before = self._upstream.request_count()
        status, response_body = self._chunked_request(
            "/grpc-stream",
            [b"\x00\x00\x00\x00\x0c", b"attack-token"],
            {"grpc-status": "0"},
            "application/grpc",
        )
        self.assertEqual(200, status, self._envoy_logs())
        self.assertEqual(b"\x00\x00\x00\x00\x02ok", response_body)
        self.assertEqual(before + 1, self._upstream.request_count())

    def test_websocket_handshake_is_not_waiting_for_end_stream(self):
        before = self._upstream.request_count()
        self.assertEqual(101, self._websocket_handshake("/socket"), self._envoy_logs())
        self.assertEqual(before + 1, self._upstream.request_count())

    def test_server_sent_events_response_is_not_buffered(self):
        self.assertResponse("GET", "/events", 200, b"data: ready")

    def test_repeated_body_requests_release_accounting(self):
        before = self._upstream.request_count()
        safe_body = "value=" + "a" * 4096
        for _ in range(64):
            self.assertResponse("POST", "/submit", 200, b"upstream-ok", safe_body)
        self.assertEqual(before + 64, self._upstream.request_count())

    def test_file_upload_at_exact_inspection_limit_is_allowed(self):
        before = self._upstream.request_count()
        upload = b"x" * (1024 * 1024)
        status, response_body = self._request(
            "POST", "/upload", upload, "application/octet-stream"
        )
        self.assertEqual(200, status, self._envoy_logs())
        self.assertIn(b"upstream-ok", response_body, self._envoy_logs())
        self.assertEqual(before + 1, self._upstream.request_count())
        self.assertEqual(len(upload), len(self._upstream.last_request()[2]))

    def test_rejects_request_body_above_inspection_limit(self):
        before = self._upstream.request_count()
        oversized_body = "x" * (1024 * 1024 + 1)
        self.assertResponse(
            "POST",
            "/submit",
            413,
            b"request body exceeds ModSecurity inspection limit",
            oversized_body,
        )
        self.assertEqual(before, self._upstream.request_count())

    def test_rejects_declared_oversized_response_before_body(self):
        before = self._upstream.request_count()
        self.assertResponse(
            "GET", "/large-response", 500, b"ModSecurity inspection error"
        )
        self.assertEqual(before + 1, self._upstream.request_count())

    def test_blocks_phase_four_upstream_response(self):
        before = self._upstream.request_count()
        self.assertResponse(
            "GET", "/response-blocked", 451, b"response blocked by ModSecurity"
        )
        self.assertEqual(before + 1, self._upstream.request_count())

    def test_response_chunks_and_trailers_are_finalized_together(self):
        before = self._upstream.request_count()
        self.assertResponse(
            "GET", "/chunked-response", 451, b"response blocked by ModSecurity"
        )
        self.assertEqual(before + 1, self._upstream.request_count())

    def test_z_releases_native_transactions_and_body_accounting(self):
        self._wait_for_zero_modsecurity_gauges(
            "active_transactions", "modsecurity_buffer_bytes"
        )


if __name__ == "__main__":
    unittest.main()
