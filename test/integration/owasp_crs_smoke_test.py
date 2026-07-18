#!/usr/bin/env python3

import argparse
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler

from test.integration.envoy_test_harness import (
    REQUEST_TIMEOUT_SECONDS,
    EnvoyProcess,
    RecordingUpstream,
)


EXPECTED_CRS_RULE_FILE_COUNT = 27


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-template", required=True)
    parser.add_argument("--crs-config-template", required=True)
    parser.add_argument("--crs-rules-marker", required=True)
    parser.add_argument("--crs-setup", required=True)
    parser.add_argument("--envoy-binary", required=True)
    parser.add_argument("--unicode-mapping", required=True)
    args, unittest_args = parser.parse_known_args()
    sys.argv = [sys.argv[0], *unittest_args]
    return args


ARGS = parse_args()


def seclang_path(path):
    value = str(Path(path).resolve())
    if any(character.isspace() for character in value) or "#" in value:
        raise ValueError(f"path cannot be represented safely in SecLang: {value!r}")
    return value


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b""
        self.server.record(self.command, self.path, body)
        response_body = b"upstream-ok"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, _format, *_args):
        pass


class OwaspCrsSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tempdir = tempfile.TemporaryDirectory(
            prefix="envoy-modsecurity-crs-", dir=os.environ.get("TEST_TMPDIR")
        )
        try:
            cls._workdir = Path(cls._tempdir.name)
            cls._upstream = RecordingUpstream(UpstreamHandler)
            cls._upstream.start()

            cls._crs_config_path = cls._write_crs_config()
            bootstrap_template = Path(ARGS.config_template).read_text(encoding="utf-8")
            bootstrap = bootstrap_template.replace(
                "__UPSTREAM_PORT__", str(cls._upstream.server_port)
            ).replace("__CRS_ROOT_CONFIG__", json.dumps(str(cls._crs_config_path)))
            cls._config_path = cls._workdir / "bootstrap.yaml"
            cls._config_path.write_text(bootstrap, encoding="utf-8")
            cls._envoy = EnvoyProcess(
                ARGS.envoy_binary,
                cls._config_path,
                cls._workdir,
                "owasp_crs_smoke_listener",
                "the OWASP CRS smoke bootstrap",
            )
            cls._envoy.start()
            cls._listener_port = cls._envoy.listener_port
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
    def _write_crs_config(cls):
        rules_directory = Path(ARGS.crs_rules_marker).resolve().parent
        rule_files = sorted(rules_directory.glob("*.conf"))
        if len(rule_files) != EXPECTED_CRS_RULE_FILE_COUNT:
            raise RuntimeError(
                "expected "
                f"{EXPECTED_CRS_RULE_FILE_COUNT} pinned CRS rule files, "
                f"found {len(rule_files)}"
            )

        template = Path(ARGS.crs_config_template).read_text(encoding="utf-8")
        includes = "\n".join(f"Include {seclang_path(path)}" for path in rule_files)
        config = (
            template.replace("__UNICODE_MAPPING__", seclang_path(ARGS.unicode_mapping))
            .replace("__CRS_SETUP__", seclang_path(ARGS.crs_setup))
            .replace("__CRS_RULE_INCLUDES__", includes)
        )
        config_path = cls._workdir / "owasp-crs.conf"
        config_path.write_text(config, encoding="utf-8")
        config_path.chmod(0o444)
        return config_path

    @classmethod
    def _stop_envoy(cls):
        envoy = getattr(cls, "_envoy", None)
        if envoy is not None:
            envoy.stop()

    @classmethod
    def _stop_upstream(cls):
        upstream = getattr(cls, "_upstream", None)
        if upstream is not None:
            upstream.stop()

    @classmethod
    def _envoy_logs(cls):
        envoy = getattr(cls, "_envoy", None)
        return envoy.logs() if envoy is not None else "<no Envoy log>"

    @classmethod
    def _request(cls, method, path, body=None, headers=None):
        request_headers = {
            "accept": "*/*",
            "host": "crs-smoke.test",
            "user-agent": "envoy-modsecurity-crs-smoke",
        }
        if body is not None:
            request_headers["content-type"] = "application/x-www-form-urlencoded"
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection(
            "127.0.0.1", cls._listener_port, timeout=REQUEST_TIMEOUT_SECONDS
        )
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def assertAllowed(self, method, path, body=None, headers=None):
        before = self._upstream.request_count()
        status, response_body = self._request(method, path, body, headers)
        self.assertEqual(200, status, self._envoy_logs())
        self.assertIn(b"upstream-ok", response_body, self._envoy_logs())
        self.assertEqual(before + 1, self._upstream.request_count())

    def assertBlocked(self, method, path, body=None, headers=None):
        before = self._upstream.request_count()
        status, response_body = self._request(method, path, body, headers)
        self.assertEqual(403, status, self._envoy_logs())
        self.assertIn(b"request blocked by ModSecurity", response_body, self._envoy_logs())
        self.assertEqual(before, self._upstream.request_count())

    def test_allows_normal_get(self):
        self.assertAllowed("GET", "/products?page=2&sort=price")

    def test_allows_normal_form_body(self):
        self.assertAllowed("POST", "/profile", "name=Alice&city=Seoul")

    def test_allows_normal_json_body(self):
        self.assertAllowed(
            "POST",
            "/search",
            json.dumps({"query": "weather", "limit": 10}),
            {"content-type": "application/json"},
        )

    def test_allows_upstream_scanner_allowlist_user_agent(self):
        self.assertAllowed(
            "GET", "/packages", headers={"user-agent": "urlgrabber/3.10 yum/3.4.3"}
        )

    def test_blocks_disallowed_method(self):
        self.assertBlocked("DELETE", "/method-policy")

    def test_blocks_scanner_user_agent(self):
        self.assertBlocked("GET", "/", headers={"user-agent": "nuclei"})

    def test_blocks_protocol_content_type_violation(self):
        self.assertBlocked(
            "POST", "/submit", "test", {"content-type": "my-new-content-type"}
        )

    def test_blocks_request_smuggling_payload(self):
        self.assertBlocked("POST", "/submit", "var=%0aPOST+/+HTTP/1.1")

    def test_blocks_local_file_inclusion(self):
        self.assertBlocked("GET", "/get?file=.../.../WINDOWS/win.ini")

    def test_blocks_remote_file_inclusion(self):
        self.assertBlocked(
            "GET",
            "/get/timthumb.php?src=http://66.240.183.75/crash.php",
            headers={"referer": "http"},
        )

    def test_blocks_command_injection(self):
        self.assertBlocked("POST", "/run", "arg=%3Bifconfig+example")

    def test_blocks_php_injection(self):
        self.assertBlocked("GET", "/get?code=%3C%3F+exec%28%27wget%20example%27%29")

    def test_blocks_generic_node_injection(self):
        self.assertBlocked("GET", "/get?value=_%24%24ND_FUNC%24%24_")

    def test_blocks_cross_site_scripting(self):
        self.assertBlocked(
            "POST", "/comment", "text=%3Cxss+onbeforehellfreezes%3Daler%77%281%29%3E"
        )

    def test_blocks_form_sql_injection(self):
        self.assertBlocked("POST", "/login", "user=1234+OR+1%3D1")

    def test_blocks_protocol_attack_in_json_body(self):
        self.assertBlocked(
            "POST",
            "/api/import",
            json.dumps({"request": "GET /admin HTTP/1.1"}),
            {"content-type": "application/json"},
        )

    def test_blocks_session_fixation(self):
        self.assertBlocked("GET", "/get?session=.cookie%3Bexpires%3D")

    def test_blocks_java_injection(self):
        self.assertBlocked("POST", "/deserialize", "value=java.lang.Runtime")

    def test_z_releases_native_transactions_and_body_accounting(self):
        self._envoy.wait_for_zero_modsecurity_gauges(
            "active_transactions", "modsecurity_buffer_bytes"
        )


if __name__ == "__main__":
    unittest.main()
