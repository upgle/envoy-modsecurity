import http.client
import json
from pathlib import Path
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer


STARTUP_TIMEOUT_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 5


class RecordingUpstream(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, handler_class):
        super().__init__(("127.0.0.1", 0), handler_class)
        self._requests = []
        self._requests_lock = threading.Lock()
        self._thread = None

    def start(self):
        if self._thread is not None:
            return
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        self._thread = thread

    def stop(self):
        if self._thread is not None:
            self.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self.server_close()

    def record(self, method, path, body):
        with self._requests_lock:
            self._requests.append((method, path, body))

    def request_count(self):
        with self._requests_lock:
            return len(self._requests)

    def last_request(self):
        with self._requests_lock:
            return self._requests[-1] if self._requests else None


class EnvoyProcess:
    def __init__(self, binary, config_path, workdir, listener_name, config_description):
        self._binary = binary
        self._config_path = Path(config_path)
        self._listener_name = listener_name
        self._config_description = config_description
        self._admin_address_path = Path(workdir) / "admin-address.txt"
        self._log_path = Path(workdir) / "envoy.log"
        self._log = None
        self._process = None
        self._admin_host = None
        self._admin_port = None
        self.listener_port = None

    def start(self):
        validation = subprocess.run(
            [self._binary, "--mode", "validate", "-c", str(self._config_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=STARTUP_TIMEOUT_SECONDS,
        )
        if validation.returncode != 0:
            raise RuntimeError(
                f"custom Envoy rejected {self._config_description}:\n"
                f"stdout:\n{validation.stdout}\nstderr:\n{validation.stderr}"
            )

        self._log = self._log_path.open("w", encoding="utf-8")
        try:
            self._process = subprocess.Popen(
                [
                    self._binary,
                    "-c",
                    str(self._config_path),
                    "--admin-address-path",
                    str(self._admin_address_path),
                    "--concurrency",
                    "1",
                    "--disable-hot-restart",
                    "--log-level",
                    "warning",
                ],
                stdout=self._log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self._admin_host, self._admin_port = self._wait_for_admin()
            self.listener_port = self._discover_listener_port()
        except Exception:
            self.stop()
            raise

    def stop(self):
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
        if self._log is not None and not self._log.closed:
            self._log.close()

    def logs(self):
        if self._log is not None and not self._log.closed:
            self._log.flush()
        if not self._log_path.exists():
            return "<no Envoy log>"
        return self._log_path.read_text(encoding="utf-8")

    def admin_request(self, path):
        return self._request(self._admin_host, self._admin_port, path)

    def wait_for_zero_modsecurity_gauges(self, *suffixes):
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        last_values = {}
        while time.monotonic() < deadline:
            status, body = self.admin_request("/stats?filter=modsecurity&format=json")
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

    def _wait_for_admin(self):
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        last_error = None
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise RuntimeError(
                    f"custom Envoy exited with {self._process.returncode}:\n{self.logs()}"
                )
            if self._admin_address_path.exists():
                address = self._admin_address_path.read_text(encoding="utf-8").strip()
                if address:
                    try:
                        host, port = address.rsplit(":", 1)
                        host = host.strip("[]")
                        status, _body = self._request(host, int(port), "/ready")
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
            f"custom Envoy admin did not become ready: {last_error}\n{self.logs()}"
        )

    def _discover_listener_port(self):
        status, body = self.admin_request("/listeners?format=json")
        if status != 200:
            raise RuntimeError(f"listener discovery failed with HTTP {status}: {body!r}")
        listeners = json.loads(body)["listener_statuses"]
        for listener in listeners:
            if listener["name"] == self._listener_name:
                return listener["local_address"]["socket_address"]["port_value"]
        raise RuntimeError(f"listener {self._listener_name!r} was not found: {listeners!r}")

    @staticmethod
    def _request(host, port, path):
        connection = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
