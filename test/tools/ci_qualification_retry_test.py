#!/usr/bin/env python3

"""Unit tests for CI qualification performance retry behavior."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "tools" / "run-ci-qualification.sh"
)


class CiQualificationRetryTest(unittest.TestCase):
    def run_qualification(self, statuses):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        root = Path(temporary_directory.name)
        output = root / "output"
        runner = root / "fake-benchmark.py"
        state = root / "state"
        runner.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path
                import sys

                statuses = [int(value) for value in os.environ["FAKE_STATUSES"].split(",")]
                state_path = Path(os.environ["FAKE_STATE"])
                attempt = int(state_path.read_text() if state_path.exists() else "0")
                state_path.write_text(str(attempt + 1))
                output = Path(sys.argv[sys.argv.index("--output-directory") + 1])
                output.mkdir(parents=True, exist_ok=True)
                status = statuses[attempt]
                if status in (0, 1):
                    violations = ["p99 exceeded"] if status == 1 else []
                    (output / "qualification-benchmark.json").write_text(
                        json.dumps(
                            {
                                "attempt": attempt + 1,
                                "enforced": True,
                                "violations": violations,
                            }
                        )
                    )
                    (output / "qualification-benchmark.md").write_text(
                        f"# Attempt {attempt + 1}\\n"
                    )
                sys.exit(status)
                """
            ),
            encoding="utf-8",
        )
        runner.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_STATUSES": ",".join(str(status) for status in statuses),
                "FAKE_STATE": str(state),
                "QUALIFICATION_BENCHMARK_RUNNER": str(runner),
                "QUALIFICATION_OUTPUT_DIRECTORY": str(output),
            }
        )

        result = subprocess.run(
            ["bash", str(SCRIPT_PATH)],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )
        return result, output, int(state.read_text())

    def canonical_attempt(self, output):
        return json.loads(
            (output / "qualification-benchmark.json").read_text(encoding="utf-8")
        )["attempt"]

    def test_does_not_retry_a_passing_attempt(self):
        result, output, attempts = self.run_qualification([0])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(attempts, 1)
        self.assertEqual(self.canonical_attempt(output), 1)
        self.assertFalse((output / "attempt-2").exists())

    def test_retries_a_threshold_failure_and_accepts_a_pass(self):
        result, output, attempts = self.run_qualification([1, 0])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(attempts, 2)
        self.assertEqual(self.canonical_attempt(output), 2)
        self.assertTrue((output / "attempt-1/qualification-benchmark.json").is_file())
        self.assertTrue((output / "attempt-2/qualification-benchmark.json").is_file())

    def test_fails_after_two_threshold_failures(self):
        result, output, attempts = self.run_qualification([1, 1])

        self.assertEqual(result.returncode, 1)
        self.assertEqual(attempts, 2)
        self.assertEqual(self.canonical_attempt(output), 2)

    def test_does_not_retry_a_functional_error(self):
        result, output, attempts = self.run_qualification([2])

        self.assertEqual(result.returncode, 2)
        self.assertEqual(attempts, 1)
        self.assertFalse((output / "qualification-benchmark.json").exists())

    def test_second_attempt_functional_error_does_not_publish_stale_result(self):
        result, output, attempts = self.run_qualification([1, 2])

        self.assertEqual(result.returncode, 2)
        self.assertEqual(attempts, 2)
        self.assertFalse((output / "qualification-benchmark.json").exists())


if __name__ == "__main__":
    unittest.main()
