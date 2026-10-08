#!/usr/bin/env python3
"""Exercise the actual Action runner and CLI against synthetic local release assets."""
import functools
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "action-version.txt").read_text().strip() if (ROOT / "action-version.txt").exists() else "0.1.0"
ARCHIVE = f"leakguard-v{VERSION}-x86_64-unknown-linux-gnu.tar.gz"
TOKEN = "ghp_" + "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp"

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass

class ActionIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.release = cls.root / f"v{VERSION}"
        cls.release.mkdir()
        binary = (ROOT / "target/release/leakguard").read_bytes()
        with tarfile.open(cls.release / ARCHIVE, "w:gz") as archive:
            info = tarfile.TarInfo("leakguard")
            info.size, info.mode = len(binary), 0o755
            archive.addfile(info, io.BytesIO(binary))
        cls.checksum = hashlib.sha256((cls.release / ARCHIVE).read_bytes()).hexdigest()
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(cls.root)))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()
    def setUp(self):
        (self.release / "SHA256SUMS").write_text(f"{self.checksum}  {ARCHIVE}\n")
        self.work = tempfile.TemporaryDirectory(dir=self.root)
        self.path = Path(self.work.name)
        self.addCleanup(self.work.cleanup)
    def run_action(self, **inputs):
        env = os.environ.copy()
        env.update({
            "GITHUB_ACTION_PATH": str(ROOT),
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "RUNNER_TEMP": str(self.path),
            "LEAKGUARD_RELEASE_BASE_URL": f"http://127.0.0.1:{self.server.server_port}",
            "INPUT_PATHS": "clean.txt", "INPUT_MODE": "tracked", "INPUT_BASE": "",
            "INPUT_FAIL_ON": "high", "INPUT_FORMAT": "json", "INPUT_OUTPUT": "",
            "INPUT_MAX_FILE_BYTES": "10485760",
            "INPUT_CONFIG": "",
        })
        env.update(inputs)
        (self.path / "clean.txt").write_text("safe\n")
        return subprocess.run(["bash", str(ROOT / "scripts/leakguard-action.sh")], cwd=self.path, env=env, capture_output=True, text=True)
    def test_clean_scan_and_checksum_download(self):
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["scanned_files"], 1)
    def test_finding_exit_and_redaction(self):
        (self.path / "secret.log").write_text("Authorization: Bearer " + TOKEN)
        result = self.run_action(INPUT_PATHS="secret.log", INPUT_FORMAT="annotations")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("::error", result.stdout)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
    def test_checksum_mismatch_is_exit_two(self):
        (self.release / "SHA256SUMS").write_text(f"{'0' * 64}  {ARCHIVE}\n")
        result = self.run_action()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("scanned_files", result.stdout)
    def test_paths_are_literals_and_reports_can_be_written(self):
        name = "$(touch INJECTED);artifact.txt"
        (self.path / name).write_text(TOKEN)
        result = self.run_action(INPUT_PATHS=f"clean.txt\n{name}", INPUT_OUTPUT="report.json")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.path / "INJECTED").exists())
        self.assertEqual(json.loads((self.path / "report.json").read_text())["scanned_files"], 2)
    def test_input_and_report_errors_propagate(self):
        for inputs in [dict(INPUT_PATHS="missing.txt"), dict(INPUT_OUTPUT="missing/report.json"), dict(INPUT_MODE="unknown"), dict(INPUT_MODE="history", INPUT_PATHS="clean.txt"), dict(INPUT_MODE="diff", INPUT_PATHS="", INPUT_BASE="")]:
            with self.subTest(inputs=inputs):
                self.assertEqual(self.run_action(**inputs).returncode, 2)
    def test_unsupported_runner_fails(self):
        self.assertEqual(self.run_action(RUNNER_OS="Windows").returncode, 2)
    def test_diff_mode_uses_merge_base_for_diverged_pr(self):
        def git(*args):
            subprocess.run(["git", *args], cwd=self.path, check=True, capture_output=True)
        git("init", "-q", "-b", "main")
        git("config", "user.name", "Smoke")
        git("config", "user.email", "smoke@example.invalid")
        (self.path / "existing.txt").write_text(TOKEN)
        git("add", ".")
        git("commit", "-qm", "base")
        git("checkout", "-qb", "pr")
        (self.path / "new.log").write_text("Authorization: Bearer " + TOKEN)
        git("add", ".")
        git("commit", "-qm", "PR addition")
        git("checkout", "-q", "main")
        (self.path / "existing.txt").write_text("removed upstream")
        git("add", ".")
        git("commit", "-qm", "upstream removal")
        git("checkout", "-q", "pr")
        result = self.run_action(INPUT_PATHS="", INPUT_MODE="diff", INPUT_BASE="main")
        self.assertEqual(result.returncode, 1, result.stderr)
        findings = json.loads(result.stdout)["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["path"], "new.log")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
    def test_config_input_and_default_discovery_suppress_fixtures(self):
        (self.path / "secret.log").write_text("Authorization: Bearer " + TOKEN)
        config = '[[allow]]\npaths = ["secret.log"]\nreason = "synthetic"\n'
        (self.path / "lg.toml").write_text(config)
        result = self.run_action(INPUT_PATHS="secret.log", INPUT_CONFIG="lg.toml")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["suppressed"][0]["suppression"]["reason"], "synthetic")
        (self.path / ".leakguard.toml").write_text(config)
        result = self.run_action(INPUT_PATHS="secret.log")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
    def test_invalid_config_is_exit_two(self):
        for value in ["missing.toml", "-leading-dash.toml"]:
            with self.subTest(config=value):
                self.assertEqual(self.run_action(INPUT_CONFIG=value).returncode, 2)
        (self.path / ".leakguard.toml").write_text('[[allow]]\npaths = ["clean.txt"]\n')
        self.assertEqual(self.run_action().returncode, 2)

if __name__ == "__main__":
    unittest.main(verbosity=2)
