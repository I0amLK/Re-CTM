from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_target_checks", ROOT / "scripts/release_target_checks.py")
assert spec is not None and spec.loader is not None
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ReleaseTargetChecksTests(unittest.TestCase):
    def test_pending_manual_gate_prevents_release(self) -> None:
        report = {"gates": [
            {"name": "native_isolation", "status": "passed"},
            {"name": "real_browser_client", "status": "manual_pending"},
        ]}
        self.assertEqual(driver._finish(report), 2)
        self.assertTrue(report["machine_gates_passed"])
        self.assertFalse(report["release_ready"])

    def test_explicit_control_plane_omission_is_not_machine_pass(self) -> None:
        report = {"gates": [{"name": "native_isolation", "status": "manual_pending"}]}
        self.assertEqual(driver._finish(report), 2)
        self.assertFalse(report["machine_gates_passed"])
        self.assertFalse(report["release_ready"])

    def test_failed_and_blocked_gates_return_one(self) -> None:
        for state in ("failed", "blocked"):
            report = {"gates": [{"name": "native_isolation", "status": state}]}
            self.assertEqual(driver._finish(report), 1)
            self.assertFalse(report["release_ready"])

    def test_snapshot_excludes_private_state_and_preserves_original_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, copy = root / "source", root / "copy"
            source.mkdir()
            (source / "src").mkdir()
            (source / "src/example.py").write_text("VALUE = 1\n")
            (source / ".env").write_text("REAL_PASSWORD=never-copy")
            (source / "private").mkdir()
            (source / "private/state.sqlite3").write_bytes(b"private database")
            (source / "src/__pycache__").mkdir()
            (source / "src/__pycache__/example.pyc").write_bytes(b"cache")
            (source / "local-validation.json").write_text('{"historical": true}')
            before = driver._snapshot(source, copy)
            self.assertNotIn(".env", before)
            self.assertFalse((copy / "private").exists())
            self.assertFalse((copy / "src/__pycache__").exists())
            (copy / "local-validation.json").write_text('{"fresh": true}')
            self.assertEqual(driver._source_manifest(source), before)

    @unittest.skipUnless(hasattr(os, "symlink"), "Symlinks unavailable")
    def test_snapshot_rejects_symlinked_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "outside.py").write_text("secret")
            (root / "src/leak.py").symlink_to(root / "outside.py")
            with self.assertRaises(ValueError):
                driver._snapshot(root, root / "copy")

    def test_json_refuses_to_overwrite_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("keep")
            with self.assertRaises(FileExistsError):
                driver._json(path, {"replace": True})
            self.assertEqual(path.read_text(), "keep")

    def test_snapshot_rejects_source_destination_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                driver._snapshot(root, root / "nested")

    def test_environment_has_no_real_secrets_or_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.dict(os.environ, {
                "RE_CTM_OAUTH_PASSWORD": "real-secret", "RE_CTM_DATA_ROOT": "/production",
                "HTTPS_PROXY": "http://user:secret@proxy", "PIP_INDEX_URL": "https://private/",
            }):
                env = driver._environment(root, root)
            self.assertNotIn("RE_CTM_OAUTH_PASSWORD", env)
            self.assertNotIn("RE_CTM_DATA_ROOT", env)
            self.assertNotIn("HTTPS_PROXY", env)
            self.assertNotIn("PIP_INDEX_URL", env)
            self.assertEqual(env["PIP_NO_INDEX"], "1")
            self.assertEqual(env["HOME"], str(root / "home"))

    def test_command_records_full_separate_streams(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = driver._command(
                "fixture", [sys.executable, "-c", "import sys;print('out');print('err',file=sys.stderr)"],
                cwd=root, environment=driver._environment(root, root),
                evidence=root, timeout=10,
            )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(Path(result["stdout"]).read_text(), "out\n")
            self.assertEqual(Path(result["stderr"]).read_text(), "err\n")

    def test_timeout_is_failed_and_owned_process_is_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = driver._command(
                "timeout", [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=root, environment=driver._environment(root, root),
                evidence=root, timeout=0.1,
            )
            self.assertEqual(result["status"], "failed")
            self.assertIsNotNone(result["exit_code"])
            self.assertIn("exceeded", result["reason"])

    def test_strict_fixture_never_falls_back_after_isolation_failure(self) -> None:
        from re_ctm.enums import LatexPolicy
        from re_ctm.errors import ReCTMError
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "strict.json"
            with mock.patch("re_ctm.app.build_application", side_effect=ReCTMError(
                "NATIVE_ISOLATION_REQUIRED", "Fixture attestation denied", category="security",
            )) as build:
                self.assertEqual(driver._fixture(path, control_plane_only=False), 1)
            self.assertEqual(build.call_count, 1)
            settings = build.call_args.args[0]
            self.assertEqual(settings.native_exec_backend, "bubblewrap")
            self.assertIs(settings.latex_policy, LatexPolicy.REQUIRED)
            result = json.loads(path.read_text())
            self.assertFalse(result["passed"])
            self.assertEqual(result["error"]["code"], "NATIVE_ISOLATION_REQUIRED")
            self.assertNotIn("workflow", result)

    def test_control_plane_fixture_reports_static_only_without_browser_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            self.assertEqual(driver._fixture(path, control_plane_only=True), 0)
            result = json.loads(path.read_text())
            self.assertTrue(result["passed"])
            self.assertEqual(result["fixture"], "control_plane_only")
            self.assertFalse(result["real_browser_validated"])
            self.assertFalse(result["external_retrieval_validated"])
            self.assertEqual(result["workflow"]["transport"], "oauth_authenticated_mcp_http")
            self.assertEqual(result["workflow"]["tools_exercised"], [
                "rethlas_artifact", "rethlas_control", "rethlas_inspect", "rethlas_start", "rethlas_step",
            ])
            self.assertEqual(result["workflow"]["workflow_protocol"], 3)
            self.assertEqual(result["workflow"]["state_schema"], 8)
            self.assertEqual(result["workflow"]["latex"]["policy"], "static_only")
            self.assertFalse(result["workflow"]["latex"]["compile_attempted"])
            self.assertEqual(result["workflow"]["verified_fact_count"], 1)
            self.assertTrue(result["workflow"]["terminal_replay_unchanged"])


if __name__ == "__main__":
    unittest.main()
