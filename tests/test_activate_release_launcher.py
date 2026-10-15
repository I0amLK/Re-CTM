from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("activate_release_launcher", ROOT / "scripts/activate_release_launcher.py")
assert SPEC and SPEC.loader
ACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACT)


class ReleaseLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo with ' quote $ and 中文"
        self.home = self.root / "home with ' quote $ and 中文"
        (self.repo / ".local-install/workspace").mkdir(parents=True)
        self.bin = self.home / ".local/bin"
        self.bin.mkdir(parents=True)
        self.target = self.bin / "re-ctm"

    def test_launcher_preserves_exact_defaults_and_arguments(self) -> None:
        python = self.repo / ".local-install-0.4.1/venv/bin/python"
        python.parent.mkdir(parents=True)
        # This fake interpreter records argv/environment, without starting runtime.
        python.write_text("#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({'argv':sys.argv[1:],'env':dict(os.environ)}))\n")
        python.chmod(0o755)
        self.target.write_bytes(ACT.launcher_bytes(self.repo, self.home))
        self.target.chmod(0o755)
        env = dict(os.environ, RE_CTM_DATA_ROOT="/old/state", RE_CTM_OAUTH_PASSWORD="secret",
                   PYTHONPATH="/old/code", RE_CTM_HOST="0.0.0.0", CLOUD_TOKEN="secret")
        result = subprocess.run([str(self.target), "tui", "--quick-tunnel", "--native-mode", "dangerous",
                                 "--workspace", "path with spaces"], env=env,
                                capture_output=True, text=True, check=True)
        captured = json.loads(result.stdout)
        self.assertEqual(captured["argv"], ["-I", "-B", "-m", "re_ctm", "tui", "--quick-tunnel",
                                          "--native-mode", "dangerous", "--workspace", "path with spaces"])
        values = captured["env"]
        self.assertEqual(values["RE_CTM_WORKSPACE"], str(self.repo / ".local-install/workspace"))
        self.assertEqual(values["RE_CTM_DATA_ROOT"], str(self.home / ".re-ctm-0.4-local"))
        self.assertEqual(values["RE_CTM_PRIVATE_ROOT"], str(self.home / ".re-ctm-0.4-local/private"))
        self.assertEqual(values["RE_CTM_NATIVE_EXEC_BACKEND"], "bubblewrap")
        self.assertEqual(values["RE_CTM_LATEX_POLICY"], "required")
        self.assertEqual(values["RE_CTM_HOST"], "127.0.0.1")
        self.assertEqual(values["RE_CTM_PORT"], "0")
        self.assertEqual(values["HOME"], str(self.home))
        for name in ("RE_CTM_OAUTH_PASSWORD", "PYTHONPATH", "CLOUD_TOKEN"):
            self.assertNotIn(name, values)

    def test_atomic_replace_and_regular_backup_rollback(self) -> None:
        self.target.write_bytes(b"old launcher")
        self.target.chmod(0o751)
        evidence = self.root / "evidence"
        receipt = ACT.publish_launcher(self.target, b"new launcher", evidence)
        self.assertEqual(self.target.read_bytes(), b"new launcher")
        self.assertEqual(Path(receipt["backup"]).read_bytes(), b"old launcher")
        ACT.rollback(evidence / "activation.json")
        self.assertEqual(self.target.read_bytes(), b"old launcher")
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o751)

    def test_symlink_backup_does_not_change_its_destination(self) -> None:
        old = self.root / "old-install"
        old.write_text("old")
        self.target.symlink_to(old)
        evidence = self.root / "evidence"
        receipt = ACT.publish_launcher(self.target, b"new", evidence)
        self.assertEqual(old.read_text(), "old")
        self.assertTrue(Path(receipt["backup"]).is_symlink())
        ACT.rollback(evidence / "activation.json")
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(self.target.read_text(), "old")

    def test_dangling_symlink_is_preserved(self) -> None:
        self.target.symlink_to(self.root / "missing")
        evidence = self.root / "evidence"
        ACT.publish_launcher(self.target, b"new", evidence)
        ACT.rollback(evidence / "activation.json")
        self.assertTrue(self.target.is_symlink())

    def test_first_install_rollback_removes_only_new_launcher(self) -> None:
        evidence = self.root / "evidence"
        ACT.publish_launcher(self.target, b"new", evidence)
        ACT.rollback(evidence / "activation.json")
        self.assertFalse(self.target.exists())

    def test_rollback_refuses_changed_launcher(self) -> None:
        self.target.write_text("old")
        evidence = self.root / "evidence"
        receipt = ACT.publish_launcher(self.target, b"new", evidence)
        self.target.write_text("newer")
        with self.assertRaisesRegex(ValueError, "changed"):
            ACT.rollback(evidence / "activation.json")
        self.assertEqual(self.target.read_text(), "newer")
        self.assertEqual(Path(receipt["backup"]).read_text(), "old")

    def test_replace_failure_keeps_old_launcher_and_backup(self) -> None:
        self.target.write_text("old")
        evidence = self.root / "evidence"
        original = ACT.os.replace
        def fail_launcher(source, destination):
            if Path(destination) == self.target:
                raise OSError("failure")
            return original(source, destination)
        with patch.object(ACT.os, "replace", side_effect=fail_launcher):
            with self.assertRaises(OSError):
                ACT.publish_launcher(self.target, b"new", evidence)
        self.assertEqual(self.target.read_text(), "old")
        receipt = json.loads((evidence / "activation.json").read_text())
        self.assertEqual(receipt["status"], "prepared")
        self.assertEqual(Path(receipt["backup"]).read_text(), "old")
        self.assertEqual([p for p in self.bin.glob(".re-ctm-*") if p.name != ".re-ctm-activation.lock"], [])

    def test_rejects_directory_launcher(self) -> None:
        self.target.mkdir()
        with self.assertRaisesRegex(ValueError, "regular file"):
            ACT.publish_launcher(self.target, b"new", self.root / "evidence")

    def test_rejects_symlink_launcher_directory(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.bin)
        with self.assertRaisesRegex(ValueError, "symlink"):
            ACT.publish_launcher(alias / "re-ctm", b"new", self.root / "evidence")

    def test_rejects_missing_workspace(self) -> None:
        with self.assertRaisesRegex(ValueError, "workspace"):
            ACT.launcher_bytes(self.root / "missing", self.home)

    def test_rejects_wrong_wheel_before_interpreter_execution(self) -> None:
        installation = self.repo / ".local-install-0.4.1"
        installation.mkdir()
        (installation / "re_ctm-0.4.1-py3-none-any.whl").write_bytes(b"wrong")
        with patch.object(ACT.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "digest"):
                ACT.verify_install(self.repo, self.home)
            run.assert_not_called()

    def test_path_requires_target_directory_even_if_command_missing(self) -> None:
        with patch.dict(os.environ, {"PATH": "/usr/bin"}), patch.object(ACT.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "not on PATH"):
                ACT.check_path_target(self.target)

    def test_path_rejects_shadowing_and_accepts_missing_first_install(self) -> None:
        with patch.dict(os.environ, {"PATH": str(self.bin) + ":/usr/bin"}):
            with patch.object(ACT.shutil, "which", return_value="/usr/bin/re-ctm"):
                with self.assertRaisesRegex(ValueError, "shadows"):
                    ACT.check_path_target(self.target)
            with patch.object(ACT.shutil, "which", return_value=None):
                ACT.check_path_target(self.target)

    def test_atomic_receipt_failure_preserves_previous_json(self) -> None:
        receipt = self.root / "receipt.json"
        ACT.write_receipt(receipt, {"status": "prepared"})
        with patch.object(ACT.os, "replace", side_effect=OSError("failure")):
            with self.assertRaises(OSError):
                ACT.write_receipt(receipt, {"status": "activated_verified"})
        self.assertEqual(json.loads(receipt.read_text()), {"status": "prepared"})
        self.assertEqual(list(self.root.glob(".receipt-*")), [])

    def _main_patches(self, stack):
        installation = self.repo / ".local-install-0.4.1"
        installation.mkdir()
        (installation / "install-report.json").write_text(json.dumps({"installation_root": str(installation)}))
        stack.enter_context(patch.object(ACT, "__file__", str(self.repo / "scripts/activate_release_launcher.py")))
        stack.enter_context(patch.object(ACT.Path, "home", return_value=self.home))
        stack.enter_context(patch.object(ACT, "verify_install", return_value={"version": "0.4.1", "runtime_files": 55}))
        stack.enter_context(patch.object(ACT, "check_path_target"))
        stack.enter_context(patch.object(ACT, "smoke_launcher", return_value={"passed": True}))
        stack.enter_context(patch.object(ACT.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "re-ctm 0.4.1\n", "")))
        stack.enter_context(patch("sys.argv", ["activate_release_launcher.py", "--activate"]))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def test_main_persists_verified_evidence(self) -> None:
        self.target.write_text("old")
        with contextlib.ExitStack() as stack:
            self._main_patches(stack)
            self.assertEqual(ACT.main(), 0)
        receipt = next((self.repo / ".release-validation").glob("launcher-*/activation.json"))
        data = json.loads(receipt.read_text())
        self.assertEqual(data["status"], "activated_verified")
        self.assertEqual(data["version_output"], "re-ctm 0.4.1")
        self.assertTrue(data["smoke"]["passed"])
        self.assertEqual(data["verified"]["runtime_files"], 55)

    def test_final_receipt_failure_rolls_back_launcher(self) -> None:
        self.target.write_text("old")
        original = ACT.write_receipt
        def fail_verified(path, receipt):
            if receipt["status"] == "activated_verified":
                raise OSError("failure")
            return original(path, receipt)
        with contextlib.ExitStack() as stack:
            self._main_patches(stack)
            stack.enter_context(patch.object(ACT, "write_receipt", side_effect=fail_verified))
            with self.assertRaises(OSError):
                ACT.main()
        self.assertEqual(self.target.read_text(), "old")
        receipt = next((self.repo / ".release-validation").glob("launcher-*/activation.json"))
        self.assertEqual(json.loads(receipt.read_text())["status"], "rolled_back")

    def test_smoke_template_starts_and_stops_only_fixture_server(self) -> None:
        python = self.repo / ".local-install-0.4.1/venv/bin/python"
        python.parent.mkdir(parents=True)
        python.write_text("""#!/usr/bin/python3
import http.server,json,sys
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=json.dumps({'issuer':origin}).encode()
  self.send_response(200);self.end_headers();self.wfile.write(body)
 def log_message(self,*args): pass
server=http.server.HTTPServer(('127.0.0.1',0),H)
origin='http://127.0.0.1:'+str(server.server_port)
print('MCP URL        '+origin+'/mcp',file=sys.stderr,flush=True)
print('OAuth key fixture-secret-never-report',file=sys.stderr,flush=True)
try: server.serve_forever()
except KeyboardInterrupt: sys.exit(130)
finally: server.server_close()
""")
        python.chmod(0o755)
        report = ACT.smoke_launcher(self.repo)
        self.assertTrue(report["passed"])
        self.assertEqual(report["owned_shutdown_exit_code"], 130)
        self.assertNotIn("fixture-secret", json.dumps(report))


    def test_smoke_uses_actual_cli_terminal_discovery_and_interrupt_contract(self) -> None:
        import re_ctm
        python = self.repo / ".local-install-0.4.1/venv/bin/python"
        python.parent.mkdir(parents=True)
        package_root = str(Path(re_ctm.__file__).resolve().parent.parent)
        python.write_text(
            "#!" + sys.executable + "\n"
            "import sys\n"
            "sys.path.insert(0, " + repr(package_root) + ")\n"
            "from unittest.mock import patch\n"
            "from re_ctm.cli import main\n"
            # No Native command is run. Only the unavailable nested physical
            # attestation is mocked; actual CLI/config/OAuth/TUI/shutdown run.
            "with patch('re_ctm.app.BubblewrapExecBackend.attest', return_value={}):\n"
            "    raise SystemExit(main(sys.argv[5:]))\n")
        python.chmod(0o755)
        report = ACT.smoke_launcher(self.repo)
        self.assertTrue(report["loopback_oauth_discovery"])
        self.assertEqual(report["owned_shutdown_exit_code"], 130)



if __name__ == "__main__":
    unittest.main()
