from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.debug import DebugEventBus
from re_ctm.native import (
    BubblewrapExecBackend,
    ExternalHelperExecBackend,
    NativeRuntime,
    NativeWorkspace,
    discover_dangerous_toolchain_roots,
)
from re_ctm.toolchains import build_toolchain_exposure_plan
from re_ctm.native_helper_bwrap import HelperError, _bubblewrap_command


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bwrap"), "bubblewrap required")
class BubblewrapNativeHelperTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.private = self.root / "private"
        self.data = self.root / "data"
        self.workspace.mkdir()
        self.private.mkdir()
        self.data.mkdir()
        (self.workspace / "hello.txt").write_text("workspace-ok\n", encoding="utf-8")
        (self.private / "canary.txt").write_text("PRIVATE-CANARY\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_attestation_and_dangerous_private_vault_denial(self) -> None:
        backend = BubblewrapExecBackend()
        attestation = backend.attest(
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
        )
        self.assertTrue(attestation["hard_isolation"])
        self.assertTrue(attestation["forbidden_paths_hidden"])
        self.assertFalse(attestation["private_vault_mounted"])
        self.assertTrue(attestation["network_isolated"])

        safe = backend.execute(
            workspace=self.workspace,
            argv=["/bin/cat", "hello.txt"],
            workdir=".",
            timeout_ms=10_000,
            mode=NativeMode.SAFE,
        )
        self.assertEqual(safe["exit_code"], 0)
        self.assertEqual(safe["stdout"], "workspace-ok\n")
        self.assertTrue(safe["attestation"]["network_isolated"])

        probe = (
            "import os,sys; "
            "print(os.path.exists(sys.argv[1])); "
            "print(os.environ.get('RE_CTM_TEST_PARENT_SECRET','missing'))"
        )
        os.environ["RE_CTM_TEST_PARENT_SECRET"] = "must-not-leak"
        try:
            dangerous = backend.execute(
                workspace=self.workspace,
                argv=[
                    "/usr/bin/python3",
                    "-c",
                    probe,
                    str(self.private / "canary.txt"),
                ],
                workdir=".",
                timeout_ms=10_000,
                mode=NativeMode.DANGEROUS,
            )
        finally:
            os.environ.pop("RE_CTM_TEST_PARENT_SECRET", None)
        self.assertEqual(dangerous["exit_code"], 0)
        self.assertEqual(dangerous["stdout"].splitlines(), ["False", "missing"])
        self.assertFalse(dangerous["attestation"]["private_vault_mounted"])

    def test_helper_response_nonce_is_enforced(self) -> None:
        fake = self.root / "fake_helper.py"
        fake.write_text(
            "import json,sys\n"
            "request=json.load(sys.stdin)\n"
            "json.dump({'protocol':'re-ctm-native-helper-v1','operation':request.get('operation'),"
            "'request_id':'wrong','ok':True,'attestation':{}},sys.stdout)\n",
            encoding="utf-8",
        )
        backend = ExternalHelperExecBackend(fake)
        with self.assertRaises(ReCTMError) as denied:
            backend.attest(workspace=self.workspace, forbidden_paths=(self.private,))
        self.assertEqual(denied.exception.code, "NATIVE_HELPER_PROTOCOL_ERROR")

    def test_bubblewrap_command_revalidates_protected_root_overlap(self) -> None:
        with self.assertRaises(HelperError) as denied:
            _bubblewrap_command(
                workspace=self.workspace,
                workdir=".",
                mode="dangerous",
                argv=["/bin/true"],
                extra_read_roots=(self.private,),
                forbidden_paths=(self.data, self.private),
            )
        self.assertEqual(denied.exception.code, "NATIVE_TOOLCHAIN_ROOT_DENIED")

    def test_runtime_refuses_unattested_bubblewrap_instance(self) -> None:
        debug = DebugEventBus(self.root / "unattested-events.jsonl", self.private, enabled=True)
        runtime = NativeRuntime(
            NativeWorkspace(self.workspace, private_root=self.private),
            NativeMode.DANGEROUS,
            debug,
            exec_backend=BubblewrapExecBackend(),
        )
        try:
            with self.assertRaises(ReCTMError) as denied:
                runtime.exec_command(cmd="true")
        finally:
            runtime.close()
        self.assertEqual(denied.exception.code, "NATIVE_ISOLATION_REQUIRED")

    def test_parent_requires_toolchain_attestation_fields(self) -> None:
        backend = BubblewrapExecBackend()

        def incomplete(request: dict[str, object], *, timeout_seconds: float) -> dict[str, object]:
            _ = timeout_seconds
            return {
                "protocol": "re-ctm-native-helper-v1",
                "operation": request["operation"],
                "request_id": request["request_id"],
                "ok": True,
                "attestation": {
                    "hard_isolation": True,
                    "workspace_mounted": True,
                    "forbidden_paths_hidden": True,
                    "private_vault_mounted": False,
                    "network_isolated": True,
                    "no_privilege_escalation": True,
                    "mount_namespace": True,
                    "user_namespace": True,
                    "pid_namespace": True,
                },
            }

        with mock.patch.object(backend, "_invoke", side_effect=incomplete):
            with self.assertRaises(ReCTMError) as denied:
                backend.attest(
                    workspace=self.workspace,
                    forbidden_paths=(self.data, self.private),
                )
        self.assertEqual(denied.exception.code, "NATIVE_HELPER_ATTESTATION_INVALID")

    def test_dangerous_runtime_mounts_user_path_toolchain_read_only(self) -> None:
        toolchain = self.root / "toolchain"
        bin_dir = toolchain / "bin"
        bin_dir.mkdir(parents=True)
        executable = bin_dir / "fake-cas"
        executable.write_text("#!/bin/sh\nprintf 'cas-ok\\n'\n", encoding="utf-8")
        executable.chmod(0o755)
        host_path = f"{bin_dir}:/usr/bin:/bin"
        roots = discover_dangerous_toolchain_roots(
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
            host_path=host_path,
        )
        self.assertIn(toolchain.resolve(), roots)

        backend = BubblewrapExecBackend(host_path=host_path, extra_read_roots=roots)
        backend.attest(
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
        )
        debug = DebugEventBus(self.root / "events.jsonl", self.private, enabled=True)
        runtime = NativeRuntime(
            NativeWorkspace(self.workspace, private_root=self.private),
            NativeMode.DANGEROUS,
            debug,
            exec_backend=backend,
        )
        try:
            result = runtime.exec_command(cmd="fake-cas", yield_time_ms=10_000)
            denied_write = runtime.exec_command(
                cmd=f"printf no > {toolchain / 'must-remain-read-only'}",
                yield_time_ms=10_000,
            )
        finally:
            runtime.close()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "cas-ok\n")
        self.assertNotEqual(denied_write["exit_code"], 0)
        self.assertFalse((toolchain / "must-remain-read-only").exists())

    def test_explicit_generic_toolchain_root_is_on_path_and_reported(self) -> None:
        product = self.root / "nonstandard" / "vendor-product"
        executables = product / "Executables"
        executables.mkdir(parents=True)
        executable = executables / "symbolic-kernel"
        executable.write_text("#!/bin/sh\nprintf 'generic-ok\\n'\n", encoding="utf-8")
        executable.chmod(0o755)
        plan = build_toolchain_exposure_plan(
            mode=NativeMode.SAFE,
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
            explicit_roots=(product,),
            host_path=str(self.root / "not-inherited"),
        )
        backend = BubblewrapExecBackend(exposure_plan=plan)
        attestation = backend.attest(
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
        )
        self.assertTrue(attestation["toolchain_roots_validated"])
        self.assertEqual(attestation["toolchain_read_only_root_count"], 1)
        synchronous = backend.execute(
            workspace=self.workspace,
            argv=["symbolic-kernel"],
            workdir=".",
            timeout_ms=10_000,
            mode=NativeMode.SAFE,
        )
        self.assertEqual(synchronous["exit_code"], 0)
        self.assertEqual(synchronous["stdout"], "generic-ok\n")
        debug = DebugEventBus(self.root / "explicit-events.jsonl", self.private, enabled=True)
        runtime = NativeRuntime(
            NativeWorkspace(self.workspace, private_root=self.private),
            NativeMode.SAFE,
            debug,
            exec_backend=backend,
        )
        try:
            result = runtime.exec_command(cmd="symbolic-kernel", yield_time_ms=10_000)
            environment = runtime.check_exec_environment()
        finally:
            runtime.close()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "generic-ok\n")
        exposure = environment["toolchain_exposure"]
        self.assertEqual(exposure["policy"], "system_plus_path_discovery_plus_explicit_roots")
        self.assertEqual(exposure["explicit_root_count"], 1)
        self.assertEqual(exposure["resolved_read_only_roots"], [str(product.resolve())])


if __name__ == "__main__":
    unittest.main()
