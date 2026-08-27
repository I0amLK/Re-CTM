from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.native import BubblewrapExecBackend, ExternalHelperExecBackend


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


if __name__ == "__main__":
    unittest.main()
