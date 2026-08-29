from __future__ import annotations

import os
import json
import tempfile
import unittest
from pathlib import Path

from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.toolchains import (
    build_toolchain_exposure_plan,
    parse_native_exec_allow_roots,
    validate_explicit_toolchain_roots,
)


class ToolchainExposurePolicyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.data = self.root / "server-data"
        self.private = self.data / "private"
        self.workspace.mkdir()
        self.private.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_generic_path_discovery_and_explicit_roots_need_no_product_names(self) -> None:
        environment = self.root / "odd-location" / "science-stack"
        environment_bin = environment / "bin"
        environment_bin.mkdir(parents=True)
        (environment / "conda-meta").mkdir()
        (environment_bin / "symbolic-a").write_text("#!/bin/sh\n", encoding="utf-8")

        wrapper_bin = self.root / "unusual-home" / "custom-bin"
        wrapper_bin.mkdir(parents=True)
        product = self.root / "vendor" / "algebra-suite"
        product_exec = product / "Executables"
        product_exec.mkdir(parents=True)
        target = product_exec / "symbolic-b"
        target.write_text("#!/bin/sh\n", encoding="utf-8")
        target.chmod(0o755)
        (wrapper_bin / "symbolic-b").symlink_to(target)

        explicit = self.root / "shared" / "proof-tool"
        explicit_bin = explicit / "bin"
        explicit_bin.mkdir(parents=True)
        (explicit_bin / "symbolic-c").write_text("#!/bin/sh\n", encoding="utf-8")

        host_path = os.pathsep.join(
            (str(environment_bin), str(wrapper_bin), "/usr/bin", "/bin")
        )
        plan = build_toolchain_exposure_plan(
            mode=NativeMode.DANGEROUS,
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
            explicit_roots=(explicit,),
            host_path=host_path,
        )

        self.assertIn(environment.resolve(), plan.discovered_roots)
        self.assertIn(product.resolve(), plan.discovered_roots)
        self.assertIn(wrapper_bin.resolve(), plan.discovered_roots)
        self.assertTrue(all(root.is_relative_to(self.root) for root in plan.discovered_roots))
        self.assertEqual(plan.explicit_roots, (explicit.resolve(),))
        self.assertIn(explicit.resolve(), plan.read_only_roots)
        self.assertIn(str(explicit_bin.resolve()), plan.sandbox_path.split(os.pathsep))
        self.assertTrue(plan.host_path_inherited)
        self.assertEqual(plan.summary()["mount_mode"], "read_only")
        self.assertNotIn(str(explicit.resolve()), json.dumps(plan.summary()))

    def test_safe_mode_uses_only_explicit_toolchains_and_extends_path(self) -> None:
        explicit = self.root / "operator-declared" / "kernel"
        executable_directory = explicit / "Executables"
        executable_directory.mkdir(parents=True)
        plan = build_toolchain_exposure_plan(
            mode=NativeMode.SAFE,
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
            explicit_roots=(explicit,),
            host_path=str(self.root / "must-not-be-inherited"),
        )
        self.assertFalse(plan.auto_discovery_enabled)
        self.assertFalse(plan.host_path_inherited)
        self.assertEqual(plan.discovered_roots, ())
        path_entries = plan.sandbox_path.split(os.pathsep)
        self.assertIn(str(explicit.resolve()), path_entries)
        self.assertIn(str(executable_directory.resolve()), path_entries)
        self.assertNotIn(str(self.root / "must-not-be-inherited"), path_entries)

    def test_declared_roots_are_canonical_and_reject_every_trust_domain_overlap(self) -> None:
        valid = self.root / "toolchain"
        valid.mkdir()
        child = valid / "bin"
        child.mkdir()
        alias = self.root / "toolchain-alias"
        alias.symlink_to(valid, target_is_directory=True)
        parsed = parse_native_exec_allow_roots(
            os.pathsep.join((str(alias), str(valid), str(child)))
        )
        validated = validate_explicit_toolchain_roots(
            parsed,
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
        )
        self.assertEqual(validated, (valid.resolve(),))

        denied_roots = [
            Path("/"),
            Path.home(),
            self.workspace,
            self.workspace.parent,
            self.data,
            self.private,
            self.private.parent,
        ]
        denied_roots.extend(
            path for path in (Path("/home"), Path("/var"), Path("/opt")) if path.is_dir()
        )
        for denied in denied_roots:
            with self.subTest(denied=denied), self.assertRaises(ReCTMError) as error:
                validate_explicit_toolchain_roots(
                    (denied,),
                    workspace=self.workspace,
                    forbidden_paths=(self.data, self.private),
                )
            self.assertIn(
                error.exception.code,
                {"NATIVE_TOOLCHAIN_ROOT_DENIED", "INVALID_NATIVE_EXEC_ALLOW_ROOT"},
            )

    def test_invalid_explicit_configuration_fails_closed(self) -> None:
        with self.assertRaises(ReCTMError) as relative:
            parse_native_exec_allow_roots("relative/toolchain")
        self.assertEqual(relative.exception.code, "INVALID_NATIVE_EXEC_ALLOW_ROOT")

        missing = self.root / "missing"
        with self.assertRaises(ReCTMError) as absent:
            validate_explicit_toolchain_roots(
                (missing,),
                workspace=self.workspace,
                forbidden_paths=(self.data, self.private),
            )
        self.assertEqual(absent.exception.code, "INVALID_NATIVE_EXEC_ALLOW_ROOT")

    def test_path_symlink_into_private_state_is_silently_excluded(self) -> None:
        path_bin = self.root / "path-bin"
        path_bin.mkdir()
        secret_executable = self.private / "secret-kernel"
        secret_executable.write_text("secret\n", encoding="utf-8")
        (path_bin / "secret-kernel").symlink_to(secret_executable)
        plan = build_toolchain_exposure_plan(
            mode=NativeMode.DANGEROUS,
            workspace=self.workspace,
            forbidden_paths=(self.data, self.private),
            host_path=os.pathsep.join(
                (
                    str(path_bin),
                    str(self.private),
                    "relative/path",
                    str(self.root / "missing-path-entry"),
                )
            ),
        )
        self.assertIn(path_bin.resolve(), plan.discovered_roots)
        self.assertNotIn(self.private.resolve(), plan.read_only_roots)
        sandbox_entries = plan.sandbox_path.split(os.pathsep)
        self.assertIn(str(path_bin.resolve()), sandbox_entries)
        self.assertNotIn(str(self.private.resolve()), sandbox_entries)
        self.assertNotIn("relative/path", sandbox_entries)
        self.assertNotIn(str(self.root / "missing-path-entry"), sandbox_entries)
        self.assertFalse(
            any(self.private.resolve().is_relative_to(root) for root in plan.read_only_roots)
        )


if __name__ == "__main__":
    unittest.main()
