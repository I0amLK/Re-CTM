from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_package_checks", ROOT / "scripts/release_package_checks.py")
assert SPEC is not None and SPEC.loader is not None
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)


class OfflinePackageCheckTests(unittest.TestCase):
    def test_snapshot_excludes_generated_trees_and_python_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ("src/re_ctm/__init__.py", "src/re_ctm/__pycache__/a.pyc",
                             "src/re_ctm.egg-info/PKG-INFO", ".release-validation/private.json",
                             ".git/config", "dist/old.whl"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("example")
            self.assertEqual(set(CHECKS._source_files(root)), {"src/re_ctm/__init__.py"})

    def test_snapshot_rejects_source_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "outside").write_text("not package input")
            (root / "src/linked.py").symlink_to(root / "outside")
            with self.assertRaisesRegex(ValueError, "refuses a source symlink"):
                CHECKS._source_files(root)

    def test_snapshot_rejects_source_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").mkdir()
            (root / "outside/private.py").write_text("outside package")
            (root / "src").symlink_to(root / "outside", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "refuses a source symlink"):
                CHECKS._source_files(root)

    def test_output_inside_source_inputs_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "outside source-input"):
                CHECKS.run_package_checks(root, root / "src/generated")
            self.assertFalse((root / "src/generated").exists())

    def test_output_symlink_ancestor_is_rejected_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, outside = root / "repo", root / "outside"
            repo.mkdir()
            outside.mkdir()
            alias = root / "alias"
            alias.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                CHECKS.run_package_checks(repo, alias / "generated")
            self.assertFalse((outside / "generated").exists())

    def test_output_cannot_contain_source_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            with self.assertRaisesRegex(ValueError, "contain the source"):
                CHECKS.run_package_checks(repo, root)

    def test_existing_output_is_never_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            sentinel = output / "keep"
            sentinel.write_text("unchanged")
            with self.assertRaises(FileExistsError):
                CHECKS.run_package_checks(root, output)
            self.assertEqual(sentinel.read_text(), "unchanged")

    def test_failure_is_reported_with_isolated_offline_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, output = root / "repo", root / "output"
            repo.mkdir()
            (repo / "pyproject.toml").write_text("[project]\nname='example'\n")
            failed = subprocess.CompletedProcess(["builder"], 1, "fixture build failure")
            with patch.dict("os.environ", {"RE_CTM_OAUTH_PASSWORD": "do-not-copy",
                                          "CLOUD_TOKEN": "do-not-copy", "PYTHONPATH": "/foreign"}), patch.object(
                CHECKS.subprocess, "run", return_value=failed
            ) as run:
                report = CHECKS.run_package_checks(repo, output)
            self.assertFalse(report["passed"])
            self.assertEqual(report["checks"][0]["exit_code"], 1)
            self.assertTrue((output / "report.json").is_file())
            environment = run.call_args.kwargs["env"]
            self.assertEqual(environment["PIP_NO_INDEX"], "1")
            self.assertEqual(environment["PIP_CONFIG_FILE"], CHECKS.os.devnull)
            self.assertEqual(environment["HOME"], str(output / "home"))
            self.assertEqual(environment["TMPDIR"], str(output / "tmp"))
            for key in ("RE_CTM_OAUTH_PASSWORD", "CLOUD_TOKEN", "PYTHONPATH"):
                self.assertNotIn(key, environment)

    def test_sdist_allowlist_preserves_source_validation_inputs(self) -> None:
        manifest = (ROOT / "MANIFEST.in").read_text()
        for directory in ("src", "tests", "scripts", "docs"):
            self.assertIn("recursive-include " + directory + " ", manifest)
        for filename in ("engineering-graph.json", "manual-validation.json",
                         "code-optimization-graph.json", "project-progress.json"):
            self.assertIn(filename, manifest)
        for generated in (".release-validation", ".git", ".venv", "venv", "build", "dist"):
            self.assertIn("prune " + generated, manifest)


if __name__ == "__main__":
    unittest.main()
