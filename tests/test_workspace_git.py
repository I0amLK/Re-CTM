from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_ctm import ctm_compat
from re_ctm.debug import DebugEventBus
from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.tools import validate_tool_arguments


@unittest.skipUnless(shutil.which("git"), "Git is required for repository fixtures")
class WorkspaceGitTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "workspace"
        self.private = self.base / "private"
        self.private.mkdir()
        self.init(self.root, "parent-fixture")
        self.nested = self.root / "nested"
        self.init(self.nested, "child-fixture")
        self.workspace = NativeWorkspace(self.root, private_root=self.private)

    def git(self, root: Path, *arguments: str) -> str:
        env = {
            "PATH": os.defpath,
            "HOME": str(self.base),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_NAME": "Re-CTM fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Re-CTM fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        completed = subprocess.run(
            ["git", "--literal-pathspecs", "-C", str(root), "-c", "core.hooksPath=/dev/null", *arguments],
            capture_output=True, text=True, check=True, env=env,
        )
        return completed.stdout

    def init(self, root: Path, label: str) -> None:
        root.mkdir(parents=True)
        self.git(root, "init", "--quiet")
        (root / "a.txt").write_text(f"{label}\nsecond\n", encoding="utf-8")
        self.commit(root, "a.txt", message=label)

    def commit(self, root: Path, *paths: str, message: str = "fixture update") -> None:
        self.git(root, "add", "--", *paths)
        self.git(root, "commit", "--quiet", "-m", message)

    def call(self, tool: str, **args: object) -> dict:
        return getattr(ctm_compat, tool)(self.workspace, args)

    def test_all_tools_select_nested_repository(self) -> None:
        (self.nested / "a.txt").write_text("changed-child\nsecond\n", encoding="utf-8")
        (self.root / "a.txt").write_text("changed-parent\nsecond\n", encoding="utf-8")
        for tool, args in [
            ("git_status", {}),
            ("git_diff", {"path": "a.txt"}),
            ("git_log", {"path": "a.txt"}),
            ("git_show", {"path": "a.txt"}),
            ("git_blame", {"path": "a.txt", "rev": "HEAD"}),
        ]:
            with self.subTest(tool=tool):
                result = self.call(tool, repo_path="nested", **args)
                self.assertEqual(result["repo_path"], "nested")
                self.assertNotIn("parent-fixture", str(result))
                self.assertNotIn("changed-parent", str(result))
        self.assertIn("changed-child", self.call("git_diff", repo_path="nested", path="a.txt")["diff"])
        self.assertEqual(self.call("git_log", path="a.txt")["commits"][0]["subject"], "parent-fixture")

    def test_status_legacy_directory_selector_and_explicit_precedence(self) -> None:
        (self.nested / "new.txt").write_text("new", encoding="utf-8")
        result = self.call("git_status", path="nested")
        self.assertEqual(result["repo_path"], "nested")
        self.assertEqual(result["entries"][0]["path"], "new.txt")
        explicit = self.call("git_status", repo_path="nested", path="../ignored-legacy-selector")
        self.assertEqual(explicit["repo_path"], "nested")
        self.assertEqual(explicit["entries"], result["entries"])

    def test_discovery_stops_at_workspace_boundary_for_every_tool(self) -> None:
        empty = self.root / "empty-workspace"
        empty.mkdir()
        self.workspace = NativeWorkspace(empty, private_root=self.private)
        for tool, args in [
            ("git_status", {}), ("git_diff", {}), ("git_log", {}),
            ("git_show", {}), ("git_blame", {"path": "a.txt"}),
        ]:
            with self.subTest(tool=tool):
                result = self.call(tool, **args)
                if tool == "git_diff":
                    self.assertEqual(result["diff"], "")
                    self.assertEqual(result["warnings"], ["not a git repository"])
                else:
                    self.assertFalse(result["is_repo"])

    def test_directory_inside_repository_discovers_bounded_parent(self) -> None:
        (self.nested / "subdir").mkdir()
        result = self.call("git_log", repo_path="nested/subdir", path="a.txt")
        self.assertEqual(result["repo_path"], "nested")
        self.assertEqual(result["commits"][0]["subject"], "child-fixture")

    def test_file_repository_selectors_are_rejected(self) -> None:
        for tool in ["git_status", "git_diff", "git_log", "git_show", "git_blame"]:
            with self.subTest(tool=tool), self.assertRaises(ReCTMError) as error:
                self.call(tool, repo_path="nested/a.txt", path="a.txt")
            self.assertEqual(error.exception.code, "NOT_A_DIRECTORY")

    def test_status_preserves_utf8_newline_and_arrow_filename(self) -> None:
        name = "中文 -> actual\nfile.txt"
        (self.nested / name).write_text("data", encoding="utf-8")
        result = self.call("git_status", repo_path="nested", max_entries=1)
        self.assertEqual(result["entries"][0]["path"], name)
        self.assertIsNone(result["entries"][0]["original_path"])
        self.assertFalse(result["truncated"])
        (self.nested / "second-untracked").write_text("data", encoding="utf-8")
        self.assertTrue(self.call("git_status", repo_path="nested", max_entries=1)["truncated"])
        self.assertFalse(self.call("git_status", repo_path="nested", include_untracked=False)["entries"])

    def test_status_rename_has_exact_source_and_destination(self) -> None:
        original = "old -> 中文\nname.txt"
        renamed = "new -> 中文\nname.txt"
        (self.nested / original).write_text("rename-content\n", encoding="utf-8")
        self.commit(self.nested, original)
        self.git(self.nested, "mv", "--", original, renamed)
        result = self.call("git_status", repo_path="nested", max_entries=1)
        self.assertEqual(result["entries"], [{
            "path": renamed, "original_path": original, "index_status": "R", "worktree_status": " ",
        }])
        self.assertFalse(result["truncated"])

    def test_literal_filters_do_not_expand_globs(self) -> None:
        literal = "*.txt"
        (self.nested / literal).write_text("literal-before\n", encoding="utf-8")
        self.commit(self.nested, literal, message="literal-name")
        (self.nested / literal).write_text("literal-after\n", encoding="utf-8")
        (self.nested / "a.txt").write_text("sibling-not-selected\n", encoding="utf-8")
        diff = self.call("git_diff", repo_path="nested", paths=[literal])["diff"]
        self.assertIn("literal-after", diff)
        self.assertNotIn("sibling-not-selected", diff)
        log = self.call("git_log", repo_path="nested", paths=[literal])
        self.assertEqual([commit["subject"] for commit in log["commits"]], ["literal-name"])
        shown = self.call("git_show", repo_path="nested", path=literal)["content"]
        self.assertIn("literal-before", shown)
        self.assertNotIn("child-fixture", shown)

    def test_missing_historical_files_and_ancestors_remain_valid_filters(self) -> None:
        directory = self.nested / "removed"
        directory.mkdir()
        (directory / "historical.txt").write_text("historical\nsecond\n", encoding="utf-8")
        self.commit(self.nested, "removed/historical.txt", message="add historic file")
        self.git(self.nested, "rm", "--quiet", "removed/historical.txt")
        self.git(self.nested, "commit", "--quiet", "-m", "delete historic file")
        self.assertFalse(directory.exists())
        result = self.call("git_log", repo_path="nested", path="removed/historical.txt")
        self.assertEqual([c["subject"] for c in result["commits"]], ["delete historic file", "add historic file"])
        blame = self.call("git_blame", repo_path="nested", path="removed/historical.txt", rev="HEAD~1")
        self.assertEqual([line["content"] for line in blame["lines"]], ["historical", "second"])
        shown = self.call("git_show", repo_path="nested", path="removed/historical.txt", rev="HEAD~1")
        self.assertIn("historical", shown["content"])
        self.assertEqual(self.call("git_diff", repo_path="nested", path="removed/historical.txt")["diff"], "")

    def test_log_limit_is_true_only_when_an_extra_commit_exists(self) -> None:
        self.assertFalse(self.call("git_log", repo_path="nested", max_count=1)["truncated"])
        (self.nested / "a.txt").write_text("updated\n", encoding="utf-8")
        self.commit(self.nested, "a.txt")
        result = self.call("git_log", repo_path="nested", max_count=1)
        self.assertEqual(len(result["commits"]), 1)
        self.assertTrue(result["truncated"])
        self.assertFalse(self.call("git_log", repo_path="nested", max_count=1, skip=1)["truncated"])

    def test_blame_clamps_source_and_keeps_continuation_scope(self) -> None:
        (self.nested / "subdir").mkdir()
        first = self.call(
            "git_blame", repo_path="nested/subdir", path="a.txt", rev="HEAD", max_lines=1, end_line=500,
        )
        self.assertEqual(first["lines"][0]["content"], "child-fixture")
        self.assertTrue(first["truncated"])
        next_args = first["next_action"]["arguments"]
        validate_tool_arguments("git_blame", next_args)
        self.assertEqual(next_args, {
            "repo_path": "nested", "path": "a.txt", "rev": "HEAD", "max_lines": 1,
            "start_line": 2, "end_line": 2,
        })
        second = self.call("git_blame", **next_args)
        self.assertEqual(second["lines"][0]["content"], "second")
        self.assertFalse(second["truncated"])
        self.assertNotIn("next_action", second)
        for args in [{}, {"end_line": 1000}, {"rev": "HEAD"}, {"rev": "HEAD", "max_lines": 2}]:
            with self.subTest(args=args):
                full = self.call("git_blame", repo_path="nested", path="a.txt", **args)
                self.assertEqual(len(full["lines"]), 2)
                self.assertEqual(full["end_line"], 2)
                self.assertFalse(full["truncated"])
        past = self.call("git_blame", repo_path="nested", path="a.txt", start_line=3)
        self.assertEqual(past["lines"], [])
        self.assertFalse(past["truncated"])

    def test_blame_uses_selected_revision_source_and_handles_empty_file(self) -> None:
        (self.nested / "a.txt").write_text("now-one-line\n", encoding="utf-8")
        self.assertEqual(len(self.call("git_blame", repo_path="nested", path="a.txt")["lines"]), 1)
        self.assertEqual(len(self.call("git_blame", repo_path="nested", path="a.txt", rev="HEAD")["lines"]), 2)
        (self.nested / "empty.txt").write_bytes(b"")
        self.commit(self.nested, "empty.txt")
        for args in [{}, {"rev": "HEAD"}]:
            result = self.call("git_blame", repo_path="nested", path="empty.txt", **args)
            self.assertEqual(result["lines"], [])
            self.assertFalse(result["truncated"])

    def test_blame_treats_unicode_separators_and_cr_as_content(self) -> None:
        content = "left\u2028right\vtext\r\nsecond"
        (self.nested / "a.txt").write_bytes(content.encode("utf-8"))
        self.commit(self.nested, "a.txt")
        for args in [{}, {"rev": "HEAD"}]:
            result = self.call("git_blame", repo_path="nested", path="a.txt", **args)
            self.assertEqual([line["content"] for line in result["lines"]], ["left\u2028right\vtext\r", "second"])

    def test_filters_and_selectors_reject_workspace_and_repository_escapes(self) -> None:
        (self.root / "outside-child").mkdir()
        (self.nested / "alias").symlink_to(self.root / "outside-child", target_is_directory=True)
        (self.nested / "private-alias").symlink_to(self.private, target_is_directory=True)
        requests = [
            {"repo_path": "../escape"}, {"path": "../escape"}, {"path": "/etc/passwd"},
            {"repo_path": "nested", "path": "alias/missing/file"},
            {"repo_path": "nested", "path": "private-alias/missing/file"},
        ]
        for request in requests:
            with self.subTest(request=request), self.assertRaises(ReCTMError):
                self.call("git_diff", **request)

    def test_gitdir_and_common_dir_must_stay_inside_workspace(self) -> None:
        outside = self.base / "outside-repo"
        self.init(outside, "external-fixture")
        for mode in ["pointer", "symlink", "common-pointer", "common-symlink"]:
            with self.subTest(mode=mode):
                selected = self.root / mode
                selected.mkdir()
                if mode == "pointer":
                    (selected / ".git").write_text(f"gitdir: {outside / '.git'}\n", encoding="utf-8")
                elif mode == "symlink":
                    (selected / ".git").symlink_to(outside / ".git", target_is_directory=True)
                else:
                    metadata = selected / ".git"
                    metadata.mkdir()
                    if mode == "common-pointer":
                        (metadata / "commondir").write_text(str(outside / ".git"), encoding="utf-8")
                    else:
                        (outside / "pointer").write_text(str(outside / ".git"), encoding="utf-8")
                        (metadata / "commondir").symlink_to(outside / "pointer")
                with self.assertRaises(ReCTMError):
                    self.call("git_status", repo_path=mode)

    def test_git_metadata_pointer_is_bounded_regular_utf8(self) -> None:
        for mode in ["oversized", "invalid-utf8", "invalid-pointer", "fifo"]:
            selected = self.root / mode
            selected.mkdir()
            marker = selected / ".git"
            if mode == "oversized":
                marker.write_bytes(b"gitdir: " + b"a" * 4096)
            elif mode == "invalid-utf8":
                marker.write_bytes(b"gitdir: \xff")
            elif mode == "invalid-pointer":
                marker.write_bytes(b"wrong pointer")
            else:
                os.mkfifo(marker)
            with self.subTest(mode=mode), self.assertRaises(ReCTMError):
                self.call("git_log", repo_path=mode)

    def test_in_workspace_linked_worktree_is_supported(self) -> None:
        self.git(self.root, "worktree", "add", "--quiet", "--detach", "linked", "HEAD")
        for tool, args in [
            ("git_status", {}), ("git_log", {}), ("git_show", {}),
            ("git_diff", {"path": "a.txt"}), ("git_blame", {"path": "a.txt"}),
        ]:
            with self.subTest(tool=tool):
                result = self.call(tool, repo_path="linked", **args)
                self.assertEqual(result["repo_path"], "linked")

    def test_external_helpers_are_disabled(self) -> None:
        marker = self.root / "helper-ran"
        helper = self.nested / "unsafe-helper"
        helper.write_text(f"#!/bin/sh\nprintf ran > '{marker}'\nexit 0\n", encoding="utf-8")
        helper.chmod(0o755)
        (self.nested / ".gitattributes").write_text("a.txt diff=unsafe\n", encoding="utf-8")
        self.git(self.nested, "config", "core.fsmonitor", str(helper))
        self.git(self.nested, "config", "core.hooksPath", str(self.nested))
        self.git(self.nested, "config", "diff.external", str(helper))
        self.git(self.nested, "config", "diff.unsafe.command", str(helper))
        self.git(self.nested, "config", "diff.unsafe.textconv", str(helper))
        (self.nested / "a.txt").write_text("changed\nsecond\n", encoding="utf-8")
        for tool, args in [
            ("git_status", {}), ("git_diff", {"path": "a.txt"}), ("git_log", {"path": "a.txt"}),
            ("git_show", {"path": "a.txt"}), ("git_blame", {"path": "a.txt", "rev": "HEAD"}),
        ]:
            with self.subTest(tool=tool):
                self.call(tool, repo_path="nested", **args)
                self.assertFalse(marker.exists())
        command = ctm_compat._select_repository(self.workspace, {"repo_path": "nested"}).command("status")
        self.assertIn("core.hooksPath=/dev/null", command)
        self.assertIn("core.fsmonitor=false", command)
        self.assertIn("--no-optional-locks", command)

    def filter_helper(self) -> tuple[Path, Path]:
        marker = self.base / "external-filter-ran"
        helper = self.base / "external-filter-helper"
        helper.write_text(f"#!/bin/sh\nprintf ran > '{marker}'\nexit 1\n", encoding="utf-8")
        helper.chmod(0o755)
        (self.nested / ".gitattributes").write_text("a.txt filter=fixture-secret-driver\n", encoding="utf-8")
        (self.nested / "a.txt").write_text("changed-with-filter\n", encoding="utf-8")
        return helper, marker

    def test_external_filters_are_denied_for_every_tool_and_native_mode(self) -> None:
        helper, marker = self.filter_helper()
        debug = DebugEventBus(self.base / "debug.jsonl", self.private, enabled=False)
        for mode in NativeMode:
            runtime = NativeRuntime(self.workspace, mode, debug)
            self.addCleanup(runtime.close)
            for kind in ["clean", "smudge", "process"]:
                key = f"filter.fixture-secret-driver.{kind}"
                self.git(self.nested, "config", key, str(helper))
                for tool, args in [
                    ("git_status", {}), ("git_diff", {"path": "a.txt"}), ("git_log", {"path": "a.txt"}),
                    ("git_show", {"path": "a.txt"}), ("git_blame", {"path": "a.txt"}),
                ]:
                    with self.subTest(mode=mode, kind=kind, tool=tool), self.assertRaises(ReCTMError) as error:
                        getattr(runtime, tool)(repo_path="nested", **args)
                    self.assertEqual(error.exception.code, "GIT_FILTER_DENIED")
                    self.assertEqual(error.exception.category, "security")
                    self.assertNotIn("fixture-secret-driver", str(error.exception.to_payload()))
                    self.assertNotIn(str(helper), str(error.exception.to_payload()))
                    self.assertFalse(marker.exists())
                self.git(self.nested, "config", "--unset-all", key)

    def test_filters_in_includes_and_conditional_includes_are_denied(self) -> None:
        helper, marker = self.filter_helper()
        included = self.nested / ".git" / "included-filter.conf"
        included.write_text(f'[filter "fixture-secret-driver"]\n clean = {helper}\n', encoding="utf-8")
        for key in ["include.path", f"includeIf.gitdir:{self.nested / '.git'}.path"]:
            self.git(self.nested, "config", key, str(included))
            with self.subTest(key=key), self.assertRaises(ReCTMError) as error:
                self.call("git_diff", repo_path="nested", path="a.txt")
            self.assertEqual(error.exception.code, "GIT_FILTER_DENIED")
            self.assertFalse(marker.exists())
            self.git(self.nested, "config", "--unset-all", key)

    def test_filter_in_linked_worktree_config_is_denied(self) -> None:
        helper, marker = self.filter_helper()
        self.git(self.root, "worktree", "add", "--quiet", "--detach", "linked-filter", "HEAD")
        self.git(self.root, "config", "extensions.worktreeConfig", "true")
        linked = self.root / "linked-filter"
        self.git(linked, "config", "--worktree", "filter.fixture-secret-driver.process", str(helper))
        (linked / ".gitattributes").write_text("a.txt filter=fixture-secret-driver\n", encoding="utf-8")
        (linked / "a.txt").write_text("changed-with-filter\n", encoding="utf-8")
        with self.assertRaises(ReCTMError) as error:
            self.call("git_status", repo_path="linked-filter")
        self.assertEqual(error.exception.code, "GIT_FILTER_DENIED")
        self.assertFalse(marker.exists())

    def test_filter_gate_handles_key_case_punctuation_duplicates_and_empty_values(self) -> None:
        helper, marker = self.filter_helper()
        key = "Filter.fixture-secret-driver.with=equals.Clean"
        self.git(self.nested, "config", "--add", key, str(helper))
        self.git(self.nested, "config", "--add", key, "")
        with self.assertRaises(ReCTMError) as error:
            self.call("git_status", repo_path="nested")
        self.assertEqual(error.exception.code, "GIT_FILTER_DENIED")
        self.assertFalse(marker.exists())
        self.git(self.nested, "config", "--unset-all", key)
        self.git(self.nested, "config", "filter.unused.process", "")
        with self.assertRaises(ReCTMError) as error:
            self.call("git_log", repo_path="nested")
        self.assertEqual(error.exception.code, "GIT_FILTER_DENIED")
        self.assertFalse(marker.exists())

    def test_required_only_filter_config_is_allowed(self) -> None:
        self.git(self.nested, "config", "filter.harmless.required", "true")
        result = self.call("git_log", repo_path="nested")
        self.assertEqual(result["commits"][0]["subject"], "child-fixture")

    def test_config_inspection_failure_does_not_expose_stderr(self) -> None:
        secret = "filter-secret-value-must-not-leak"
        with (self.nested / ".git" / "config").open("a", encoding="utf-8") as stream:
            stream.write(f"\n[invalid-{secret}\n")
        with self.assertRaises(ReCTMError) as error:
            self.call("git_status", repo_path="nested")
        self.assertEqual(error.exception.code, "GIT_CONFIG_UNSAFE")
        self.assertEqual(error.exception.category, "security")
        self.assertNotIn(secret, str(error.exception.to_payload()))
        self.assertNotIn(str(self.nested), str(error.exception.to_payload()))

    def test_missing_promisor_objects_cannot_invoke_transport_helpers(self) -> None:
        helper, marker = self.filter_helper()
        debug = DebugEventBus(self.base / "debug.jsonl", self.private, enabled=False)
        for variant in ["both", "remote-only", "extension-only", "false-promisor"]:
            repo = self.root / f"promisor-{variant}"
            self.init(repo, "promisor fixture")
            blob = self.git(repo, "rev-parse", "HEAD:a.txt").strip()
            (repo / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
            self.git(repo, "config", "core.repositoryformatversion", "1")
            self.git(repo, "config", "remote.origin.url", f"ext::{helper}")
            self.git(repo, "config", "protocol.ext.allow", "always")
            if variant in {"both", "extension-only"}:
                self.git(repo, "config", "extensions.partialClone", "origin")
            if variant in {"both", "remote-only", "false-promisor"}:
                self.git(repo, "config", "remote.origin.promisor", "false" if variant == "false-promisor" else "true")
            (repo / "a.txt").write_text("changed-with-missing-blob\n", encoding="utf-8")
            for mode in NativeMode:
                runtime = NativeRuntime(self.workspace, mode, debug)
                self.addCleanup(runtime.close)
                for tool, args in [
                    ("git_status", {}), ("git_diff", {"path": "a.txt"}), ("git_log", {"path": "a.txt"}),
                    ("git_show", {"rev": "HEAD:a.txt"}), ("git_blame", {"path": "a.txt", "rev": "HEAD"}),
                ]:
                    with self.subTest(variant=variant, mode=mode, tool=tool):
                        with self.assertRaises(ReCTMError) as error:
                            getattr(runtime, tool)(repo_path=repo.name, **args)
                        self.assertEqual(error.exception.code, "GIT_PROMISOR_DENIED")
                        self.assertEqual(error.exception.category, "security")
                        self.assertNotIn(str(helper), str(error.exception.to_payload()))
                        self.assertFalse(marker.exists())
            # Defense in depth also blocks lazy transport if the preflight is not
            # called by a future internal command path. No network is contacted.
            output = ctm_compat._git(["git", "-C", str(repo), "show", "HEAD:a.txt"])
            self.assertNotEqual(output.returncode, 0)
            self.assertFalse(marker.exists())

    def test_transport_protocol_environment_blocks_ext_helper(self) -> None:
        helper, marker = self.filter_helper()
        output = ctm_compat._git([
            "git", "-c", "protocol.ext.allow=always", "ls-remote", f"ext::{helper}",
        ])
        self.assertNotEqual(output.returncode, 0)
        self.assertFalse(marker.exists())

    def test_configured_signature_verifier_cannot_run_on_log_or_show(self) -> None:
        helper, marker = self.filter_helper()
        tree = self.git(self.nested, "rev-parse", "HEAD^{tree}").strip()
        parent = self.git(self.nested, "rev-parse", "HEAD").strip()
        commit = self.base / "fake-signed-commit"
        commit.write_text(
            f"tree {tree}\nparent {parent}\n"
            "author Re-CTM fixture <fixture@example.invalid> 1700000000 +0000\n"
            "committer Re-CTM fixture <fixture@example.invalid> 1700000000 +0000\n"
            "gpgsig -----BEGIN PGP SIGNATURE-----\n \n ZmFrZQo=\n -----END PGP SIGNATURE-----\n"
            "\nfake signed fixture\n",
            encoding="utf-8",
        )
        signed = self.git(self.nested, "hash-object", "-t", "commit", "-w", str(commit)).strip()
        self.git(self.nested, "update-ref", "HEAD", signed)
        self.git(self.nested, "config", "gpg.program", str(helper))
        self.git(self.nested, "config", "log.showSignature", "true")
        log = self.call("git_log", repo_path="nested", max_count=1)
        self.assertEqual(log["commits"][0]["subject"], "fake signed fixture")
        shown = self.call("git_show", repo_path="nested")
        self.assertIn("fake signed fixture", shown["content"])
        self.assertFalse(marker.exists())

    def test_submodule_filters_cannot_execute_through_parent_working_tree_reads(self) -> None:
        helper, marker = self.filter_helper()
        source = self.base / "submodule-source"
        self.init(source, "fixture")
        (source / ".gitattributes").write_text("a.txt filter=fixture-secret-driver\n", encoding="utf-8")
        self.commit(source, ".gitattributes", message="submodule attributes")
        self.git(self.root, "-c", "protocol.file.allow=always", "submodule", "add", "--quiet", str(source), "module")
        self.commit(self.root, ".gitmodules", "module", message="add submodule")
        module = self.root / "module"
        self.git(module, "config", "filter.fixture-secret-driver.clean", str(helper))
        (module / "a.txt").write_text("changed\nsecond\n", encoding="utf-8")
        self.git(self.root, "config", "diff.submodule", "diff")
        self.git(self.root, "config", "status.submoduleSummary", "true")
        debug = DebugEventBus(self.base / "debug.jsonl", self.private, enabled=False)
        for metadata_present in [True, False]:
            if not metadata_present:
                self.git(self.root, "update-index", "--force-remove", ".gitmodules")
                (self.root / ".gitmodules").unlink()
            for mode in NativeMode:
                runtime = NativeRuntime(self.workspace, mode, debug)
                self.addCleanup(runtime.close)
                for tool in ["git_status", "git_diff"]:
                    with self.subTest(metadata_present=metadata_present, mode=mode, tool=tool):
                        with self.assertRaises(ReCTMError) as error:
                            getattr(runtime, tool)()
                        self.assertEqual(error.exception.code, "GIT_SUBMODULE_UNSUPPORTED")
                        self.assertEqual(error.exception.category, "security")
                        self.assertIn("repo_path", error.exception.message)
                        self.assertFalse(marker.exists())
            # History and a parent-tracked file remain available without descending
            # into child repositories, even when user config requests submodule diffs.
            self.assertEqual(self.call("git_log", max_count=1)["commits"][0]["subject"], "add submodule")
            self.assertIn("add submodule", self.call("git_show")["content"])
            self.assertEqual(self.call("git_blame", path="a.txt")["lines"][0]["content"], "parent-fixture")
            self.assertFalse(marker.exists())
        with self.assertRaises(ReCTMError) as error:
            self.call("git_status", repo_path="module")
        self.assertEqual(error.exception.code, "GIT_FILTER_DENIED")
        self.git(module, "config", "--unset-all", "filter.fixture-secret-driver.clean")
        selected = self.call("git_status", repo_path="module")
        self.assertEqual(selected["repo_path"], "module")
        self.assertFalse(selected["clean"])
        self.assertFalse(marker.exists())

    def test_text_output_bounds_report_truncation_without_broken_utf8(self) -> None:
        (self.nested / "a.txt").write_text("中🙂" * 30_000 + "\n", encoding="utf-8")
        for budget in [1, 2, 3, 100, 1000]:
            result = self.call("git_diff", repo_path="nested", max_bytes=budget)
            self.assertLessEqual(len(result["diff"].encode("utf-8")), budget)
            self.assertTrue(result["truncated"])
            self.assertTrue(result["warnings"])
            self.assertNotIn("\ufffd", result["diff"])
        self.commit(self.nested, "a.txt")
        result = self.call("git_show", repo_path="nested", max_bytes=100)
        self.assertEqual(len(result["content"].encode("utf-8")), 100)
        self.assertTrue(result["truncated"])

    def test_exact_text_budget_is_not_truncation(self) -> None:
        (self.nested / "a.txt").write_text("changed\n", encoding="utf-8")
        for tool, field in [("git_diff", "diff"), ("git_show", "content")]:
            with self.subTest(tool=tool):
                whole = self.call(tool, repo_path="nested")
                size = len(whole[field].encode("utf-8"))
                exact = self.call(tool, repo_path="nested", max_bytes=size)
                self.assertFalse(exact["truncated"])
                self.assertEqual(exact[field], whole[field])
                self.assertTrue(self.call(tool, repo_path="nested", max_bytes=size - 1)["truncated"])

    def test_structured_output_is_rejected_before_partial_parsing(self) -> None:
        incomplete = ctm_compat._GitOutput(0, "malformed", "", stdout_truncated=True)

        def output(command: list[str], **kwargs: object) -> ctm_compat._GitOutput:
            if "config" in command:
                return ctm_compat._GitOutput(1, "", "")
            if "ls-files" in command:
                return ctm_compat._GitOutput(0, "", "")
            return incomplete

        for tool, args, operation in [
            ("git_status", {}, "status"), ("git_log", {}, "log"),
            ("git_blame", {"path": "a.txt"}, "blame"),
            ("git_blame", {"path": "a.txt", "rev": "HEAD"}, "show"),
        ]:
            with self.subTest(tool=tool, args=args), patch.object(ctm_compat, "_git", side_effect=output) as git:
                with self.assertRaises(ReCTMError) as error:
                    self.call(tool, repo_path="nested", **args)
                self.assertEqual(error.exception.code, "GIT_OUTPUT_TRUNCATED")
                self.assertIn(operation, git.call_args.args[0])

    def test_config_and_index_preflights_reject_truncated_output(self) -> None:
        incomplete = ctm_compat._GitOutput(0, "malformed", "", stdout_truncated=True)
        for operation in ["config", "ls-files"]:
            def output(command: list[str], **kwargs: object) -> ctm_compat._GitOutput:
                if operation in command:
                    return incomplete
                return ctm_compat._GitOutput(1, "", "")

            with self.subTest(operation=operation), patch.object(ctm_compat, "_git", side_effect=output) as git:
                with self.assertRaises(ReCTMError) as error:
                    self.call("git_status", repo_path="nested")
                self.assertEqual(error.exception.code, "GIT_OUTPUT_TRUNCATED")
                self.assertIn(operation, git.call_args.args[0])

    def test_real_capture_is_bounded_and_exact_limit_is_complete(self) -> None:
        repo = ctm_compat._select_repository(self.workspace, {"repo_path": "nested"})
        command = repo.command("show") + ["HEAD:a.txt"]
        full = ctm_compat._git(command)
        size = len(full.stdout.encode("utf-8"))
        exact = ctm_compat._git(command, max_bytes=size)
        self.assertEqual(exact.stdout, full.stdout)
        self.assertFalse(exact.stdout_truncated)
        short = ctm_compat._git(command, max_bytes=size - 1)
        self.assertTrue(short.stdout_truncated)
        self.assertLessEqual(len(short.stdout.encode("utf-8")), size - 1)
        (self.nested / "large.txt").write_text("x" * 2_000_001, encoding="utf-8")
        self.commit(self.nested, "large.txt")
        with self.assertRaises(ReCTMError) as error:
            self.call("git_blame", repo_path="nested", path="large.txt", rev="HEAD")
        self.assertEqual(error.exception.code, "GIT_OUTPUT_TRUNCATED")

    def test_capture_drains_both_streams_with_bounded_retained_prefixes(self) -> None:
        # A deterministic producer isolates pipe backpressure from repository size.
        result = ctm_compat._git([
            sys.executable, "-c",
            "import os; "
            "[(os.write(1, b'x' * 65536), os.write(2, b'e' * 65536)) for _ in range(40)]",
        ], max_bytes=1000)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "x" * 1000)
        self.assertEqual(result.stderr, "e" * 65_536)
        self.assertTrue(result.stdout_truncated)

    def test_invalid_arguments_are_not_coerced(self) -> None:
        requests = [
            ("git_status", {"repo_path": ""}), ("git_status", {"repo_path": 1}),
            ("git_status", {"max_entries": 0}), ("git_status", {"max_entries": True}),
            ("git_diff", {"path": 1}), ("git_diff", {"paths": "a.txt"}),
            ("git_diff", {"paths": [1]}), ("git_diff", {"paths": ["a.txt"] * 257}),
            ("git_diff", {"max_bytes": 0}), ("git_log", {"ref": "--all"}),
            ("git_log", {"max_count": 0}), ("git_log", {"ref": 1}),
            ("git_blame", {"path": "a.txt", "end_line": 0}),
            ("git_blame", {"path": "a.txt", "max_lines": 0}),
        ]
        for tool, args in requests:
            with self.subTest(tool=tool, args=args), self.assertRaises(ReCTMError):
                self.call(tool, **args)


if __name__ == "__main__":
    unittest.main()
