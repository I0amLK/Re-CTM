from __future__ import annotations

import base64
import fnmatch
import hashlib
import io
import json
import mimetypes
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import ReCTMError, invalid_argument


NETWORK_RE = re.compile(
    r"(https?://|urllib\.request|urllib3|requests\.|http\.client|\bHTTPConnection\b|\bHTTPSConnection\b|socket\.|aiohttp|httpx|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bssh\b|\bscp\b|\bftp\b)",
    re.I,
)
SHELL_EXPANSION_RE = re.compile(r"(`|\$\(|\$\{)")
DESTRUCTIVE_RE = re.compile(
    r"(^|\s)(sudo|su|chmod\s+-R|chown\s+-R|mkfs|mount|umount|find\b[^;&|]*\s-delete\b|git\b[^;&|]*\breset\s+--hard\b|git\b[^;&|]*\bclean\s+-[^\s]*[fx][^\s]*|rm\s+-[^\s]*r[^\s]*f|rm\s+-[^\s]*f[^\s]*r)\b",
    re.I,
)
SENSITIVE_ENV_RE = re.compile(r"(token|secret|credential|api[_-]?key|password|passwd|private)", re.I)
SENSITIVE_VALUE_RE = re.compile(
    r"(COMPLIANCE_SHOULD_NOT_LEAK|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})"
)
RISKY_ENV_NAMES = {
    "BASH_ENV",
    "ENV",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYOPT",
    "RUBYLIB",
}


def check_command_policy(mode: str, cmd: str, env: Mapping[str, str]) -> None:
    """Preserve CTM's permission-mode gates before entering the hard sandbox."""

    if mode == "dangerous":
        return
    filtered = [key for key, value in env.items() if is_filtered_env_var(key, value)]
    if filtered:
        raise ReCTMError(
            "PERMISSION_REQUIRED",
            "Sensitive or loader/startup environment variables require explicit permission.",
            category="permission",
            details={"permission": "sensitive_env", "env_keys": sorted(filtered)},
        )
    if DESTRUCTIVE_RE.search(cmd):
        raise ReCTMError(
            "PERMISSION_REQUIRED",
            "Destructive commands are blocked without explicit permission.",
            category="permission",
            details={"permission": "destructive_command"},
        )
    if mode == "trusted":
        return
    if SHELL_EXPANSION_RE.search(cmd):
        raise ReCTMError(
            "PERMISSION_REQUIRED",
            "Shell command substitution and parameter expansion require explicit permission.",
            category="permission",
            details={"permission": "shell_expansion"},
        )
    inline = inline_script_command(cmd)
    if inline is not None:
        raise ReCTMError(
            "PERMISSION_REQUIRED",
            "Inline interpreter or shell code requires explicit permission.",
            category="permission",
            details={"permission": "inline_script", **inline},
        )
    if NETWORK_RE.search(cmd):
        raise ReCTMError(
            "PERMISSION_REQUIRED",
            "Network access is denied by default.",
            category="permission",
            details={"permission": "network"},
        )


def is_filtered_env_var(name: str, value: str) -> bool:
    upper = name.upper()
    risky = upper in RISKY_ENV_NAMES or upper.startswith("DYLD_")
    return bool(SENSITIVE_ENV_RE.search(name) or risky or SENSITIVE_VALUE_RE.search(value))


def inline_script_command(command: str) -> dict[str, str] | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in {"|", "||", "&", "&&", ";"}:
            segments.append([])
        else:
            segments[-1].append(token)
    for segment in segments:
        if not segment:
            continue
        while segment and "=" in segment[0] and not segment[0].startswith("="):
            segment = segment[1:]
        if not segment:
            continue
        name = Path(segment[0].replace("\\", "/")).name.lower()
        args = segment[1:]
        if name == "env":
            while args and (args[0].startswith("-") or "=" in args[0]):
                args = args[1:]
            if args:
                name = Path(args[0].replace("\\", "/")).name.lower()
                args = args[1:]
        if name in {"bash", "sh", "zsh"}:
            option = next((arg for arg in args if arg.startswith("-") and "c" in arg.lstrip("-")), None)
            if option:
                return {"command": name, "option": option}
        if name in {"python", "python3"} and ("-c" in args or "-" in args):
            return {"command": name, "option": "-c" if "-c" in args else "-"}
        if name == "node":
            for option in ("-e", "--eval", "-p", "--print"):
                if option in args:
                    return {"command": name, "option": option}
        if name in {"ruby", "perl"} and "-e" in args:
            return {"command": name, "option": "-e"}
    return None


@dataclass
class PatchOperation:
    kind: str
    path: str
    add_content: str | None = None
    hunks: list[list[str]] = field(default_factory=list)
    move_to: str | None = None


def list_dir(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    resolved = workspace.resolve_existing(str(args.get("path", ".")))
    if not resolved.path.is_dir():
        raise ReCTMError("NOT_A_DIRECTORY", "Path is not a directory.", category="validation")
    recursive = bool(args.get("recursive", False))
    max_depth = int(args.get("max_depth", 1))
    max_entries = int(args.get("max_entries", 1000))
    include_hidden = bool(args.get("include_hidden", False))
    include_ignored = bool(args.get("include_ignored", False))
    sort_key = str(args.get("sort", "name"))
    entries: list[dict[str, Any]] = []
    truncated = False

    def visit(directory: Path, depth: int) -> None:
        nonlocal truncated
        if truncated:
            return
        try:
            children = list(directory.iterdir())
        except OSError:
            return
        for child in children:
            if _ignored(child.name, include_hidden, include_ignored):
                continue
            try:
                stat = child.lstat()
            except OSError:
                continue
            item = {
                "name": child.name,
                "path": child.relative_to(workspace.root).as_posix(),
                "type": "symlink" if child.is_symlink() else "directory" if child.is_dir() else "file",
                "size_bytes": stat.st_size,
                "modified": stat.st_mtime,
                "is_hidden": child.name.startswith("."),
                "is_ignored": _ignored(child.name, True, False),
            }
            entries.append(item)
            if len(entries) >= max_entries:
                truncated = True
                return
            if recursive and depth < max_depth and child.is_dir() and not child.is_symlink():
                visit(child, depth + 1)

    visit(resolved.path, 1)
    if sort_key == "type":
        entries.sort(key=lambda item: (item["type"], item["path"]))
    elif sort_key == "modified":
        entries.sort(key=lambda item: (-float(item["modified"]), item["path"]))
    else:
        entries.sort(key=lambda item: item["path"])
    return {
        "path": resolved.display,
        "entries": entries,
        "truncated": truncated,
        "warnings": ["entry limit reached"] if truncated else [],
    }


def list_files(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    resolved = workspace.resolve_existing(str(args.get("path", ".")))
    if not resolved.path.is_dir():
        raise ReCTMError("NOT_A_DIRECTORY", "Path is not a directory.", category="validation")
    patterns_arg = args.get("patterns")
    glob_arg = args.get("glob")
    if isinstance(patterns_arg, list) and patterns_arg:
        patterns = [str(item) for item in patterns_arg]
    elif isinstance(glob_arg, str) and glob_arg:
        patterns = [glob_arg]
    else:
        patterns = ["**/*"]
    excludes = [str(item) for item in args.get("exclude_patterns", []) if str(item)]
    include_hidden = bool(args.get("include_hidden", False))
    include_ignored = bool(args.get("include_ignored", False))
    max_results = int(args.get("max_results", 5000))
    sort_key = str(args.get("sort", "path"))
    files: list[dict[str, Any]] = []
    for path in resolved.path.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(workspace.root).as_posix()
        local_rel = path.relative_to(resolved.path).as_posix()
        if any(_ignored(part, include_hidden, include_ignored) for part in path.relative_to(resolved.path).parts):
            continue
        if not any(_glob_match(local_rel, pattern) for pattern in patterns):
            continue
        if any(_glob_match(local_rel, pattern) or _glob_match(rel, pattern) for pattern in excludes):
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        files.append({"path": rel, "type": "file", "size_bytes": stat.st_size, "modified": stat.st_mtime})
    if sort_key == "modified":
        files.sort(key=lambda item: (-float(item["modified"]), item["path"]))
    else:
        files.sort(key=lambda item: item["path"])
    truncated = len(files) > max_results
    return {"files": files[:max_results], "count": min(len(files), max_results), "truncated": truncated}


def search_text(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    query = str(args.get("query", ""))
    if not query:
        raise invalid_argument("query is required")
    regex = bool(args.get("regex", False))
    case_sensitive = bool(args.get("case_sensitive", False))
    context_lines = int(args.get("context_lines", 0))
    max_results = int(args.get("max_results", 1000))
    max_preview = int(args.get("max_preview_bytes", 512))
    include_globs = [str(item) for item in args.get("include_globs", []) if str(item)]
    if isinstance(args.get("glob"), str) and args.get("glob"):
        include_globs.append(str(args["glob"]))
    exclude_globs = [str(item) for item in args.get("exclude_globs", []) if str(item)]
    listed = list_files(
        workspace,
        {
            "path": str(args.get("path", ".")),
            "patterns": include_globs or ["**/*"],
            "exclude_patterns": exclude_globs,
            "include_hidden": False,
            "include_ignored": False,
            "max_results": 50_000,
        },
    )
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(query if regex else re.escape(query), flags)
    except re.error as exc:
        raise invalid_argument("invalid regular expression", error=str(exc)) from exc
    matches: list[dict[str, Any]] = []
    for item in listed["files"]:
        path = workspace.resolve_existing(item["path"]).path
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lines = text.splitlines()
        for index, line in enumerate(lines):
            match = pattern.search(line)
            if match is None:
                continue
            before = lines[max(0, index - context_lines) : index]
            after = lines[index + 1 : index + 1 + context_lines]
            preview = line.encode("utf-8")[:max_preview].decode("utf-8", errors="ignore")
            matches.append(
                {
                    "path": item["path"],
                    "line": index + 1,
                    "column": match.start() + 1,
                    "preview": preview,
                    "before": before,
                    "after": after,
                }
            )
            if len(matches) >= max_results:
                return {"matches": matches, "total_matches": len(matches), "truncated": True}
    return {"matches": matches, "total_matches": len(matches), "truncated": False}


def patch_to_editor_operations(workspace: Any, patch: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    parsed = parse_patch(patch)
    editor_ops: list[dict[str, Any]] = []
    additions = 0
    removals = 0
    summaries: list[str] = []
    for operation in parsed:
        if operation.kind == "add":
            workspace.resolve_for_write(operation.path)
            content = operation.add_content or ""
            editor_ops.append({"op": "add", "path": operation.path, "content": content})
            additions += len(content.splitlines())
            summaries.append(f"A {operation.path}")
            continue
        existing = workspace.resolve_existing(operation.path)
        if existing.path.is_dir():
            raise ReCTMError("PATCH_FAILED", "Cannot patch a directory.", category="validation")
        try:
            old = existing.path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ReCTMError("UNSUPPORTED_ENCODING", "Patch target is not valid UTF-8.", category="validation") from exc
        baseline = hashlib.sha256(existing.path.read_bytes()).hexdigest()
        if operation.kind == "delete":
            editor_ops.append({"op": "delete", "path": operation.path, "expected_sha256": baseline})
            removals += len(old.splitlines())
            summaries.append(f"D {operation.path}")
            continue
        updated = apply_update_hunks(old, operation.hunks, operation.path)
        old_lines = old.splitlines()
        new_lines = updated.splitlines()
        additions += max(0, len(new_lines) - len(old_lines))
        removals += max(0, len(old_lines) - len(new_lines))
        if operation.move_to:
            workspace.resolve_for_write(operation.move_to)
            editor_ops.append({"op": "delete", "path": operation.path, "expected_sha256": baseline})
            editor_ops.append({"op": "add", "path": operation.move_to, "content": updated})
            summaries.append(f"R {operation.path} -> {operation.move_to}")
        else:
            editor_ops.append(
                {"op": "update", "path": operation.path, "content": updated, "expected_sha256": baseline}
            )
            summaries.append(f"M {operation.path}")
    return editor_ops, {"summary": "\n".join(summaries), "additions": additions, "removals": removals}


def parse_patch(patch: str) -> list[PatchOperation]:
    lines = patch.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[-1]:
        lines.pop()
    if not lines or lines[0].strip() != "*** Begin Patch" or lines[-1].strip() != "*** End Patch":
        raise ReCTMError(
            "PATCH_FAILED",
            "Patch must use *** Begin Patch / *** End Patch envelope.",
            category="validation",
        )
    operations: list[PatchOperation] = []
    i = 1
    while i < len(lines) - 1:
        line = lines[i]
        if not line:
            i += 1
            continue
        if line.startswith("*** Add File: "):
            path = line.removeprefix("*** Add File: ").strip()
            i += 1
            content: list[str] = []
            while i < len(lines) - 1 and not lines[i].startswith("*** "):
                if not lines[i].startswith("+"):
                    raise ReCTMError("PATCH_FAILED", "Add file lines must start with '+'.", category="validation")
                content.append(lines[i][1:])
                i += 1
            operations.append(PatchOperation("add", path, add_content="\n".join(content) + "\n"))
            continue
        if line.startswith("*** Delete File: "):
            operations.append(PatchOperation("delete", line.removeprefix("*** Delete File: ").strip()))
            i += 1
            continue
        if line.startswith("*** Update File: "):
            path = line.removeprefix("*** Update File: ").strip()
            i += 1
            move_to: str | None = None
            if i < len(lines) - 1 and lines[i].startswith("*** Move to: "):
                move_to = lines[i].removeprefix("*** Move to: ").strip()
                i += 1
            hunks: list[list[str]] = []
            current: list[str] = []
            while i < len(lines) - 1 and not lines[i].startswith("*** "):
                if lines[i].startswith("@@"):
                    if current:
                        hunks.append(current)
                    current = []
                else:
                    current.append(lines[i])
                i += 1
            if current:
                hunks.append(current)
            operations.append(PatchOperation("update", path, hunks=hunks, move_to=move_to))
            continue
        raise ReCTMError("PATCH_FAILED", f"Unrecognized patch line: {line}", category="validation")
    return operations


def apply_update_hunks(content: str, hunks: list[list[str]], path: str) -> str:
    if not hunks:
        return content
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    parsed = [_parse_hunk(hunk) for hunk in hunks]
    replacements: list[tuple[int, int, list[str]]] = []
    for index, (old, new) in enumerate(parsed):
        matches = [0] if not old else _find_all(lines, old)
        if not matches:
            raise ReCTMError(
                "PATCH_CONTEXT_NOT_FOUND",
                f"Patch context did not match in {path}.",
                category="validation",
                retryable=True,
                details={"hunk_index": index},
            )
        if len(matches) > 1:
            raise ReCTMError(
                "PATCH_CONTEXT_AMBIGUOUS",
                f"Patch context matched {len(matches)} locations in {path}.",
                category="validation",
                retryable=True,
                details={"hunk_index": index, "match_count": len(matches)},
            )
        start = matches[0]
        replacements.append((start, start + len(old), new))
    replacements.sort()
    for previous, current in zip(replacements, replacements[1:]):
        if previous[1] > current[0]:
            raise ReCTMError("PATCH_HUNKS_OVERLAP", "Patch hunks overlap.", category="validation")
    updated = list(lines)
    for start, end, new in reversed(replacements):
        updated[start:end] = new
    result = "\n".join(updated)
    if "\r\n" in content:
        result = result.replace("\n", "\r\n")
    return result


def git_status(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    resolved = workspace.resolve_existing(str(args.get("path", ".")))
    if not _is_repo(resolved.path):
        return {"is_repo": False, "clean": True, "entries": [], "truncated": False, "warnings": []}
    max_entries = int(args.get("max_entries", 1000))
    command = ["git", "-C", str(resolved.path), "status", "--porcelain=v1", "-b"]
    if not bool(args.get("include_untracked", True)):
        command.append("--untracked-files=no")
    completed = _git(command)
    if completed.returncode != 0:
        raise ReCTMError("GIT_ERROR", completed.stderr.strip() or "git status failed", category="runtime")
    branch = ""
    upstream = ""
    ahead = behind = 0
    entries: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        if line.startswith("## "):
            branch, upstream, ahead, behind = _parse_branch(line[3:])
            continue
        if not line:
            continue
        path_text = line[3:]
        original = None
        if " -> " in path_text:
            original, path_text = path_text.split(" -> ", 1)
        entries.append(
            {"path": path_text, "original_path": original, "index_status": line[0], "worktree_status": line[1]}
        )
        if len(entries) >= max_entries:
            break
    head = _git(["git", "-C", str(resolved.path), "rev-parse", "HEAD"])
    return {
        "is_repo": True,
        "branch": branch,
        "head": head.stdout.strip() if head.returncode == 0 else "",
        "upstream": upstream,
        "ahead": ahead,
        "behind": behind,
        "clean": not entries,
        "entries": entries,
        "truncated": len(entries) >= max_entries,
    }


def git_diff(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    if not _is_repo(workspace.root):
        return {"diff": "", "files": [], "truncated": False, "warnings": ["not a git repository"]}
    context = int(args.get("context_lines", 3))
    max_bytes = int(args.get("max_bytes", 262_144))
    filters = _path_filters(workspace, args)
    chunks: list[str] = []
    for staged in (False, True):
        if staged and not bool(args.get("staged", False)):
            continue
        if not staged and not bool(args.get("unstaged", True)):
            continue
        command = [
            "git",
            "-C",
            str(workspace.root),
            "-c",
            "diff.external=",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            f"--unified={context}",
        ]
        if staged:
            command.append("--cached")
        if filters:
            command += ["--", *filters]
        completed = _git(command)
        if completed.returncode not in {0, 1}:
            raise ReCTMError("GIT_ERROR", completed.stderr.strip() or "git diff failed", category="runtime")
        chunks.append(completed.stdout)
    text = "\n".join(chunk.rstrip("\n") for chunk in chunks if chunk)
    if text:
        text += "\n"
    encoded = text.encode("utf-8")
    truncated = len(encoded) > max_bytes
    if truncated:
        text = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return {"diff": text, "files": _parse_diff_files(text), "truncated": truncated, "warnings": ["diff truncated"] if truncated else []}


def git_log(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    requested = workspace.resolve_existing(str(args.get("path", ".")))
    if not _is_repo(requested.path):
        return {"is_repo": False, "commits": [], "truncated": False, "warnings": []}
    ref = _validate_ref(str(args.get("ref", "HEAD")))
    count = int(args.get("max_count", 20))
    skip = int(args.get("skip", 0))
    command = [
        "git", "-C", str(workspace.root), "log", f"--max-count={count + 1}", f"--skip={skip}",
        "--date=iso-strict", "--pretty=format:%H%x1f%h%x1f%an%x1f%ae%x1f%ad%x1f%s%x1e", ref,
    ]
    if requested.display != ".":
        command += ["--", requested.display]
    completed = _git(command)
    if completed.returncode != 0:
        raise ReCTMError("GIT_ERROR", completed.stderr.strip() or "git log failed", category="runtime")
    commits: list[dict[str, Any]] = []
    for record in completed.stdout.split("\x1e"):
        fields = record.strip("\n").split("\x1f")
        if len(fields) >= 6 and fields[0]:
            commits.append(
                {"hash": fields[0], "short_hash": fields[1], "author_name": fields[2], "author_email": fields[3], "author_date": fields[4], "subject": fields[5]}
            )
    truncated = len(commits) > count
    return {"is_repo": True, "ref": ref, "path": requested.display, "max_count": count, "skip": skip, "commits": commits[:count], "truncated": truncated, "warnings": ["commit limit reached"] if truncated else []}


def git_show(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    if not _is_repo(workspace.root):
        return {"is_repo": False, "content": "", "files": [], "truncated": False, "warnings": []}
    rev = _validate_ref(str(args.get("rev", "HEAD")))
    context = int(args.get("context_lines", 3))
    max_bytes = int(args.get("max_bytes", 262_144))
    command = [
        "git", "-C", str(workspace.root), "show", "--no-ext-diff", "--no-textconv", "--format=fuller", f"--unified={context}",
    ]
    if not bool(args.get("include_diff", True)):
        command.append("--no-patch")
    command.append(rev)
    filters = _path_filters(workspace, args)
    if filters:
        command += ["--", *filters]
    completed = _git(command)
    if completed.returncode != 0:
        raise ReCTMError("GIT_ERROR", completed.stderr.strip() or "git show failed", category="runtime")
    encoded = completed.stdout.encode("utf-8")
    truncated = len(encoded) > max_bytes
    content = encoded[:max_bytes].decode("utf-8", errors="ignore") if truncated else completed.stdout
    return {"is_repo": True, "rev": rev, "content": content, "files": _parse_diff_files(content), "truncated": truncated, "warnings": ["output truncated"] if truncated else []}


def git_blame(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    requested_path = str(args.get("path", ""))
    resolved = workspace.resolve_existing(requested_path)
    if resolved.path.is_dir():
        raise ReCTMError("IS_DIRECTORY", "Path is a directory.", category="validation")
    if not _is_repo(workspace.root):
        return {"is_repo": False, "path": resolved.display, "lines": [], "truncated": False, "warnings": []}
    start = int(args.get("start_line", 1))
    max_lines = int(args.get("max_lines", 200))
    requested_end = int(args.get("end_line", start + max_lines - 1))
    if requested_end < start:
        raise invalid_argument("end_line must be >= start_line")
    final = min(requested_end, start + max_lines - 1)
    ref = _validate_ref(str(args["rev"])) if args.get("rev") else None
    command = ["git", "-C", str(workspace.root), "blame", "--line-porcelain", "-L", f"{start},{final}"]
    if ref:
        command.append(ref)
    command += ["--", resolved.display]
    completed = _git(command)
    if completed.returncode != 0:
        raise ReCTMError("GIT_ERROR", completed.stderr.strip() or "git blame failed", category="runtime")
    lines = _parse_blame(completed.stdout)
    truncated = requested_end > final
    result: dict[str, Any] = {"is_repo": True, "path": resolved.display, "rev": ref, "start_line": start, "end_line": final, "max_lines": max_lines, "lines": lines[:max_lines], "truncated": truncated, "warnings": ["line limit reached"] if truncated else []}
    if truncated:
        result["next_action"] = {"tool": "git_blame", "arguments": {"path": requested_path, "start_line": final + 1, "end_line": requested_end, "max_lines": max_lines}}
    return result


def view_image(workspace: Any, args: Mapping[str, Any]) -> dict[str, Any]:
    resolved = workspace.resolve_existing(str(args.get("path", "")))
    if resolved.path.is_dir():
        raise ReCTMError("IS_DIRECTORY", "Path is a directory.", category="validation")
    max_bytes = int(args.get("max_bytes", 5_242_880))
    max_width = int(args.get("max_width", 2000))
    max_height = int(args.get("max_height", 2000))
    auto_resize = bool(args.get("auto_resize", True))
    data = resolved.path.read_bytes()
    mime, width, height = _identify_image(data, resolved.path)
    if mime is None:
        raise ReCTMError("BINARY_FILE", "File is not a supported image.", category="validation")
    original = {"bytes": len(data), "width": width, "height": height, "mime_type": mime}
    resized = False
    warnings: list[str] = []
    if auto_resize and _should_resize_image(len(data), width, height, max_bytes, max_width, max_height):
        resized_data = _resize_image_bytes(
            data,
            mime,
            max_width=max_width,
            max_height=max_height,
            max_bytes=max_bytes,
        )
        if resized_data is not None:
            data, mime = resized_data
            mime, width, height = _identify_image(data, resolved.path)
            resized = True
        else:
            warnings.append("auto_resize requested but Pillow is not installed or image resize failed")
    if len(data) > max_bytes:
        raise ReCTMError("OUTPUT_TOO_LARGE", "Image exceeds max_bytes.", category="validation", details={"bytes": len(data), "max_bytes": max_bytes})
    return {
        "path": resolved.display,
        "mime_type": mime,
        "bytes": len(data),
        "width": width,
        "height": height,
        "resized": resized,
        "original": original,
        "_mcp_image_data": base64.b64encode(data).decode("ascii"),
        "warnings": warnings,
    }


def _ignored(name: str, include_hidden: bool, include_ignored: bool) -> bool:
    excluded = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    return (not include_hidden and name.startswith(".")) or (not include_ignored and name in excluded)


def _glob_match(path: str, pattern: str) -> bool:
    if pattern in {"*", "**/*"}:
        return True
    return fnmatch.fnmatch(path, pattern) or Path(path).match(pattern)


def _parse_hunk(hunk: Iterable[str]) -> tuple[list[str], list[str]]:
    old: list[str] = []
    new: list[str] = []
    for raw in hunk:
        if raw == "*** End of File":
            continue
        if not raw:
            old.append("")
            new.append("")
            continue
        marker = raw[0]
        value = raw[1:] if marker in {" ", "-", "+"} else raw
        if marker == " ":
            old.append(value); new.append(value)
        elif marker == "-":
            old.append(value)
        elif marker == "+":
            new.append(value)
        else:
            raise ReCTMError("PATCH_FAILED", "Update lines must start with space, '-' or '+'.", category="validation")
    return old, new


def _find_all(lines: list[str], needle: list[str]) -> list[int]:
    return [index for index in range(max(0, len(lines) - len(needle) + 1)) if lines[index : index + len(needle)] == needle]


def _git(command: list[str]) -> subprocess.CompletedProcess[str]:
    if shutil.which("git") is None:
        raise ReCTMError("GIT_NOT_FOUND", "git executable is not available.", category="runtime")
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C.UTF-8",
    }
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15, env=env, check=False)


def _is_repo(path: Path) -> bool:
    completed = _git(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"])
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def _validate_ref(value: str) -> str:
    if not value or value.startswith("-") or any(char.isspace() for char in value) or "\x00" in value:
        raise invalid_argument("invalid git revision", rev=value)
    return value


def _path_filters(workspace: Any, args: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    if isinstance(args.get("path"), str):
        values.append(str(args["path"]))
    if isinstance(args.get("paths"), list):
        values.extend(str(item) for item in args["paths"])
    result: list[str] = []
    for value in values:
        if value in {"", "."}:
            continue
        try:
            result.append(workspace.resolve_existing(value).display)
        except ReCTMError as exc:
            if exc.code != "NOT_FOUND":
                raise
            result.append(workspace.resolve_for_write(value).display)
    return result


def _parse_branch(text: str) -> tuple[str, str, int, int]:
    branch = text
    upstream = ""
    ahead = behind = 0
    if "..." in text:
        branch, rest = text.split("...", 1)
        upstream = rest.split(" ", 1)[0]
    match = re.search(r"ahead (\d+)", text)
    if match:
        ahead = int(match.group(1))
    match = re.search(r"behind (\d+)", text)
    if match:
        behind = int(match.group(1))
    return branch.strip(), upstream.strip(), ahead, behind


def _parse_diff_files(text: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            if path not in seen:
                seen.add(path)
                files.append({"path": path, "status": "modified", "binary": False})
    return files


def _parse_blame(text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in text.splitlines():
        if re.match(r"^[0-9a-f]{40} \d+ \d+(?: \d+)?$", line):
            parts = line.split()
            current = {"commit": parts[0], "original_line": int(parts[1]), "line": int(parts[2])}
        elif line.startswith("author "):
            current["author"] = line[7:]
        elif line.startswith("author-mail "):
            current["author_email"] = line[12:].strip("<>")
        elif line.startswith("author-time "):
            current["author_time"] = int(line[12:])
        elif line.startswith("summary "):
            current["summary"] = line[8:]
        elif line.startswith("\t"):
            current["content"] = line[1:]
            result.append(current)
            current = {}
    return result


def _identify_image(data: bytes, path: Path) -> tuple[str | None, int | None, int | None]:
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        return "image/png", int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")) and len(data) >= 10:
        return "image/gif", int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")
    if data.startswith(b"\xff\xd8"):
        width, height = _identify_jpeg_size(data)
        return "image/jpeg", width, height
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        width, height = _identify_webp_size(data)
        return "image/webp", width, height
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed and guessed.startswith("image/"):
        return guessed, None, None
    return None, None, None


def _identify_jpeg_size(data: bytes) -> tuple[int | None, int | None]:
    index = 2
    while index + 9 < len(data):
        while index < len(data) and data[index] == 0xFF:
            index += 1
        if index >= len(data):
            break
        marker = data[index]
        index += 1
        if marker in {0xD8, 0xD9}:
            continue
        if marker == 0xDA or index + 2 > len(data):
            break
        segment_length = int.from_bytes(data[index : index + 2], "big")
        if segment_length < 2 or index + segment_length > len(data):
            break
        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        } and segment_length >= 7:
            height = int.from_bytes(data[index + 3 : index + 5], "big")
            width = int.from_bytes(data[index + 5 : index + 7], "big")
            return width, height
        index += segment_length
    return None, None


def _identify_webp_size(data: bytes) -> tuple[int | None, int | None]:
    if len(data) < 30:
        return None, None
    chunk = data[12:16]
    if chunk == b"VP8X" and len(data) >= 30:
        return int.from_bytes(data[24:27], "little") + 1, int.from_bytes(data[27:30], "little") + 1
    if chunk == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
        return int.from_bytes(data[26:28], "little") & 0x3FFF, int.from_bytes(data[28:30], "little") & 0x3FFF
    if chunk == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
        bits = int.from_bytes(data[21:25], "little")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    return None, None


def _should_resize_image(
    size_bytes: int,
    width: int | None,
    height: int | None,
    max_bytes: int,
    max_width: int,
    max_height: int,
) -> bool:
    return (
        size_bytes > max_bytes
        or (width is not None and width > max_width)
        or (height is not None and height > max_height)
    )


def _resize_image_bytes(
    data: bytes,
    mime_type: str,
    *,
    max_width: int,
    max_height: int,
    max_bytes: int,
) -> tuple[bytes, str] | None:
    try:
        from PIL import Image
    except Exception:
        return None
    try:
        image = Image.open(io.BytesIO(data))
        image.thumbnail((max_width, max_height))
        output = io.BytesIO()
        output_format = "JPEG" if mime_type == "image/jpeg" else "PNG" if mime_type == "image/png" else "WEBP"
        save_kwargs: dict[str, Any] = {}
        if output_format in {"JPEG", "WEBP"}:
            save_kwargs["quality"] = 85
            save_kwargs["optimize"] = True
        if output_format == "JPEG" and image.mode not in {"RGB", "L"}:
            image = image.convert("RGB")
        image.save(output, format=output_format, **save_kwargs)
        resized = output.getvalue()
        if len(resized) > max_bytes and output_format in {"JPEG", "WEBP"}:
            for quality in (75, 65, 55):
                output = io.BytesIO()
                image.save(output, format=output_format, quality=quality, optimize=True)
                resized = output.getvalue()
                if len(resized) <= max_bytes:
                    break
        return resized, mime_type
    except Exception:
        return None
