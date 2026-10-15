"""Validated Native command requests and pre-start executable identity checks.

Resolution uses the sandbox's PATH and workdir, never the server's current
directory. Shell collection follows MTM's bounded literal-list/loop policy; it
is not a full shell interpreter and does not evaluate user code during checks.
"""
from __future__ import annotations

import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import ReCTMError, invalid_argument
from .native_replay import canonical_bytes
from .toolchains import DEFAULT_SANDBOX_PATH

SYSTEM_ROOTS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc",
                "/var/lib/texmf", "/var/cache/fontconfig", "/var/cache/fonts")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
_KEYWORDS = {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
             "case", "esac", "in", "function", "{", "}", "(", ")"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")


def _security(code: str, message: str) -> ReCTMError:
    return ReCTMError(code, message, category="security")


def bounded_integer(args: Mapping[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    value = args.get(key, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise invalid_argument(f"{key} must be an integer between {minimum} and {maximum}")
    return value


@dataclass(repr=False)
class ExecInvocation:
    argv: list[str]
    cmd: str | None
    workdir: str
    environment: dict[str, str]
    timeout_ms: int
    yield_time_ms: int
    max_output_bytes: int
    preview_bytes: int
    stdin: str
    tty: bool
    verbosity: str | None

    @classmethod
    def parse(cls, arguments: Mapping[str, Any]) -> "ExecInvocation":
        allowed = {"cmd", "argv", "workdir", "cwd", "env", "timeout_ms", "yield_time_ms",
                   "max_output_bytes", "preview_bytes", "stdin", "tty", "verbosity"}
        if set(arguments) - allowed:
            raise invalid_argument("Unknown exec_command field")
        if ("cmd" in arguments) == ("argv" in arguments):
            raise invalid_argument("exec_command requires exactly one of cmd or argv")
        cmd = arguments.get("cmd")
        if "cmd" in arguments:
            if not isinstance(cmd, str) or not cmd or "\0" in cmd:
                raise invalid_argument("cmd must be a nonempty NUL-free string")
            argv = ["/bin/sh", "-c", cmd]
        else:
            argv = arguments["argv"]
            if (not isinstance(argv, list) or not argv or not all(isinstance(x, str) and "\0" not in x for x in argv)
                    or not argv[0]):
                raise invalid_argument("argv requires a nonempty executable and NUL-free string arguments")
            argv = list(argv)
        for name in ("workdir", "cwd"):
            if name in arguments and (not isinstance(arguments[name], str) or not arguments[name]):
                raise invalid_argument(f"{name} must be a nonempty workspace-relative path")
        if "workdir" in arguments and "cwd" in arguments and arguments["workdir"] != arguments["cwd"]:
            raise invalid_argument("workdir and cwd refer to different directories")
        environment = arguments.get("env", {})
        if not isinstance(environment, dict) or any(
            not isinstance(key, str) or not key or "=" in key or "\0" in key
            or not isinstance(value, str) or "\0" in value for key, value in environment.items()
        ):
            raise invalid_argument("env must have valid nonempty keys and NUL-free string values")
        stdin = arguments.get("stdin", "")
        if not isinstance(stdin, str) or type(arguments.get("tty", False)) is not bool:
            raise invalid_argument("stdin must be a string and tty must be a boolean")
        verbosity = arguments.get("verbosity")
        if verbosity is not None and (not isinstance(verbosity, str) or verbosity not in {"summary", "preview", "full"}):
            raise invalid_argument("verbosity must be summary, preview, or full")
        canonical_bytes(dict(arguments))
        return cls(argv, cmd, arguments.get("workdir", arguments.get("cwd", ".")), dict(environment),
                   bounded_integer(arguments, "timeout_ms", 300_000, 1, 600_000),
                   bounded_integer(arguments, "yield_time_ms", 10_000, 0, 30_000),
                   bounded_integer(arguments, "max_output_bytes", 65_536, 1, 1_048_576),
                   bounded_integer(arguments, "preview_bytes", 4096, 1, 1_048_576),
                   stdin, arguments.get("tty", False), verbosity)

    def candidates(self) -> list[str]:
        if self.cmd is not None:
            return shell_candidates(self.cmd)
        candidates = [self.argv[0]]
        script = _shell_script(self.argv)
        if script is not None:
            candidates.extend(shell_candidates(script, 1))
        return candidates


def _shell_script(words: list[str]) -> str | None:
    if not words or Path(words[0]).name.lower() not in _SHELLS:
        return None
    return next((words[i + 1] for i, word in enumerate(words[:-1])
                 if word in {"-c", "-ec", "-ce", "--command"}), None)


def _segments(command: str) -> list[str] | None:
    if len(command.encode("utf-8")) > 1_048_576:
        raise _security("NATIVE_EXECUTABLE_PARSE_LIMIT", "Command parsing exceeded its fixed bound")
    quote = None
    escaped = False
    start = 0
    segments = []
    for index, char in enumerate(command):
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if escaped:
            if char == "\n":
                return None
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "`" or char == "$" and (
            index + 1 == len(command) or not (command[index + 1].isascii()
            and (command[index + 1].isalnum() or command[index + 1] in "_@*#?-$!"))
        ):
            return None
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char in "<>(){}#":
            return None
        elif char in "\n\r;|&":
            if command[start:index].strip():
                segments.append(command[start:index])
            start = index + 1
            if len(segments) > 1024:
                raise _security("NATIVE_EXECUTABLE_PARSE_LIMIT", "Command list exceeded its fixed bound")
    if quote is not None or escaped:
        raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Command quotes could not be parsed")
    if command[start:].strip():
        segments.append(command[start:])
    if len(segments) > 1024:
        raise _security("NATIVE_EXECUTABLE_PARSE_LIMIT", "Command list exceeded its fixed bound")
    return segments


def _words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, comments=True)
    except ValueError as exc:
        raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Command could not be parsed for executable checks") from exc


def _append_candidates(words: list[str], depth: int, output: list[str], *, simple: bool) -> None:
    if simple and words and words[0] == "command":
        index = 1
        query = default_path = False
        while index < len(words) and words[index].startswith("-"):
            option = words[index]; index += 1
            if option == "--":
                break
            if len(option) == 1 or any(ch not in "pvV" for ch in option[1:]):
                raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Unsupported command builtin option")
            query |= any(ch in "vV" for ch in option[1:])
            default_path |= "p" in option[1:]
        if query:
            return
        if default_path or depth >= 4:
            raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Command PATH changes require literal argv")
        return _append_candidates(words[index:], depth + 1, output, simple=True)
    index = 0
    while index < len(words) and _ASSIGNMENT.match(words[index]):
        index += 1
    while index < len(words):
        name = Path(words[index]).name.lower()
        if name in {"env", "command", "exec", "nohup", "setsid", "time"} and not (
            simple and "/" in words[index] and name == "command"
        ):
            index += 1
            if name == "env":
                while index < len(words) and (words[index].startswith("-") or _ASSIGNMENT.match(words[index])):
                    index += 2 if words[index] in {"-u", "--unset"} else 1
            continue
        if name in _KEYWORDS:
            index += 1
            continue
        output.append(words[index])
        script = _shell_script(words[index:])
        if script is not None:
            output.extend(shell_candidates(script, depth + 1))
        return


def shell_candidates(command: str, depth: int = 0) -> list[str]:
    if depth > 4:
        raise _security("NATIVE_EXECUTABLE_PARSE_LIMIT", "Nested shell command parsing exceeded its bound")
    segments = _segments(command)
    output: list[str] = []
    if segments is not None:
        complex_keywords = {"if", "then", "elif", "else", "fi", "while", "until", "case", "esac", "select", "function"}
        simple = not any(segment.strip().split(maxsplit=1)[0] in complex_keywords for segment in segments)
        loops: list[bool] = []
        for segment in segments:
            words = _words(segment)
            if not words:
                continue
            if simple:
                if words[0] == "do":
                    if not loops or not loops[-1]:
                        raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Invalid bounded loop structure")
                    loops[-1] = False
                    words = words[1:]
                elif loops and loops[-1]:
                    raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Invalid bounded loop structure")
                if not words:
                    continue
                if words[0] == "for":
                    if len(words) < 2 or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", words[1]) or (len(words) > 2 and words[2] != "in") or len(loops) >= 32:
                        raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Unsupported bounded loop header")
                    loops.append(True)
                    continue
                if words[0] == "done":
                    if len(words) != 1 or not loops or loops.pop():
                        raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Invalid bounded loop structure")
                    continue
            _append_candidates(words, depth, output, simple=simple)
        if loops:
            raise _security("NATIVE_EXECUTABLE_PARSE_FAILED", "Unclosed bounded loop")
        return output
    # Retain MTM's compatibility collection for complex shell constructs. Never
    # split a heredoc body or quoted string into newly invented commands.
    segment: list[str] = []
    for word in _words(command):
        if word in {"|", "||", "&", "&&", ";"}:
            _append_candidates(segment, depth, output, simple=False)
            segment = []
        else:
            segment.append(word)
    _append_candidates(segment, depth, output, simple=False)
    return output


def collect_executable_facts(
    invocation: ExecInvocation, workspace: Any, *, sandbox_path: str = DEFAULT_SANDBOX_PATH,
    read_only_roots: tuple[Path, ...] = (), forbidden_paths: tuple[Path, ...] = (),
) -> tuple[Any, ...]:
    root = workspace.root
    workdir = workspace.resolve_existing(invocation.workdir).path
    if not workdir.is_dir():
        raise invalid_argument("workdir must be a directory")
    roots = tuple(Path(path).resolve() for path in (*SYSTEM_ROOTS, *read_only_roots) if Path(path).exists())
    search_path = invocation.environment.get("PATH", sandbox_path)
    facts: list[Any] = []
    missing = []
    for index, requested in enumerate(invocation.candidates()):
        path = _resolve_executable(requested, root, workdir, search_path, roots, forbidden_paths)
        if path is None:
            missing.append(index)
            continue
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            raise _security("NATIVE_EXECUTABLE_NOT_EXECUTABLE", "Resolved command executable is not executable")
        facts.append((index, str(path), metadata.st_dev, metadata.st_ino, metadata.st_mode,
                      metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns))
    if missing:
        raise ReCTMError("NATIVE_EXECUTABLE_UNRESOLVED", "Command executable could not be resolved in the sandbox view.",
                         category="security", details={"unresolved_candidate_indexes": missing,
                         "recovery": {"automatic_retry": False, "side_effects": "none",
                                      "next_tool": "check_exec_environment"}})
    metadata = workdir.stat()
    return (str(workdir), metadata.st_dev, metadata.st_ino, metadata.st_mode, tuple(facts))


def _resolve_executable(requested: str, workspace: Path, workdir: Path, sandbox_path: str,
                        roots: tuple[Path, ...], forbidden: tuple[Path, ...]) -> Path | None:
    direct = "/" in requested
    values = [requested] if direct else [str(Path(entry) / requested) if entry else requested for entry in sandbox_path.split(":")]
    for index, value in enumerate(values):
        raw = Path(value)
        workspace_only = not raw.is_absolute() or raw == Path("/workspace") or raw.is_relative_to("/workspace")
        if raw.is_absolute() and (raw == Path("/workspace") or raw.is_relative_to("/workspace")):
            candidate = workspace / raw.relative_to("/workspace")
        else:
            candidate = raw if raw.is_absolute() else workdir / raw
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            continue
        except (OSError, RuntimeError) as exc:
            raise _security("NATIVE_EXECUTABLE_INSPECTION_FAILED", "An executable candidate could not be inspected") from exc
        if (workspace_only and not resolved.is_relative_to(workspace)
                or not workspace_only and not ((not direct and resolved.is_relative_to(workspace)) or any(resolved.is_relative_to(root) for root in roots))
                or any(resolved.is_relative_to(path) for path in forbidden)):
            raise _security("NATIVE_EXECUTABLE_PATH_DENIED", "Executable path is outside the visible Native sandbox")
        metadata = resolved.stat()
        if not direct and (not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111):
            continue
        return resolved
    return None
