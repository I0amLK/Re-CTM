"""Canonical Re-CTM Native tool declarations, adapted from MTM's v11 contract.

The declaration table is the sole authority for public Native names, annotations,
argument schemas and tool-specific result fields. It has no runtime dependency on
MTM source files or a historical catalog snapshot.
"""
from __future__ import annotations

from typing import Any

TOOL_CONTRACT_VERSION = "mtm-tools-v11"


def _object(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def _text() -> dict[str, Any]:
    return {"type": "string"}


def _nonempty() -> dict[str, Any]:
    return {"type": "string", "minLength": 1}


def _strings() -> dict[str, Any]:
    return {"type": "array", "items": _text()}


def _integer(minimum: int, maximum: int, default: int) -> dict[str, Any]:
    return {"type": "integer", "minimum": minimum, "maximum": maximum, "default": default}


def _boolean(default: bool) -> dict[str, Any]:
    return {"type": "boolean", "default": default}


def _choice(*values: str) -> dict[str, Any]:
    return {"type": "string", "enum": list(values)}


def _output_options(properties: dict[str, Any]) -> dict[str, Any]:
    return {**properties, "max_output_bytes": _integer(1, 1_048_576, 65_536),
            "preview_bytes": _integer(1, 1_048_576, 4096), "verbosity": _choice("summary", "preview", "full")}


# name, title, description, read-only, destructive, open-world, idempotent.
_METADATA = (
    (
        'server_info',
        'Server info',
        'Read Re-CTM identity, workspace, tool contract version, workflow protocol and Native policy. The returned workspace is an informational host path, not a Native path argument: filesystem path, repo_path, workdir and cwd inputs are workspace-relative unless a tool explicitly says otherwise. Use . for the workspace root. This does not create a run or authorize an operation.',
        True,
        False,
        False,
        True,
    ),
    (
        'check_exec_environment',
        'Check exec environment',
        'Read the actual Native sandbox PATH, exposed toolchain roots and execution capabilities before choosing a program. Do not assume the host login shell and sandbox are identical.',
        True,
        False,
        False,
        True,
    ),
    (
        'read_file',
        'Read file',
        'Read lossless UTF-8 pages of a workspace file up to 64 MiB. path must be workspace-relative; use README.md or nested/file.txt, not the absolute host path shown by server_info.workspace. Lines are one-based; end_line is an inclusive range limit, max_lines is a page limit. Continue using next_action verbatim: a long line may require the same start_line with a nonzero line_byte_offset. expected_sha256 prevents mixing changed contents. truncated means the requested range has more data. Use view_image for images.',
        True,
        False,
        False,
        True,
    ),
    (
        'list_dir',
        'List directory',
        'List entries of a workspace directory, not a file. Use read_file or search_text for a known file. Hidden and commonly generated entries are excluded unless requested.',
        True,
        False,
        False,
        True,
    ),
    (
        'list_files',
        'List files',
        'List files under a workspace directory with optional glob filters. path is a directory; patterns are relative to it. For a single known file use search_text or read_file.',
        True,
        False,
        False,
        True,
    ),
    (
        'search_text',
        'Search text',
        'Search UTF-8 text in a workspace file or directory. An explicit file target searches only that file, never its siblings. glob/include_globs and exclude_globs restrict the selection. Results and context are bounded.',
        True,
        False,
        False,
        True,
    ),
    (
        'apply_patch',
        'Apply patch',
        'Validate and apply a workspace patch envelope. Use *** Begin Patch, file operations and *** End Patch. dry_run validates without writing and does not grant permission. On a stale baseline read the affected files before preparing a new patch.',
        False,
        True,
        False,
        False,
    ),
    (
        'apply_changes',
        'Apply structured changes',
        'Atomically apply revision-bound create/write/edit/delete/move/copy changes. Read revision from read_file; existing sources require that exact revision. create and move/copy destinations require absence. Each resolved path appears once. Line edits address original one-based LF-delimited lines, matching read_file; bare CR is content. Replacement content contains whole lines. dry_run writes nothing. Optional idempotency_key is bounded, caller-scoped and in-memory only; replay support is limited to this server lifetime and retained results. An unknown outcome never permits blind retry.',
        False,
        True,
        False,
        False,
    ),
    (
        'exec_command',
        'Execute command',
        'Run a bounded Native command. Supply exactly one of argv (literal program and arguments) or cmd (non-login /bin/sh -c, no profile-based PATH reset). Prefer argv for a single program. workdir/cwd must be workspace-relative; use . for the workspace root and never pass the absolute host path from server_info.workspace. Set workdir and any env.PATH explicitly; executable checks use that same PATH. Poll command_id with write_stdin and page output_ref with read_output; never restart just to obtain output. A transport failure has unknown outcome. For unresolved executables inspect check_exec_environment and correct the request, not permissions.',
        False,
        True,
        True,
        False,
    ),
    (
        'write_stdin',
        'Poll or write stdin',
        'Poll an existing command_id or send stdin. Empty chars only polls; nonempty chars sends input and is not safe to replay after an uncertain transport failure. Use the returned command_id, never a guessed process identifier.',
        False,
        False,
        False,
        False,
    ),
    (
        'kill_command',
        'Terminate command',
        'Terminate a server-managed command_id using TERM, INT or KILL. This affects the command and its managed descendants, not arbitrary host processes. Check the returned lifecycle outcome.',
        False,
        True,
        False,
        False,
    ),
    (
        'read_output',
        'Read retained output',
        'Read a bounded page of an output_ref returned by exec_command/write_stdin. Use next_offset where present; head/tail retention can evict a middle range, reported as evicted_gap_bytes. This never reruns a command.',
        True,
        False,
        False,
        True,
    ),
    (
        'git_status',
        'Git status',
        'Read Git working-tree status. repo_path selects a repository directory relative to the workspace; legacy path selects it only when repo_path is omitted. Discovery never climbs outside the workspace. The result reports the actual repo_path.',
        True,
        False,
        False,
        True,
    ),
    (
        'git_diff',
        'Git diff',
        'Read bounded staged/unstaged diffs. repo_path selects the repository directory relative to the workspace (default .). path/paths are literal file filters relative to the selected repository, not repository selectors or glob patterns. The result reports the actual repo_path.',
        True,
        False,
        False,
        True,
    ),
    (
        'git_log',
        'Git log',
        'Read bounded commit history. repo_path selects the repository directory relative to the workspace (default .); path is a literal file/directory filter relative to that repository, including deleted files. The result reports the actual repo_path.',
        True,
        False,
        False,
        True,
    ),
    (
        'git_show',
        'Git show',
        'Read a revision and optional file diffs. repo_path selects a repository relative to the workspace (default .); path/paths are literal file filters relative to it. External diff and text conversion helpers are disabled.',
        True,
        False,
        False,
        True,
    ),
    (
        'git_blame',
        'Git blame',
        'Read paged blame metadata. repo_path selects a repository relative to the workspace (default .); path names a file relative to that repository. Lines start at one. Use next_action to preserve the repository, revision and requested range on subsequent pages.',
        True,
        False,
        False,
        True,
    ),
    (
        'request_permissions',
        'Native permission compatibility',
        'Report the fixed dangerous-mode compatibility response. This does not create a consent request or grant ledger, change policy, execute an operation, or grant workflow/project authority. Legacy request fields remain accepted for compatibility.',
        False,
        False,
        False,
        False,
    ),
    (
        'view_image',
        'View image',
        'Return a bounded workspace image as MCP image content. Use the actual workspace path; this tool does not fetch external images.',
        True,
        False,
        False,
        True,
    ),
)

_IDEMPOTENCY_KEY = {"type": "string", "minLength": 1, "maxLength": 128}
_INPUT_SCHEMAS = {
    "server_info": _object({}),
    "check_exec_environment": _object({}),
    "read_file": _object({
        "path": {"type": "string", "minLength": 1, "description": "Workspace-relative file path, for example README.md or nested/file.txt. Absolute host paths, including paths formed from server_info.workspace, are rejected."},
        "encoding": {"type": "string", "enum": ["utf-8"], "default": "utf-8"},
        "start_line": {"type": "integer", "minimum": 1, "default": 1},
        "end_line": {"type": "integer", "minimum": 1},
        "max_lines": {"type": "integer", "minimum": 1, "default": 500},
        "line_byte_offset": _integer(0, 67_108_864, 0),
        "expected_sha256": {"type": "string", "pattern": "[0-9a-fA-F]{64}"},
        "max_bytes": _integer(1, 1_048_576, 131_072),
    }, ("path",)),
    "list_dir": _object({
        "path": {"type": "string", "default": "."}, "recursive": _boolean(False),
        "include_hidden": _boolean(False), "include_ignored": _boolean(False),
        "max_depth": _integer(1, 20, 1), "max_entries": _integer(1, 10_000, 1000),
        "sort": {"type": "string", "enum": ["name", "type", "modified"], "default": "name"},
    }),
    "list_files": _object({
        "path": {"type": "string", "default": "."}, "patterns": _strings(), "glob": _text(),
        "exclude_patterns": _strings(), "include_hidden": _boolean(False), "include_ignored": _boolean(False),
        "max_results": _integer(1, 50_000, 5000),
        "sort": {"type": "string", "enum": ["path", "modified"], "default": "path"},
    }),
    "search_text": _object({
        "path": {"type": "string", "default": ".", "description": "Workspace file or directory."},
        "query": _nonempty(), "regex": _boolean(False), "case_sensitive": _boolean(False),
        "include_globs": _strings(), "exclude_globs": _strings(), "glob": _text(),
        "context_lines": _integer(0, 5, 0), "max_results": _integer(1, 10_000, 1000),
        "max_preview_bytes": _integer(80, 4096, 512),
    }, ("query",)),
    "apply_patch": _object({
        "patch": _nonempty(), "dry_run": _boolean(False), "idempotency_key": dict(_IDEMPOTENCY_KEY),
    }, ("patch",)),
    "apply_changes": _object({
        "changes": {"type": "array", "minItems": 1, "maxItems": 100, "items": _object({
            "action": _choice("create", "write", "edit", "delete", "move", "copy"),
            "path": _nonempty(), "content": _text(), "destination": _nonempty(),
            "revision": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "edits": {"type": "array", "minItems": 1, "maxItems": 200, "items": _object({
                "op": _choice("replace", "delete", "insert_after", "insert_before"),
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
                "line": {"type": "integer", "minimum": 0}, "content": _text(),
            }, ("op",))},
        }, ("action", "path"))},
        "dry_run": _boolean(False), "idempotency_key": dict(_IDEMPOTENCY_KEY),
    }, ("changes",)),
    "exec_command": {
        **_object(_output_options({
            "cmd": _nonempty(),
            "argv": {"type": "array", "minItems": 1, "items": _text(), "prefixItems": [_nonempty()],
                     "description": "Literal executable and arguments, without a shell. Arguments may be empty except argv[0], which the runtime validates."},
            "workdir": {"type": "string", "default": ".", "description": "Workspace-relative working directory. Use . for the workspace root. Do not pass the absolute host path reported by server_info.workspace."},
            "cwd": {"type": "string", "description": "Legacy alias for workdir; when supplied it is also workspace-relative. Use . for the workspace root, never an absolute host path."},
            "env": {"type": "object", "additionalProperties": {"type": "string"}, "default": {}},
            "stdin": {"type": "string", "default": ""}, "tty": _boolean(False),
            "timeout_ms": _integer(1, 600_000, 300_000), "yield_time_ms": _integer(0, 30_000, 10_000),
        })),
        "oneOf": [{"required": ["cmd"]}, {"required": ["argv"]}],
    },
    "write_stdin": _object(_output_options({
        "command_id": _nonempty(), "chars": {"type": "string", "default": ""},
        "yield_time_ms": _integer(0, 30_000, 10_000),
    }), ("command_id",)),
    "kill_command": _object(_output_options({
        "command_id": _nonempty(), "signal": {"type": "string", "enum": ["TERM", "KILL", "INT"], "default": "TERM"},
        "wait_ms": _integer(0, 30_000, 5000), "kill_wait_ms": _integer(0, 30_000, 2000),
    }), ("command_id",)),
    "read_output": _object({
        "output_ref": _nonempty(), "stream": _choice("stdout", "stderr"),
        "offset": {"type": "integer", "minimum": 0, "default": 0}, "limit": _integer(1, 1_048_576, 4096),
    }, ("output_ref",)),
    "git_status": _object({
        "repo_path": _nonempty(), "path": {"type": "string", "default": "."},
        "include_untracked": _boolean(True), "max_entries": _integer(1, 10_000, 1000),
    }),
    "git_diff": _object({
        "repo_path": _nonempty(), "path": _text(), "paths": _strings(),
        "staged": _boolean(False), "unstaged": _boolean(True), "include_untracked": _boolean(True),
        "context_lines": _integer(0, 20, 3), "max_bytes": _integer(1, 1_048_576, 262_144),
    }),
    "git_log": _object({
        "repo_path": _nonempty(), "path": {"type": "string", "default": "."},
        "paths": _strings(),
        "ref": {"type": "string", "default": "HEAD"},
        "max_count": _integer(1, 100, 20), "skip": _integer(0, 10_000, 0),
    }),
    "git_show": _object({
        "repo_path": _nonempty(), "rev": {"type": "string", "default": "HEAD"},
        "path": _text(), "paths": _strings(), "include_diff": _boolean(True),
        "context_lines": _integer(0, 20, 3), "max_bytes": _integer(1, 1_048_576, 262_144),
    }),
    "git_blame": _object({
        "repo_path": _nonempty(), "path": _nonempty(), "rev": _text(),
        "start_line": {"type": "integer", "minimum": 1, "default": 1},
        "end_line": {"type": "integer", "minimum": 1}, "max_lines": _integer(1, 1000, 200),
    }, ("path",)),
    "request_permissions": _object({
        "tool_name": _choice("exec_command", "apply_patch"),
        "permission": _choice("network", "destructive_command", "long_timeout", "sensitive_env", "shell_expansion",
                              "inline_script", "privileged_executable", "write_generated_or_ignored"),
        "reason": _nonempty(), "arguments": {"type": "object", "additionalProperties": True},
        "scope": {"type": "string", "enum": ["once", "session"], "default": "once"},
        "ttl_seconds": _integer(1, 3600, 300),
    }, ("tool_name", "permission", "reason", "arguments")),
    "view_image": _object({
        "path": _nonempty(), "auto_resize": _boolean(True), "max_bytes": _integer(1024, 10_485_760, 5_242_880),
        "max_width": _integer(1, 10_000, 2000), "max_height": _integer(1, 10_000, 2000),
    }, ("path",)),
}


def _output_properties(name: str) -> dict[str, Any]:
    # Lists encode fields of one type, not success-time required fields. Errors
    # keep the common envelope; runtime extension fields remain valid.
    fields = {
        "server_info": {
            "string": "server version workspace tool_contract_version", "integer": "tool_count native_tool_count rethlas_tool_count",
            "array": "tools", "object": "output_retention workspace_mutation_policy",
        },
        "check_exec_environment": {
            "string": "native_mode permission_mode native_exec_backend",
            "boolean": "private_vault_visible network_allowed", "array": "warnings",
        },
        "read_file": {
            "string": "path content revision sha256", "integer": "start_line end_line total_lines total_bytes line_byte_offset",
            "boolean": "truncated",
        },
        "list_dir": {"string": "path", "array": "entries", "boolean": "truncated"},
        "list_files": {"string": "path", "array": "files", "boolean": "truncated"},
        "search_text": {"array": "matches", "integer": "total_matches", "boolean": "truncated"},
        "apply_patch": {
            "boolean": "clean dry_run already_applied idempotent_replay", "string": "summary",
            "array": "affected_files warnings", "integer": "additions removals",
        },
        "exec_command": {
            "string": "command_id status stdout stderr summary", "boolean": "timed_out",
            "object": "output_refs", "array": "warnings",
        },
        "read_output": {
            "string": "command_id output_ref stream content operation_outcome",
            "integer": "offset head_retained_bytes evicted_gap_bytes total_stream_bytes",
        },
        "git_status": {"boolean": "is_repo clean truncated", "string": "repo_path head", "array": "entries"},
        "git_diff": {"string": "repo_path diff", "array": "files warnings", "boolean": "truncated"},
        "git_log": {"boolean": "is_repo truncated", "string": "repo_path", "array": "commits"},
        "git_show": {"boolean": "is_repo truncated", "string": "repo_path content", "array": "files"},
        "git_blame": {"string": "repo_path path", "array": "lines", "boolean": "truncated"},
        "request_permissions": {"string": "status grant_id", "object": "constraints", "array": "warnings"},
        "view_image": {"string": "path mime_type", "integer": "bytes", "boolean": "resized", "object": "original", "array": "warnings"},
    }
    kind = {"apply_changes": "apply_patch", "write_stdin": "exec_command", "kill_command": "exec_command"}.get(name, name)
    result = {key: {"type": data_type} for data_type, keys in fields[kind].items() for key in keys.split()}
    if kind in {"apply_patch", "read_file"}:
        result["revision_algorithm"] = _choice("sha256")
    if kind == "read_file":
        result.update({"next_start_line": {"type": ["integer", "null"]},
                       "next_line_byte_offset": {"type": ["integer", "null"]}, "next_action": {"type": ["object", "null"]}})
    if kind == "exec_command":
        result.update({"exit_code": {"type": ["integer", "null"]}, "signal": {"type": ["string", "null"]},
                       "operation_outcome": _choice("running", "exited_0", "exited_nonzero", "timeout", "signal", "spawn_error")})
    if kind == "read_output":
        result["next_offset"] = {"type": ["integer", "null"]}
    if kind == "git_status":
        result["branch"] = {"type": ["string", "null"]}
    if kind == "git_blame":
        result["next_action"] = {"type": ["object", "null"]}
    if kind == "request_permissions":
        result["expires_at"] = {"type": ["string", "integer", "null"]}
    if kind == "view_image":
        result.update({"width": {"type": ["integer", "null"]}, "height": {"type": ["integer", "null"]}})
    return result


def _output_schema(name: str) -> dict[str, Any]:
    return {
        "type": "object", "required": ["ok"], "additionalProperties": True,
        "properties": {
            "ok": {"type": "boolean"},
            "error": {
                "type": "object", "additionalProperties": True,
                "required": ["code", "message", "category", "retryable", "details"],
                "properties": {"code": _text(), "message": _text(), "category": _text(),
                               "retryable": {"type": "boolean"}, "details": {"type": "object", "additionalProperties": True}},
            },
            **_output_properties(name),
        },
    }


NATIVE_TOOL_DECLARATIONS: list[dict[str, Any]] = [
    {
        "name": name, "title": title, "description": description,
        "inputSchema": _INPUT_SCHEMAS[name], "outputSchema": _output_schema(name),
        "annotations": {"title": title, "readOnlyHint": read_only, "destructiveHint": destructive,
                        "openWorldHint": open_world, "idempotentHint": idempotent},
    }
    for name, title, description, read_only, destructive, open_world, idempotent in _METADATA
]
NATIVE_TOOL_NAMES: tuple[str, ...] = tuple(item["name"] for item in NATIVE_TOOL_DECLARATIONS)
CTM_NATIVE_TOOL_NAMES = NATIVE_TOOL_NAMES
