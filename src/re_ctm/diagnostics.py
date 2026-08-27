from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .debug import redact, utc_now
from .errors import ReCTMError


def build_debug_bundle(data_root: Path, run_id: str) -> dict[str, Any]:
    """Build a content-minimized, redacted diagnostic bundle for manual review."""

    root = data_root.expanduser().resolve()
    private_root = root / "private"
    run_root = private_root / "runs" / run_id
    if not run_root.is_dir():
        raise ReCTMError(
            "RUN_NOT_FOUND",
            f"Private run directory was not found: {run_id}",
            category="not_found",
        )
    database = private_root / "state.sqlite3"
    if not database.is_file():
        raise ReCTMError(
            "STATE_STORE_NOT_FOUND",
            "The Re-CTM state store was not found.",
            category="not_found",
        )

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        run = _fetch_one(connection, "SELECT * FROM runs WHERE run_id = ?", (run_id,))
        if run is None:
            raise ReCTMError(
                "RUN_NOT_FOUND",
                f"Run was not found in the state store: {run_id}",
                category="not_found",
            )
        domains = _fetch_all(
            connection,
            "SELECT * FROM domains WHERE run_id = ? ORDER BY order_index, created_at",
            (run_id,),
        )
        branches = _fetch_all(
            connection,
            "SELECT * FROM branches WHERE run_id = ? ORDER BY order_index",
            (run_id,),
        )
        transitions = _fetch_all(
            connection,
            "SELECT * FROM transitions WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        )
        capability_summary = _fetch_one(
            connection,
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END) AS revoked,
                SUM(CASE WHEN revoked = 0 THEN 1 ELSE 0 END) AS active
            FROM capabilities WHERE run_id = ?
            """,
            (run_id,),
        )
    finally:
        connection.close()

    events = _read_jsonl(run_root / "debug" / "events.jsonl", maximum=20_000)
    last_error = _read_json(run_root / "debug" / "last_error.json")
    manual_manifest = _read_json(
        run_root / "debug" / "manual-validation-manifest.json"
    )
    bundle = {
        "schema_version": "1.0.0",
        "generated_at": utc_now(),
        "run": _normalize_row(run),
        "domains": [_normalize_row(item) for item in domains],
        "branches": [_normalize_row(item) for item in branches],
        "transitions": [_normalize_row(item) for item in transitions],
        "capabilities": {
            "total": int((capability_summary or {}).get("total") or 0),
            "revoked": int((capability_summary or {}).get("revoked") or 0),
            "active": int((capability_summary or {}).get("active") or 0),
            "note": "Capability nonces and signed handles are intentionally omitted.",
        },
        "events": events,
        "last_error": last_error,
        "manual_validation_manifest": manual_manifest,
        "file_manifest": _file_manifest(run_root),
        "redaction": {
            "raw_oauth_secrets_included": False,
            "raw_capability_handles_included": False,
            "problem_or_proof_contents_included": False,
            "private_file_contents_included": False,
        },
        "validation_boundary": {
            "locally_validated": "Deterministic authorization, persistence, state-machine, protocol, and static checks only.",
            "still_manual": [
                "real webpage OAuth/MCP compatibility",
                "target-PC hard isolation under native dangerous mode",
                "external retrieval and mathematical reasoning quality",
                "real target LaTeX compilation",
                "end-to-end 95-percent functional-equivalence acceptance",
            ],
        },
    }
    return redact(bundle)


def write_debug_bundle(data_root: Path, run_id: str, output: Path) -> Path:
    payload = build_debug_bundle(data_root, run_id)
    target = output.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(target)
    return target


def _fetch_one(
    connection: sqlite3.Connection,
    query: str,
    arguments: tuple[Any, ...],
) -> dict[str, Any] | None:
    row = connection.execute(query, arguments).fetchone()
    return None if row is None else dict(row)


def _fetch_all(
    connection: sqlite3.Connection,
    query: str,
    arguments: tuple[Any, ...],
) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, arguments).fetchall()]


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    payload = dict(row)
    for key in list(payload):
        if key.endswith("_json"):
            raw = payload.pop(key)
            normalized_key = key.removesuffix("_json")
            try:
                payload[normalized_key] = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload[normalized_key] = {"parse_error": True}
    for key in ("sealed", "revoked", "latex_passed", "consumed"):
        if key in payload:
            payload[key] = bool(payload[key])
    if "nonce" in payload:
        payload["nonce_fingerprint"] = _hash_text(str(payload.pop("nonce")))[:12]
    return payload


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"read_error": True, "file": path.name}


def _read_jsonl(path: Path, *, maximum: int) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if len(records) >= maximum:
                    records.append(
                        {
                            "event_type": "diagnostics.truncated",
                            "reason": f"event count exceeded {maximum}",
                        }
                    )
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    records.append(
                        {"event_type": "diagnostics.parse_error", "line_sha256": _hash_text(line)}
                    )
                    continue
                if isinstance(value, dict):
                    records.append(value)
    except OSError:
        return [{"event_type": "diagnostics.read_error", "file": path.name}]
    return records


def _file_manifest(root: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            size = path.stat().st_size
            digest = _hash_file(path)
        except OSError:
            continue
        result.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": size,
                "sha256": digest,
                "content_included": False,
            }
        )
    return result


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
