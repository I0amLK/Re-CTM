from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import ReCTMError


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


GENERATION_CHANNELS = frozenset(
    {
        "immediate_conclusions",
        "toy_examples",
        "counterexamples",
        "big_decisions",
        "subgoals",
        "proof_steps",
        "failed_paths",
        "verification_reports",
        "branch_states",
        "events",
    }
)
VERIFIER_CHANNELS = frozenset(
    {
        "statement_checks",
        "reference_checks",
        "verification_reports",
        "failed_checks",
        "events",
    }
)
BRANCH_CHANNELS = frozenset({"branch_notes", "proof_steps", "failed_paths", "events"})


class PrivateVault:
    """Logical-resource store that never accepts caller-provided filesystem paths."""

    def __init__(self, private_root: Path) -> None:
        self.private_root = private_root.resolve()
        self.runs_root = self.private_root / "runs"
        self.runs_root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def initialize_run(
        self,
        run_id: str,
        *,
        problem_tex: str,
        references: Iterable[Mapping[str, Any]] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        root = self.run_root(run_id)
        for relative in (
            "input",
            "references",
            "memory/generation",
            "memory/verifier",
            "branches",
            "snapshots",
            "join",
            "draft",
            "verification",
            "final",
            "debug/state",
        ):
            (root / relative).mkdir(parents=True, exist_ok=True, mode=0o700)
        problem_path = root / "input" / "problem.tex"
        _atomic_text(problem_path, problem_tex)
        manifest: list[dict[str, Any]] = []
        for index, reference in enumerate(references):
            name = _safe_reference_name(str(reference.get("name") or f"reference-{index + 1}.txt"))
            content = str(reference.get("content") or "")
            target = root / "references" / name
            _atomic_text(target, content)
            manifest.append(
                {
                    "name": name,
                    "sha256": _sha256_text(content),
                    "size": len(content.encode("utf-8")),
                    "source": str(reference.get("source") or "inline"),
                }
            )
        _atomic_json(root / "references" / "manifest.json", manifest)
        _atomic_json(root / "run-metadata.json", dict(metadata or {}))
        return {
            "run_root": str(root),
            "problem_sha256": _sha256_text(problem_tex),
            "reference_count": len(manifest),
        }

    def run_root(self, run_id: str) -> Path:
        safe = _require_safe_id(run_id, "run_id")
        root = (self.runs_root / safe).resolve()
        if not root.is_relative_to(self.runs_root.resolve()):
            raise ReCTMError(
                "VAULT_ESCAPE",
                "Run id resolves outside the private vault.",
                category="security",
            )
        return root

    def read_problem(self, run_id: str) -> str:
        return self._read_text(self.run_root(run_id) / "input" / "problem.tex")

    def read_references_manifest(self, run_id: str) -> list[dict[str, Any]]:
        payload = self._read_json(self.run_root(run_id) / "references" / "manifest.json")
        return payload if isinstance(payload, list) else []

    def read_reference(self, run_id: str, name: str) -> str:
        safe = _safe_reference_name(name)
        return self._read_text(self.run_root(run_id) / "references" / safe)

    def append_generation_memory(
        self,
        run_id: str,
        channel: str,
        record: Mapping[str, Any],
    ) -> Path:
        if channel not in GENERATION_CHANNELS:
            raise ReCTMError(
                "UNKNOWN_MEMORY_CHANNEL",
                f"Unknown generation channel: {channel}",
                category="validation",
            )
        target = self.run_root(run_id) / "memory" / "generation" / f"{channel}.jsonl"
        _append_jsonl(target, dict(record))
        return target

    def read_generation_memory(self, run_id: str, channel: str) -> list[dict[str, Any]]:
        if channel not in GENERATION_CHANNELS:
            raise ReCTMError("UNKNOWN_MEMORY_CHANNEL", f"Unknown channel: {channel}", category="validation")
        return _read_jsonl(
            self.run_root(run_id) / "memory" / "generation" / f"{channel}.jsonl"
        )

    def append_verifier_memory(
        self,
        run_id: str,
        channel: str,
        record: Mapping[str, Any],
    ) -> Path:
        if channel not in VERIFIER_CHANNELS:
            raise ReCTMError(
                "UNKNOWN_MEMORY_CHANNEL",
                f"Unknown verifier channel: {channel}",
                category="validation",
            )
        target = self.run_root(run_id) / "memory" / "verifier" / f"{channel}.jsonl"
        _append_jsonl(target, dict(record))
        return target

    def read_verifier_memory(self, run_id: str, channel: str) -> list[dict[str, Any]]:
        if channel not in VERIFIER_CHANNELS:
            raise ReCTMError("UNKNOWN_MEMORY_CHANNEL", f"Unknown channel: {channel}", category="validation")
        return _read_jsonl(
            self.run_root(run_id) / "memory" / "verifier" / f"{channel}.jsonl"
        )

    def append_branch_memory(
        self,
        run_id: str,
        branch_id: str,
        channel: str,
        record: Mapping[str, Any],
    ) -> Path:
        if channel not in BRANCH_CHANNELS:
            raise ReCTMError("UNKNOWN_MEMORY_CHANNEL", f"Unknown branch channel: {channel}", category="validation")
        branch = _require_safe_id(branch_id, "branch_id")
        target = self.run_root(run_id) / "branches" / branch / "memory" / f"{channel}.jsonl"
        _append_jsonl(target, dict(record))
        return target

    def read_branch_memory(
        self,
        run_id: str,
        branch_id: str,
        channel: str,
    ) -> list[dict[str, Any]]:
        if channel not in BRANCH_CHANNELS:
            raise ReCTMError("UNKNOWN_MEMORY_CHANNEL", f"Unknown branch channel: {channel}", category="validation")
        branch = _require_safe_id(branch_id, "branch_id")
        return _read_jsonl(
            self.run_root(run_id) / "branches" / branch / "memory" / f"{channel}.jsonl"
        )

    def create_snapshot(
        self,
        run_id: str,
        snapshot_id: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        snapshot = _require_safe_id(snapshot_id, "snapshot_id")
        target = self.run_root(run_id) / "snapshots" / f"{snapshot}.json"
        if target.exists():
            raise ReCTMError(
                "SNAPSHOT_EXISTS",
                f"Snapshot already exists: {snapshot_id}",
                category="conflict",
            )
        serialized = json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        _atomic_text(target, serialized)
        try:
            target.chmod(0o400)
        except OSError:
            pass
        return {
            "snapshot_id": snapshot_id,
            "sha256": _sha256_text(serialized),
            "path": str(target),
        }

    def read_snapshot(self, run_id: str, snapshot_id: str) -> dict[str, Any]:
        snapshot = _require_safe_id(snapshot_id, "snapshot_id")
        payload = self._read_json(
            self.run_root(run_id) / "snapshots" / f"{snapshot}.json"
        )
        if not isinstance(payload, dict):
            raise ReCTMError("INVALID_SNAPSHOT", "Snapshot must contain an object.", category="validation")
        return payload

    def initialize_branch(
        self,
        run_id: str,
        branch_id: str,
        payload: Mapping[str, Any],
    ) -> Path:
        branch = _require_safe_id(branch_id, "branch_id")
        root = self.run_root(run_id) / "branches" / branch
        (root / "memory").mkdir(parents=True, exist_ok=True, mode=0o700)
        _atomic_json(root / "assignment.json", dict(payload))
        return root

    def write_branch_result(
        self,
        run_id: str,
        branch_id: str,
        payload: Mapping[str, Any],
    ) -> Path:
        branch = _require_safe_id(branch_id, "branch_id")
        target = self.run_root(run_id) / "branches" / branch / "result.json"
        if target.exists():
            raise ReCTMError(
                "BRANCH_ALREADY_COMMITTED",
                f"Branch result already exists: {branch_id}",
                category="conflict",
            )
        _atomic_json(target, dict(payload))
        try:
            target.chmod(0o400)
        except OSError:
            pass
        return target

    def read_branch_result(self, run_id: str, branch_id: str) -> dict[str, Any]:
        branch = _require_safe_id(branch_id, "branch_id")
        payload = self._read_json(self.run_root(run_id) / "branches" / branch / "result.json")
        if not isinstance(payload, dict):
            raise ReCTMError("INVALID_BRANCH_RESULT", "Branch result must be an object.", category="validation")
        return payload

    def write_join_result(self, run_id: str, payload: Mapping[str, Any]) -> Path:
        target = self.run_root(run_id) / "join" / "result.json"
        _atomic_json(target, dict(payload))
        return target

    def read_join_result(self, run_id: str) -> dict[str, Any]:
        payload = self._read_json(self.run_root(run_id) / "join" / "result.json")
        return payload if isinstance(payload, dict) else {}

    def write_proof(self, run_id: str, content: str) -> Path:
        target = self.run_root(run_id) / "draft" / "proof.tex"
        _atomic_text(target, content)
        return target

    def read_proof(self, run_id: str) -> str:
        return self._read_text(self.run_root(run_id) / "draft" / "proof.tex")

    def write_verification_report(self, run_id: str, payload: Mapping[str, Any]) -> Path:
        target = self.run_root(run_id) / "verification" / "verification.json"
        _atomic_json(target, dict(payload))
        return target

    def read_verification_report(self, run_id: str) -> dict[str, Any]:
        payload = self._read_json(
            self.run_root(run_id) / "verification" / "verification.json"
        )
        return payload if isinstance(payload, dict) else {}

    def finalize_proof(self, run_id: str) -> Path:
        source = self.run_root(run_id) / "draft" / "proof.tex"
        if not source.is_file():
            raise ReCTMError("PROOF_NOT_FOUND", "Draft proof.tex does not exist.", category="not_found")
        target = self.run_root(run_id) / "final" / "proof_verified.tex"
        _atomic_text(target, source.read_text(encoding="utf-8"))
        try:
            target.chmod(0o400)
        except OSError:
            pass
        return target

    def read_final_proof(self, run_id: str) -> str:
        return self._read_text(
            self.run_root(run_id) / "final" / "proof_verified.tex"
        )

    def search_records(
        self,
        records: Iterable[Mapping[str, Any]],
        query: str,
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        tokens = {token.lower() for token in re.findall(r"[A-Za-z0-9_]+", query)}
        if not tokens:
            return []
        matches: list[tuple[int, dict[str, Any]]] = []
        for record in records:
            payload = dict(record)
            text = json.dumps(payload, ensure_ascii=False).lower()
            score = sum(text.count(token) for token in tokens)
            if score:
                matches.append((score, payload))
        matches.sort(key=lambda item: -item[0])
        return [{"score": score, "record": payload} for score, payload in matches[:limit]]

    def _read_text(self, path: Path) -> str:
        if not path.is_file():
            raise ReCTMError(
                "RESOURCE_NOT_FOUND",
                f"Private resource not found: {path.name}",
                category="not_found",
            )
        return path.read_text(encoding="utf-8")

    def _read_json(self, path: Path) -> Any:
        return json.loads(self._read_text(path))


def _require_safe_id(value: str, label: str) -> str:
    text = str(value).strip()
    if not _SAFE_ID.fullmatch(text):
        raise ReCTMError(
            "INVALID_IDENTIFIER",
            f"Invalid {label}.",
            category="validation",
            details={label: text},
        )
    return text


def _safe_reference_name(value: str) -> str:
    name = Path(value).name
    if name != value or not name or name in {".", "..", "manifest.json"}:
        raise ReCTMError(
            "INVALID_REFERENCE_NAME",
            "Reference names must be simple filenames.",
            category="validation",
            details={"name": value},
        )
    return name


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    temp.write_text(content, encoding="utf-8")
    os.replace(temp, path)


def _atomic_json(path: Path, payload: Any) -> None:
    _atomic_text(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(payload), ensure_ascii=False, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                records.append(payload)
    return records


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
