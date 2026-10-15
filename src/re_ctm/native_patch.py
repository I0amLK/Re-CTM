"""Current Native patch syntax and bounded forward-only text matching.

The legacy ctm_compat evaluator remains pure and unchanged. All filesystem
mutation for this parser goes through the shared Native transaction engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import ReCTMError, invalid_argument

MAX_REQUEST_BYTES = 1_048_576
MAX_SOURCE_BYTES = 64 * 1024 * 1024


@dataclass(repr=False)
class PatchOperation:
    kind: str
    path: str
    add_content: str | None = None
    hunks: list[list[str]] = field(default_factory=list)
    move_to: str | None = None


def _failure(code: str, message: str, index: int = 0, lines: list[str] | None = None,
             cursor: int = 0, candidates: list[int] | None = None) -> ReCTMError:
    lines = lines or []
    start = max(0, cursor - 3)
    nearby = "\n".join(f"{i + 1}: {lines[i][:240]}"
                       for i in range(start, min(len(lines), start + 12)))
    return ReCTMError(code, message, category="validation", retryable=True, details={
        "hunk_index": index, "candidate_lines": [i + 1 for i in (candidates or [])],
        "nearby_text": nearby, "total_lines": len(lines),
    })


def parse_patch(patch: str) -> list[PatchOperation]:
    if not isinstance(patch, str):
        raise invalid_argument("patch must be a string")
    try:
        size = len(patch.encode("utf-8"))
    except UnicodeError as exc:
        raise invalid_argument("patch must be valid UTF-8") from exc
    if size > MAX_REQUEST_BYTES:
        raise _failure("PATCH_LIMIT", "Patch exceeds 1 MiB")
    lines = patch.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[-1]:
        lines.pop()
    if not lines or lines[0].strip() != "*** Begin Patch" or lines[-1].strip() != "*** End Patch":
        raise _failure("PATCH_FAILED", "Patch must use *** Begin Patch / *** End Patch envelope.")
    operations: list[PatchOperation] = []
    index = 1
    while index < len(lines) - 1:
        line = lines[index]
        if not line:
            index += 1
            continue
        if line.startswith("*** Add File: "):
            path = line[len("*** Add File: "):].strip()
            index += 1
            content = []
            while index < len(lines) - 1 and not lines[index].startswith("*** "):
                if not lines[index].startswith("+"):
                    raise _failure("PATCH_FAILED", "Add file lines must start with '+'.")
                content.append(lines[index][1:])
                index += 1
            operation = PatchOperation("add", path, add_content="\n".join(content) + "\n")
        elif line.startswith("*** Delete File: "):
            operation = PatchOperation("delete", line[len("*** Delete File: "):].strip())
            index += 1
        elif line.startswith("*** Update File: "):
            operation = PatchOperation("update", line[len("*** Update File: "):].strip())
            index += 1
            if index < len(lines) - 1 and lines[index].startswith("*** Move to: "):
                operation.move_to = lines[index][len("*** Move to: "):].strip()
                index += 1
            current: list[str] = []
            while index < len(lines) - 1 and (
                not lines[index].startswith("*** ") or lines[index] == "*** End of File"
            ):
                if lines[index].startswith("@@"):
                    if current:
                        operation.hunks.append(current)
                    current = [lines[index]]
                else:
                    current.append(lines[index])
                index += 1
            if current:
                operation.hunks.append(current)
            if len(operation.hunks) > 200:
                raise _failure("PATCH_LIMIT", "At most 200 hunks are allowed per file")
        else:
            raise _failure("PATCH_FAILED", "Unrecognized patch instruction")
        if not operation.path or operation.move_to == "":
            raise invalid_argument("Patch paths must be nonempty")
        operations.append(operation)
        if len(operations) > 100:
            raise _failure("PATCH_LIMIT", "At most 100 patch operations are allowed")
    if not operations:
        raise invalid_argument("Patch must contain at least one operation")
    return operations


@dataclass(repr=False)
class PatchUpdate:
    content: str
    changed_ranges: list[dict[str, int]]
    match_quality: str
    already_applied: bool
    additions: int
    removals: int


def _equal(left: str, right: str, grade: int) -> bool:
    if grade == 0:
        return left == right
    if grade == 1:
        return left.rstrip() == right.rstrip()
    return left.strip() == right.strip()


def _positions(lines: list[str], needle: list[str], cursor: int, eof: bool, grade: int) -> list[int]:
    if not needle or len(needle) > len(lines):
        return []
    last = len(lines) - len(needle)
    candidates = range(max(cursor, last), last + 1) if eof else range(cursor, last + 1)
    found = []
    for index in candidates:
        if all(_equal(lines[index + j], value, grade) for j, value in enumerate(needle)):
            found.append(index)
            if len(found) == 9:
                break
    return found


def apply_update(content: str, hunks: list[list[str]], path: str) -> PatchUpdate:
    source_bytes = len(content.encode("utf-8"))
    if source_bytes > MAX_SOURCE_BYTES or len(hunks) > 200:
        raise _failure("PATCH_LIMIT", "Patch text or hunk bound exceeded")
    crlf = "\r\n" in content
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    trailing = normalized.endswith("\n")
    lines = normalized.split("\n")
    if trailing or not normalized:
        lines.pop()
    cursor = 0
    placements: list[tuple[int, int, list[str]]] = []
    max_grade = 0
    work_remaining = 512 * 1024 * 1024
    for index, raw in enumerate(hunks):
        old: list[str] = []
        new: list[str] = []
        anchor = None
        eof = context = False
        for line in raw:
            if line.startswith("@@"):
                anchor = line[2:].strip() or None
            elif line == "*** End of File":
                eof = True
            elif not line or line[0] == " ":
                old.append(line[1:]); new.append(line[1:]); context = True
            elif line[0] == "-":
                old.append(line[1:])
            elif line[0] == "+":
                new.append(line[1:])
            else:
                raise _failure("PATCH_FAILED", "Update lines need a context/add/remove marker")
        span = max(len(old), len(new), 1)
        needle_bytes = sum(len(s.encode("utf-8")) for s in old + new)
        estimate = (source_bytes * span + needle_bytes * len(lines)) * 5
        if anchor is not None:
            estimate += (source_bytes + len(anchor.encode("utf-8")) * len(lines)) * 3
        if estimate > work_remaining:
            raise _failure("PATCH_LIMIT", "Patch matching exceeds its comparison budget; use smaller hunks or apply_changes")
        work_remaining -= estimate
        if anchor is not None:
            located_anchor = next(((i, grade) for grade in range(3)
                                   for i in range(cursor, len(lines)) if _equal(lines[i], anchor, grade)), None)
            if located_anchor is None:
                raise _failure("PATCH_CONTEXT_NOT_FOUND", f"Forward anchor not found in {path}", index, lines, cursor)
            cursor = located_anchor[0] + 1
            max_grade = max(max_grade, located_anchor[1])
        if not old:
            safe_repeat = len(new) >= 2 and any(s.strip() for s in new)
            grade = next((g for g in range(2) if safe_repeat and
                          len(_positions(lines, new, cursor, True, g)) == 1), None)
            if grade is None and new:
                placements.append((len(lines), len(lines), new))
            elif grade is not None:
                max_grade = max(max_grade, grade)
            cursor = len(lines)
            continue
        located = next(((found, grade) for grade in range(3)
                        if (found := _positions(lines, old, cursor, eof, grade))), None)
        if located is not None:
            found, grade = located
            if len(found) != 1:
                raise _failure("PATCH_CONTEXT_AMBIGUOUS", f"Patch context is ambiguous in {path}", index, lines, cursor, found)
            start, end = found[0], found[0] + len(old)
            cursor = end
            prefix = 0
            while prefix < min(end - start, len(new)) and lines[start + prefix] == new[prefix]:
                prefix += 1
            start += prefix
            new = new[prefix:]
            while start < end and new and lines[end - 1] == new[-1]:
                end -= 1
                new.pop()
            if start != end or new:
                placements.append((start, end, new))
            max_grade = max(max_grade, grade)
            continue
        if (context or len(new) >= 2) and any(s.strip() for s in new):
            repeated = next(((found, grade) for grade in range(2)
                             if len(found := _positions(lines, new, cursor, eof, grade)) == 1), None)
            if repeated is not None:
                found, grade = repeated
                cursor = found[0] + len(new)
                max_grade = max(max_grade, grade)
                continue
        raise _failure("PATCH_CONTEXT_NOT_FOUND", f"Patch context did not match in {path}", index, lines, cursor)
    ranges: list[dict[str, int]] = []
    added = removed = 0
    for start, end, new in placements:
        first = start + added + 1 - removed
        ranges.append({"start_line": first, "end_line": first + len(new) - 1,
                       "added_lines": len(new), "removed_lines": end - start})
        added += len(new)
        removed += end - start
    updated = list(lines)
    for start, end, new in reversed(placements):
        updated[start:end] = new
    text = "\n".join(updated)
    if updated and (trailing or not content):
        text += "\n"
    if crlf:
        text = text.replace("\n", "\r\n")
    if not placements:
        text = content
    return PatchUpdate(text, ranges, ("exact", "trailing_whitespace", "indentation")[max_grade],
                       not placements, added, removed)
