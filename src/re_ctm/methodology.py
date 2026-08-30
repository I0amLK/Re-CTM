from __future__ import annotations

import copy
import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

from .enums import WorkflowState
from .errors import ReCTMError


@lru_cache(maxsize=1)
def _catalog() -> dict[str, Any]:
    resource = files("re_ctm").joinpath("resources/methodology.json")
    payload = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("tasks"), dict):
        raise ReCTMError(
            "METHODOLOGY_INVALID",
            "Embedded methodology resource is invalid.",
            category="internal",
        )
    for state_name, raw_task in payload["tasks"].items():
        if not isinstance(raw_task, dict):
            raise _invalid_methodology_task(state_name, "task must be a JSON object")
        if not isinstance(raw_task.get("commit_action"), str) or not raw_task["commit_action"]:
            raise _invalid_methodology_task(state_name, "commit_action is required")
        if not isinstance(raw_task.get("write_contract"), list):
            raise _invalid_methodology_task(state_name, "write_contract must be an array")
        if not isinstance(raw_task.get("commit_payload_schema"), dict):
            raise _invalid_methodology_task(state_name, "commit_payload_schema must be an object")
        if not any(
            key in raw_task
            for key in ("minimal_submission", "minimal_submission_template", "submission_examples")
        ):
            raise _invalid_methodology_task(state_name, "a submission example or template is required")
    return payload


def _invalid_methodology_task(state_name: Any, reason: str) -> ReCTMError:
    return ReCTMError(
        "METHODOLOGY_INVALID",
        "Embedded methodology task contract is invalid.",
        category="internal",
        details={"state": str(state_name), "reason": reason},
    )


def task_for_state(state: WorkflowState) -> dict[str, Any]:
    task = _catalog()["tasks"].get(state.value)
    if not isinstance(task, dict):
        raise ReCTMError(
            "NO_MODEL_TASK",
            f"Workflow state has no model task: {state.value}",
            category="validation",
            details={"state": state.value},
        )
    result = copy.deepcopy(task)
    result["step_protocol"] = {
        "tool": "rethlas_step",
        "use_current_envelope_fields": ["run_id", "capability"],
        "writes": (
            "Follow write_contract exactly. Each writes[] entry is one logical record; "
            "memory records are JSON objects unless that resource's content_schema says otherwise. "
            "Do not batch several memory records into one array-valued content field."
        ),
        "action": "Use commit_action exactly as returned by this task.",
        "payload": (
            "Follow commit_payload_schema exactly. Use {} when the schema has no required fields; "
            "do not echo logical-write content into commit payload unless the schema explicitly asks for it."
        ),
        "recoverable_correction": (
            "If submission.recoverable is true, continue with the fresh capability returned in the same response. "
            "Successful writes listed as retained must not be replayed unless the current task explicitly requires a new record."
        ),
    }
    return result
