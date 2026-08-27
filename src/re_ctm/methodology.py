from __future__ import annotations

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
    return payload


def task_for_state(state: WorkflowState) -> dict[str, Any]:
    task = _catalog()["tasks"].get(state.value)
    if not isinstance(task, dict):
        raise ReCTMError(
            "NO_MODEL_TASK",
            f"Workflow state has no model task: {state.value}",
            category="validation",
            details={"state": state.value},
        )
    return dict(task)
