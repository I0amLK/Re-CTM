from __future__ import annotations

from enum import StrEnum


class NativeMode(StrEnum):
    SAFE = "safe"
    TRUSTED = "trusted"
    DANGEROUS = "dangerous"


class WorkflowRole(StrEnum):
    GENERATOR = "generator"
    BRANCH = "branch"
    JOIN = "join"
    ASSEMBLER = "assembler"
    VERIFIER = "verifier"
    REPAIR = "repair"
    FINALIZER = "finalizer"


class WorkflowState(StrEnum):
    CREATED = "created"
    ASSESS = "assess"
    EXPLORE = "explore"
    PROPOSE_PLANS = "propose_plans"
    DIRECT_PROVING = "direct_proving"
    BRANCH_PREPARE = "branch_prepare"
    BRANCH_RUN = "branch_run"
    BRANCH_JOIN = "branch_join"
    IDENTIFY_FAILURES = "identify_failures"
    REPLAN = "replan"
    ASSEMBLE = "assemble"
    LATEX_VALIDATE = "latex_validate"
    VERIFY = "verify"
    REPAIR = "repair"
    FINALIZE = "finalize"
    DONE = "done"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in {
            WorkflowState.DONE,
            WorkflowState.CANCELLED,
            WorkflowState.FAILED,
        }


class DomainStatus(StrEnum):
    OPEN = "open"
    SEALED = "sealed"
    CANCELLED = "cancelled"


class LatexPolicy(StrEnum):
    STATIC_ONLY = "static_only"
    IF_AVAILABLE = "if_available"
    REQUIRED = "required"
