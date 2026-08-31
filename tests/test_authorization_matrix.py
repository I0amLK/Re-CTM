from __future__ import annotations

import fnmatch
import unittest

from re_ctm.capabilities import authorize_role_resource, default_permissions
from re_ctm.enums import WorkflowRole, WorkflowState
from re_ctm.errors import ReCTMError


EXPECTED_PERMISSION_PATTERNS = {
    WorkflowRole.GENERATOR: (
        "read:problem",
        "read:references",
        "read:project:verified_dependencies",
        "read:steering",
        "read:memory:generation:*",
        "write:memory:generation:*",
        "search:memory:generation:*",
        "retrieve:external:theorems",
        "retrieve:external:research",
        "commit:workflow",
    ),
    WorkflowRole.BRANCH: (
        "read:problem",
        "read:references",
        "read:project:verified_dependencies",
        "read:snapshot",
        "read:branch:self",
        "write:branch:self",
        "read:memory:branch:*",
        "write:memory:branch:*",
        "search:memory:branch:*",
        "retrieve:external:theorems",
        "retrieve:external:research",
        "commit:workflow",
    ),
    WorkflowRole.JOIN: (
        "read:problem",
        "read:snapshot",
        "read:branch:sealed:*",
        "write:join_result",
        "write:memory:generation:*",
        "commit:workflow",
    ),
    WorkflowRole.ASSEMBLER: (
        "read:problem",
        "read:references",
        "read:project:verified_dependencies",
        "read:memory:generation:*",
        "read:join_result",
        "write:proof",
        "write:proof_manifest",
        "commit:workflow",
    ),
    WorkflowRole.VERIFIER: (
        "read:problem",
        "read:proof",
        "read:proof_manifest",
        "read:project:verified_dependencies",
        "read:references:approved",
        "read:references:candidates",
        "read:memory:verifier:*",
        "write:memory:verifier:*",
        "write:verification_report",
        "write:reference_audit",
        "retrieve:external:theorems",
        "retrieve:external:research",
        "commit:workflow",
    ),
    WorkflowRole.REPAIR: (
        "read:problem",
        "read:proof",
        "read:proof_manifest",
        "read:project:verified_dependencies",
        "read:verification_report",
        "read:memory:generation:*",
        "write:memory:generation:*",
        "write:proof",
        "write:proof_manifest",
        "retrieve:external:theorems",
        "retrieve:external:research",
        "commit:workflow",
    ),
    WorkflowRole.FINALIZER: ("commit:workflow",),
}


ROLE_STATE = {
    WorkflowRole.GENERATOR: WorkflowState.ASSESS,
    WorkflowRole.BRANCH: WorkflowState.BRANCH_RUN,
    WorkflowRole.JOIN: WorkflowState.BRANCH_JOIN,
    WorkflowRole.ASSEMBLER: WorkflowState.ASSEMBLE,
    WorkflowRole.VERIFIER: WorkflowState.VERIFY,
    WorkflowRole.REPAIR: WorkflowState.REPAIR,
    WorkflowRole.FINALIZER: WorkflowState.FINALIZE,
}


ROLE_ALLOW_DENY_SAMPLES = {
    WorkflowRole.GENERATOR: (("read", "problem"), ("read", "proof")),
    WorkflowRole.BRANCH: (("read", "snapshot"), ("read", "proof")),
    WorkflowRole.JOIN: (("read", "branch:sealed:all"), ("read", "references")),
    WorkflowRole.ASSEMBLER: (("write", "proof"), ("write", "verification_report")),
    WorkflowRole.VERIFIER: (("read", "proof"), ("read", "memory:generation:events")),
    WorkflowRole.REPAIR: (("read", "verification_report"), ("write", "verification_report")),
    WorkflowRole.FINALIZER: (("commit", "workflow"), ("read", "problem")),
}


def permission_matches(role: WorkflowRole, action: str, resource: str) -> bool:
    required = f"{action}:{resource}"
    return any(
        fnmatch.fnmatchcase(required, pattern)
        for pattern in default_permissions(role)
    )


class AuthorizationMatrixTestCase(unittest.TestCase):
    def domain(self, role: WorkflowRole) -> dict:
        metadata = {"branch_id": "branch-a"} if role is WorkflowRole.BRANCH else {}
        return {"role": role.value, "metadata": metadata}

    def test_default_permission_patterns_are_frozen_for_every_role(self) -> None:
        self.assertEqual(set(EXPECTED_PERMISSION_PATTERNS), set(WorkflowRole))
        for role, expected in EXPECTED_PERMISSION_PATTERNS.items():
            with self.subTest(role=role.value):
                self.assertEqual(default_permissions(role), expected)

    def test_every_role_has_explicit_allowed_and_denied_resource_samples(self) -> None:
        self.assertEqual(set(ROLE_ALLOW_DENY_SAMPLES), set(WorkflowRole))
        for role, (allowed, denied) in ROLE_ALLOW_DENY_SAMPLES.items():
            state = ROLE_STATE[role]
            with self.subTest(role=role.value, case="allow"):
                self.assertTrue(permission_matches(role, *allowed))
                authorize_role_resource(
                    role=role,
                    state=state,
                    action=allowed[0],
                    resource=allowed[1],
                    domain=self.domain(role),
                )
            with self.subTest(role=role.value, case="deny"):
                self.assertFalse(permission_matches(role, *denied))

    def test_unknown_resource_is_fail_closed_for_every_role(self) -> None:
        for role in WorkflowRole:
            with self.subTest(role=role.value):
                self.assertFalse(permission_matches(role, "read", "future:new_resource"))
                self.assertFalse(permission_matches(role, "write", "future:new_resource"))
                self.assertFalse(permission_matches(role, "search", "future:new_resource"))

    def test_role_state_mismatch_is_rejected_for_every_role(self) -> None:
        for role, state in ROLE_STATE.items():
            wrong_state = (
                WorkflowState.VERIFY
                if state is not WorkflowState.VERIFY
                else WorkflowState.ASSESS
            )
            action, resource = ROLE_ALLOW_DENY_SAMPLES[role][0]
            with self.subTest(role=role.value):
                with self.assertRaises(ReCTMError) as caught:
                    authorize_role_resource(
                        role=role,
                        state=wrong_state,
                        action=action,
                        resource=resource,
                        domain=self.domain(role),
                    )
                self.assertEqual(caught.exception.code, "ROLE_STATE_MISMATCH")
                self.assertEqual(caught.exception.category, "permission")

    def test_verifier_data_firewall_rejects_generation_private_resources(self) -> None:
        forbidden = (
            "memory:generation:events",
            "branch:self",
            "branch:sealed:all",
            "steering",
            "join_result",
            "snapshot",
        )
        for resource in forbidden:
            with self.subTest(resource=resource):
                with self.assertRaises(ReCTMError) as caught:
                    authorize_role_resource(
                        role=WorkflowRole.VERIFIER,
                        state=WorkflowState.VERIFY,
                        action="read",
                        resource=resource,
                        domain=self.domain(WorkflowRole.VERIFIER),
                    )
                self.assertEqual(caught.exception.code, "VERIFIER_DATA_FIREWALL")
                self.assertEqual(caught.exception.category, "permission")

    def test_branch_guard_allows_self_and_rejects_other_branch(self) -> None:
        domain = self.domain(WorkflowRole.BRANCH)
        for resource in ("branch:self", "branch:branch-a"):
            with self.subTest(resource=resource):
                authorize_role_resource(
                    role=WorkflowRole.BRANCH,
                    state=WorkflowState.BRANCH_RUN,
                    action="read",
                    resource=resource,
                    domain=domain,
                )
        with self.assertRaises(ReCTMError) as caught:
            authorize_role_resource(
                role=WorkflowRole.BRANCH,
                state=WorkflowState.BRANCH_RUN,
                action="read",
                resource="branch:branch-b",
                domain=domain,
            )
        self.assertEqual(caught.exception.code, "CROSS_BRANCH_ACCESS_DENIED")

    def test_sealed_branch_sets_are_join_only(self) -> None:
        authorize_role_resource(
            role=WorkflowRole.JOIN,
            state=WorkflowState.BRANCH_JOIN,
            action="read",
            resource="branch:sealed:all",
            domain=self.domain(WorkflowRole.JOIN),
        )
        with self.assertRaises(ReCTMError) as caught:
            authorize_role_resource(
                role=WorkflowRole.GENERATOR,
                state=WorkflowState.ASSESS,
                action="read",
                resource="branch:sealed:all",
                domain=self.domain(WorkflowRole.GENERATOR),
            )
        self.assertEqual(caught.exception.code, "JOIN_ONLY_RESOURCE")

    def test_finalizer_is_mechanical_commit_only(self) -> None:
        authorize_role_resource(
            role=WorkflowRole.FINALIZER,
            state=WorkflowState.FINALIZE,
            action="commit",
            resource="workflow",
            domain=self.domain(WorkflowRole.FINALIZER),
        )
        with self.assertRaises(ReCTMError) as caught:
            authorize_role_resource(
                role=WorkflowRole.FINALIZER,
                state=WorkflowState.FINALIZE,
                action="read",
                resource="problem",
                domain=self.domain(WorkflowRole.FINALIZER),
            )
        self.assertEqual(caught.exception.code, "FINALIZER_MECHANICAL_ONLY")


if __name__ == "__main__":
    unittest.main()

