"""Domain identifier collision and legacy compatibility regressions in disposable state."""
from __future__ import annotations

import copy
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_ctm.capabilities import CapabilityAuthority, default_permissions
from re_ctm.debug import DebugEventBus
from re_ctm.enums import LatexPolicy, NativeMode, WorkflowRole
from re_ctm.latex import LatexGate
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.oauth import OAuthPrincipal
from re_ctm.storage import StateStore
from re_ctm.tools import ToolRuntime
from re_ctm.vault import PrivateVault
from re_ctm.workflow import WorkflowEngine


class DomainIdentifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        private, workspace = root / "private", root / "workspace"
        workspace.mkdir()
        debug = DebugEventBus(root / "events.jsonl", private, enabled=True)
        self.store = StateStore(private / "state.sqlite3")
        self.addCleanup(lambda: self.store.close())
        self.authority = CapabilityAuthority(b"c" * 32, self.store, debug)
        self.vault = PrivateVault(private)
        self.engine = WorkflowEngine(
            self.store, self.vault, self.authority, debug, LatexGate(LatexPolicy.STATIC_ONLY)
        )
        native = NativeRuntime(
            NativeWorkspace(workspace, private_root=private), NativeMode.DANGEROUS, debug
        )
        self.addCleanup(native.close)
        self.tools = ToolRuntime(native, self.engine, debug)
        self.owner = OAuthPrincipal("domain-test-owner", "domain-test-owner", "mcp")
        self.original_token_hex = secrets.token_hex
        self.suffix_counter = 0

    def call(self, name: str, arguments: dict) -> dict:
        response = self.tools.call(name, arguments, self.owner)
        self.assertFalse(response["isError"])
        return response["structuredContent"]

    def start(self) -> str:
        return self.call("rethlas_start", {
            "problem_tex": "Prove A=A.", "workflow_mode": "full", "register_result": False,
        })["run_id"]

    def request(self, task: dict) -> dict:
        return {"run_id": task["run_id"], "capability": task["capability"],
                **copy.deepcopy(task["task"]["minimal_submission"])}

    def colliding_short_suffix(self, nbytes: int) -> str:
        # Repeat the old 24-bit suffix; longer suffixes share it but differ afterward.
        if nbytes == 3:
            return "abcdef"
        if nbytes == 16:
            self.suffix_counter += 1
            return "abcdef" + f"{self.suffix_counter:026x}"
        return self.original_token_hex(nbytes)

    def test_same_short_suffix_does_not_block_initial_assess(self) -> None:
        runs = [self.start(), self.start()]
        self.assertNotEqual(*runs)
        with patch("re_ctm.workflow.secrets.token_hex", side_effect=self.colliding_short_suffix):
            tasks = [self.call("rethlas_step", {"run_id": run_id}) for run_id in runs]
        for task, run_id in zip(tasks, runs):
            self.assertEqual(task["run_id"], run_id)
            self.assertEqual(task["state"], "assess")
            self.assertEqual(task["role"], "generator")
            self.assertIn("task", task)
            self.assertIn("capability", task)
            self.assertRegex(task["domain_id"], r"^generator-assess-\d+-abcdef[0-9a-f]{26}$")
            self.assertEqual(self.store.get_domain(task["domain_id"])["run_id"], run_id)
        self.assertNotEqual(tasks[0]["domain_id"], tasks[1]["domain_id"])

    def test_legacy_short_domain_and_capability_survive_reopen(self) -> None:
        run_id = self.start()
        epoch = self.store.get_run(run_id)["epoch"]
        domain_id = f"generator-assess-{epoch}-abcdef"
        self.store.create_domain(domain_id=domain_id, run_id=run_id, role="generator",
                                 metadata={"state": "assess"})
        capability = self.authority.issue(
            run_id=run_id, domain_id=domain_id, role=WorkflowRole.GENERATOR,
            permissions=default_permissions(WorkflowRole.GENERATOR), trace_id="legacy-domain-test",
        )
        path = self.store.path
        self.store.close()
        self.store = StateStore(path)
        self.engine.store = self.authority.store = self.store
        with patch("re_ctm.workflow.secrets.token_hex", wraps=self.original_token_hex) as random_hex:
            task = self.call("rethlas_step", {"run_id": run_id})
            random_hex.assert_not_called()
        self.assertEqual(task["domain_id"], domain_id)
        claims = self.authority.validate(
            capability, owner_id=self.owner.client_id, action="read", resource="problem",
            trace_id="legacy-domain-test", expected_run_id=run_id,
        )
        self.assertEqual(claims.domain_id, domain_id)
        result = self.call("rethlas_step", {"run_id": run_id, "capability": capability,
                                           **copy.deepcopy(task["task"]["minimal_submission"])})
        self.assertEqual(result["state"], "explore")
        self.assertRegex(result["domain_id"], r"^generator-explore-\d+-[0-9a-f]{32}$")
        self.assertEqual(self.store.get_domain(domain_id)["domain_id"], domain_id)

    def test_next_task_and_exact_replay_with_former_suffix_collision(self) -> None:
        blocker_run, run_id = self.start(), self.start()
        initial = self.call("rethlas_step", {"run_id": run_id})
        request = self.request(initial)
        with patch("re_ctm.workflow.secrets.token_hex", side_effect=self.colliding_short_suffix):
            blocker_task = self.call("rethlas_step", {"run_id": blocker_run})
            blocker_next = self.call("rethlas_step", self.request(blocker_task))
            advanced = self.call("rethlas_step", request)
        self.assertEqual(blocker_next["state"], "explore")
        self.assertEqual(advanced["state"], "explore")
        self.assertIn("task", advanced)
        self.assertIn("capability", advanced)
        self.assertFalse(advanced.get("state_is_historical", False))
        self.assertFalse(advanced.get("task_required", False))
        self.assertNotEqual(advanced["domain_id"], blocker_next["domain_id"])
        self.assertRegex(advanced["domain_id"], r"^generator-explore-\d+-abcdef[0-9a-f]{26}$")
        transitions = self.store.list_transitions(run_id)
        domains = self.store.list_domains(run_id)
        memory = {name: self.vault.read_generation_memory(run_id, name)
                  for name in ("immediate_conclusions", "events")}
        for arguments in (request, {**request, "recover_only": True}):
            replay = self.call("rethlas_step", arguments)
            self.assertTrue(replay["state_is_historical"])
            self.assertTrue(replay["submission"]["replayed"])
            self.assertEqual(replay["writes_applied"], 0)
            self.assertNotIn("capability", replay)
            self.assertNotIn("task", replay)
            self.assertTrue(replay["task_required"])
        self.assertEqual(self.store.list_transitions(run_id), transitions)
        self.assertEqual(self.store.list_domains(run_id), domains)
        for name, contents in memory.items():
            self.assertEqual(self.vault.read_generation_memory(run_id, name), contents)
        current = self.call("rethlas_step", {"run_id": run_id})
        self.assertEqual(current["domain_id"], advanced["domain_id"])


if __name__ == "__main__":
    unittest.main()
