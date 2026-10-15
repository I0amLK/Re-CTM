from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from re_ctm.cli import build_parser, main
from re_ctm.debug import utc_now
from re_ctm.fact_memory import prepare_verified_facts
from re_ctm.fact_store import insert_promoted_facts
from re_ctm.storage import StateStore


class FactGraphCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "state.sqlite3"
        store = StateStore(self.path)
        try:
            store.create_project(owner_id="owner", title="Graph", project_id="P")
            store.create_run(run_id="R", problem_id="p", owner_id="owner", state="done")
            first = prepare_verified_facts("P", "Lemma.", "Proof.", {}, [], set())
            second = prepare_verified_facts("P", "Target.", "Proof.", {}, [first[0].fact_id], {first[0].fact_id})
            self.fact_ids = [first[0].fact_id, second[0].fact_id]
            with store.transaction() as connection:
                insert_promoted_facts(connection, "P", "R", first + second, utc_now())
        finally:
            store.close()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _call(self, arguments: list[str]) -> tuple[int, str, str]:
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(["fact-graph", *arguments, "--state-db", str(self.path)])
        return code, output.getvalue(), errors.getvalue()

    def test_export_is_exact_deterministic_read_only_and_no_clobber(self) -> None:
        original = self.path.read_bytes()
        first = self._call(["export", "--project", "P"])
        self.assertEqual(first[0], 0, first[2])
        self.assertEqual(first, self._call(["export", "--project", "P"]))
        self.assertEqual(self.path.read_bytes(), original)
        graph = json.loads(first[1])
        self.assertEqual(len(graph["graph"]["edges"]), 1)
        output = self.root / "graph.json"
        self.assertEqual(self._call(["export", "--project", "P", "--out", str(output)])[0], 0)
        self.assertEqual(output.read_text(), first[1])
        self.assertEqual(self._call(["export", "--project", "P", "--out", str(output)])[0], 2)
        self.assertEqual(output.read_text(), first[1])
        self.assertEqual(list(self.root.glob(".fact-graph-*")), [])

    def test_revocation_cascades_and_repeated_request_is_idempotent(self) -> None:
        result = self._call(["revoke", self.fact_ids[0], "--reason", "Invalid premise"])
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(set(json.loads(result[1])["revoked_fact_ids"]), set(self.fact_ids))
        result = self._call(["revoke", self.fact_ids[0], "--reason", "Invalid premise"])
        self.assertEqual(json.loads(result[1])["revoked_fact_ids"], [])
        graph = json.loads(self._call(["export", "--project", "P"])[1])
        self.assertTrue(all(node["metadata"]["revoked"] for node in graph["graph"]["nodes"].values()))

    def test_missing_relative_and_legacy_databases_are_not_created_or_migrated(self) -> None:
        for path in (self.root / "absent.sqlite3", Path("relative.sqlite3")):
            with redirect_stderr(io.StringIO()):
                code = main(["fact-graph", "export", "--project", "P", "--state-db", str(path)])
            self.assertEqual(code, 2)
            self.assertFalse(path.exists())
        old = self.root / "legacy.sqlite3"
        connection = sqlite3.connect(old)
        connection.execute("PRAGMA user_version=2")
        connection.close()
        before = old.read_bytes()
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["fact-graph", "export", "--project", "P", "--state-db", str(old)]), 2)
        self.assertEqual(before, old.read_bytes())

    def test_options_reject_cross_operation_and_duplicates(self) -> None:
        for arguments in (["export", "--project", "P", "--reason", "wrong"],
                          ["revoke", self.fact_ids[0], "--reason", "x", "--out", "file"],
                          ["export", "--project", "P", "--project", "P"]):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                build_parser().parse_args(["fact-graph", *arguments])

    def test_default_private_root_does_not_initialize_service_or_secrets(self) -> None:
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"RE_CTM_PRIVATE_ROOT": str(self.root)}, clear=True), \
                mock.patch("re_ctm.cli.materialize_secrets", side_effect=AssertionError("no secrets")), \
                redirect_stdout(output):
            self.assertEqual(main(["fact-graph", "export", "--project", "P"]), 0)
        self.assertIn("graph", json.loads(output.getvalue()))


if __name__ == "__main__":
    unittest.main()
