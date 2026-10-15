from __future__ import annotations

import unittest

from re_ctm.native_catalog import NATIVE_TOOL_DECLARATIONS, NATIVE_TOOL_NAMES, TOOL_CONTRACT_VERSION


class NativeCatalogV11TestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = {item["name"]: item for item in NATIVE_TOOL_DECLARATIONS}

    def test_exact_order_and_complete_declarations(self) -> None:
        expected = (
            "server_info", "check_exec_environment", "read_file", "list_dir", "list_files", "search_text",
            "apply_patch", "apply_changes", "exec_command", "write_stdin", "kill_command", "read_output",
            "git_status", "git_diff", "git_log", "git_show", "git_blame", "request_permissions", "view_image",
        )
        self.assertEqual(NATIVE_TOOL_NAMES, expected)
        self.assertEqual(TOOL_CONTRACT_VERSION, "mtm-tools-v11")
        self.assertEqual(len(self.catalog), 19)
        for item in NATIVE_TOOL_DECLARATIONS:
            with self.subTest(name=item["name"]):
                self.assertEqual(set(item), {"name", "title", "description", "inputSchema", "outputSchema", "annotations"})
                self.assertEqual(item["inputSchema"]["type"], "object")
                self.assertFalse(item["inputSchema"]["additionalProperties"])
                self.assertIsInstance(item["inputSchema"]["required"], list)
                self.assertEqual(item["annotations"]["title"], item["title"])
                self.assertEqual(set(item["annotations"]), {"title", "readOnlyHint", "destructiveHint", "openWorldHint", "idempotentHint"})

    def test_specialized_outputs_preserve_extensible_error_envelope(self) -> None:
        for name, item in self.catalog.items():
            with self.subTest(name=name):
                output = item["outputSchema"]
                self.assertEqual(output["required"], ["ok"])
                self.assertTrue(output["additionalProperties"])
                self.assertGreater(len(output["properties"]), 2)
                self.assertEqual(output["properties"]["error"]["required"], ["code", "message", "category", "retryable", "details"])
        self.assertEqual(self.catalog["read_file"]["outputSchema"]["properties"]["revision_algorithm"]["enum"], ["sha256"])
        for name in ("exec_command", "write_stdin", "kill_command"):
            self.assertEqual(self.catalog[name]["outputSchema"]["properties"]["operation_outcome"]["enum"],
                             ["running", "exited_0", "exited_nonzero", "timeout", "signal", "spawn_error"])

    def test_structured_change_flat_typed_contract(self) -> None:
        schema = self.catalog["apply_changes"]["inputSchema"]
        changes = schema["properties"]["changes"]
        self.assertEqual(schema["required"], ["changes"])
        self.assertEqual((changes["minItems"], changes["maxItems"]), (1, 100))
        self.assertEqual(changes["items"]["required"], ["action", "path"])
        self.assertEqual(changes["items"]["properties"]["action"]["enum"], ["create", "write", "edit", "delete", "move", "copy"])
        edits = changes["items"]["properties"]["edits"]
        self.assertEqual((edits["minItems"], edits["maxItems"]), (1, 200))
        self.assertEqual(edits["items"]["properties"]["op"]["enum"], ["replace", "delete", "insert_after", "insert_before"])
        self.assertNotIn("oneOf", changes["items"])
        for name in ("apply_patch", "apply_changes"):
            self.assertEqual(self.catalog[name]["inputSchema"]["properties"]["idempotency_key"],
                             {"type": "string", "minLength": 1, "maxLength": 128})
            self.assertFalse(self.catalog[name]["annotations"]["idempotentHint"])

    def test_execution_and_untracked_defaults(self) -> None:
        schema = self.catalog["exec_command"]["inputSchema"]
        self.assertEqual(schema["oneOf"], [{"required": ["cmd"]}, {"required": ["argv"]}])
        self.assertEqual(schema["properties"]["argv"]["items"], {"type": "string"})
        self.assertEqual(schema["properties"]["argv"]["prefixItems"], [{"type": "string", "minLength": 1}])
        self.assertEqual(schema["properties"]["timeout_ms"], {"type": "integer", "minimum": 1, "maximum": 600_000, "default": 300_000})
        self.assertEqual(self.catalog["git_diff"]["inputSchema"]["properties"]["include_untracked"], {"type": "boolean", "default": True})
        self.assertEqual(len(self.catalog["request_permissions"]["inputSchema"]["properties"]["permission"]["enum"]), 8)
        self.assertIn("dangerous-mode compatibility", self.catalog["request_permissions"]["description"])


if __name__ == "__main__":
    unittest.main()
