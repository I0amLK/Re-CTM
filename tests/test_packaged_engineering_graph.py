from __future__ import annotations

import copy
import io
import json
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from re_ctm import cli, engineering_graph


ROOT = Path(__file__).resolve().parents[1]


class PackagedEngineeringGraphTests(unittest.TestCase):
    def test_packaged_graph_matches_checkout_exactly(self) -> None:
        self.assertEqual(
            files("re_ctm").joinpath("resources/engineering-graph.json").read_bytes(),
            (ROOT / "engineering-graph.json").read_bytes(),
        )

    def test_packaged_graph_validates_without_checkout(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(engineering_graph.main(), 0)
        self.assertTrue(json.loads(output.getvalue())["ok"])

    def test_metric_drift_is_rejected(self) -> None:
        data = copy.deepcopy(engineering_graph.load_graph())
        data["derived_undirected_metrics"]["vertex_count"] += 1
        with patch.object(engineering_graph, "load_graph", return_value=data):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(engineering_graph.main(), 1)
        self.assertIn("vertex_count", json.loads(output.getvalue())["mismatches"])

    def test_cli_installed_path_uses_packaged_validator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory) / "lib/python3.13/site-packages/re_ctm/cli.py"
            with patch.object(cli, "__file__", str(installed)), patch.object(
                cli, "validate_engineering_graph", return_value=0
            ) as validator:
                self.assertEqual(cli.main(["validate-graph"]), 0)
            validator.assert_called_once_with(None)

    def test_cli_checkout_still_validates_checkout_graph(self) -> None:
        source = ROOT / "src/re_ctm/cli.py"
        with patch.object(cli, "__file__", str(source)), patch.object(
            cli, "validate_engineering_graph", return_value=1
        ) as validator:
            self.assertEqual(cli.main(["validate-graph"]), 1)
        validator.assert_called_once_with(ROOT / "engineering-graph.json")

    def test_source_script_uses_same_packaged_authority(self) -> None:
        with patch("sys.path", list(sys.path)):
            wrapper = runpy.run_path(str(ROOT / "scripts/validate_engineering_graph.py"))
        self.assertIs(wrapper["main"], engineering_graph.main)


if __name__ == "__main__":
    unittest.main()
