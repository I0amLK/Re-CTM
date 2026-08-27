from __future__ import annotations

import os
import unittest
from unittest import mock

from re_ctm.cli import build_parser


class CLITestCase(unittest.TestCase):
    def test_serve_defaults_follow_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"RE_CTM_HOST": "127.0.0.2", "RE_CTM_PORT": "42424"},
            clear=False,
        ):
            args = build_parser().parse_args(["serve"])
        self.assertEqual(args.host, "127.0.0.2")
        self.assertEqual(args.port, 42424)

    def test_cli_flags_override_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"RE_CTM_HOST": "127.0.0.2", "RE_CTM_PORT": "42424"},
            clear=False,
        ):
            args = build_parser().parse_args(
                ["serve", "--host", "127.0.0.3", "--port", "43434"]
            )
        self.assertEqual(args.host, "127.0.0.3")
        self.assertEqual(args.port, 43434)


if __name__ == "__main__":
    unittest.main()
