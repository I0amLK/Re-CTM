from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from re_ctm.config import Settings
from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.native_helper_bwrap import HelperError, _execute
from re_ctm.processes import CommandManager, CommandRun, DEFAULT_COMMAND_TIMEOUT_MS


class CommandOutcomeV11TestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.manager = CommandManager(on_terminal=self.events.append)
        self.addCleanup(self.manager.close)

    def start(self, script: str, **kwargs: Any) -> dict[str, Any]:
        options = {
            "env": os.environ.copy(), "yield_time_ms": 1000,
            "max_output_bytes": 4096, "stdin_text": "", "tty": False,
            "verbosity": "full", "preview_bytes": 1024,
        }
        options.update(kwargs)
        return self.manager.start(["/bin/sh", "-c", script], **options)

    def poll(self, command_id: str) -> dict[str, Any]:
        return self.manager.poll(
            command_id, chars="", yield_time_ms=0, max_output_bytes=4096,
            verbosity="full", preview_bytes=1024,
        )

    def read(self, command_id: str) -> dict[str, Any]:
        return self.manager.read_output(
            f"command:{command_id}:stdout", stream=None, offset=0, limit=4096,
        )

    def kill(self, command_id: str, **kwargs: Any) -> dict[str, Any]:
        options = {
            "signal_name": "TERM", "wait_ms": 1000, "kill_wait_ms": 1000,
            "max_output_bytes": 4096, "verbosity": "full", "preview_bytes": 1024,
        }
        options.update(kwargs)
        return self.manager.kill(command_id, **options)

    def test_truthful_outcomes_and_terminal_event_once_across_all_tools(self) -> None:
        for script, timeout, expected in (
            ("exit 0", 2000, "exited_0"),
            ("exit 7", 2000, "exited_nonzero"),
            ("sleep 2", 30, "timeout"),
            ("kill -TERM $$", 2000, "signal"),
        ):
            with self.subTest(expected=expected):
                before = len(self.events)
                started = self.start(script, timeout_ms=timeout)
                command_id = started["command_id"]
                for result in (started, self.read(command_id), self.poll(command_id), self.kill(command_id)):
                    self.assertTrue(result["ok"])
                    self.assertEqual(result["operation_outcome"], expected)
                    self.assertFalse(any(key.startswith("_") for key in result))
                self.assertEqual(len(self.events), before + 1)
                self.assertEqual(self.events[-1]["operation_outcome"], expected)
                self.assertEqual(self.events[-1]["command_id"], command_id)
                self.assertNotIn("stdout", self.events[-1])

    def test_read_can_observe_terminal_without_consuming_poll_output(self) -> None:
        started = self.start("sleep .1; printf result; exit 7", yield_time_ms=0)
        command_id = started["command_id"]
        self.assertEqual(started["operation_outcome"], "running")
        command = self.manager._get(command_id, stdin=False)
        command.process.wait(timeout=3)
        self.manager._prune()  # Maintenance must not consume the event.
        self.assertEqual(self.events, [])
        read = self.read(command_id)
        polled = self.poll(command_id)
        self.assertEqual(read["operation_outcome"], "exited_nonzero")
        self.assertEqual(read["content"], "result")
        self.assertEqual(polled["stdout"], "result")
        self.assertEqual(len(self.events), 1)
        self.assertEqual(read["elapsed_ms"], polled["elapsed_ms"])

    def test_concurrent_poll_and_read_observe_terminal_once(self) -> None:
        started = self.start("sleep .1; printf result; exit 7", yield_time_ms=0)
        command_id = started["command_id"]
        self.manager._get(command_id, stdin=False).process.wait(timeout=3)
        barrier = threading.Barrier(16)

        def observe(index: int) -> dict[str, Any]:
            barrier.wait(timeout=5)
            return self.read(command_id) if index % 2 else self.poll(command_id)

        with ThreadPoolExecutor(max_workers=16) as workers:
            results = list(workers.map(observe, range(16)))
        self.assertEqual(len(self.events), 1)
        self.assertTrue(all(result["operation_outcome"] == "exited_nonzero" for result in results))
        self.assertTrue(all(result["exit_code"] == 7 for result in results))
        self.assertEqual(sum(result.get("stdout", "") == "result" for result in results), 1)

    def test_kill_can_be_first_terminal_observer(self) -> None:
        started = self.start("sleep 5", yield_time_ms=0)
        self.assertEqual(self.events, [])
        result = self.kill(started["command_id"])
        self.assertEqual(result["operation_outcome"], "signal")
        self.assertTrue(result["killed"])
        self.assertEqual(result["termination"]["source"], "explicit_kill")
        self.assertTrue(result["termination"]["term_sent_by_re_ctm"])
        self.assertEqual(len(self.events), 1)

    def test_unfinished_timeout_and_kill_remain_running_and_active(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("test", 0)
        command = CommandRun(
            "unresponsive", process, timeout_at=time.time() - 1,
            requested_timeout_ms=1, on_terminal=self.events.append,
        )
        self.manager.active[command.command_id] = command
        with mock.patch("re_ctm.processes.terminate_process_group"):
            result = self.read(command.command_id)
            self.assertEqual(result["operation_outcome"], "running")
            self.assertEqual(result["status"], "running")
            self.assertTrue(result["timed_out"])
            result = self.kill(command.command_id, wait_ms=0, kill_wait_ms=0)
            self.assertEqual(result["operation_outcome"], "running")
            self.assertEqual(result["status"], "terminating")
            self.assertFalse(result["killed"])
            self.assertFalse(result["evicted"])
            self.assertIn(command.command_id, self.manager.active)
            self.assertNotIn(command.command_id, self.manager.retained)
            self.assertEqual(self.events, [])
            process.poll.return_value = -signal.SIGKILL
            result = self.read(command.command_id)
            self.assertEqual(result["operation_outcome"], "timeout")
            self.assertEqual(result["termination"]["source"], "command_timeout")
            self.assertEqual(len(self.events), 1)

    def test_default_timeout_and_invalid_lifetimes_before_spawn(self) -> None:
        result = self.start("exit 0")
        self.assertEqual(DEFAULT_COMMAND_TIMEOUT_MS, 300000)
        self.assertEqual(result["termination"]["requested_timeout_ms"], 300000)
        for timeout in (0, -1, 600001, True, 1.5, "10"):
            with self.subTest(timeout=timeout):
                with mock.patch("re_ctm.processes.spawn_process") as spawn:
                    with self.assertRaises(ReCTMError):
                        self.start("exit 0", timeout_ms=timeout)
                    spawn.assert_not_called()


class NativeConfigurationV11TestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.settings = Settings(
            workspace=self.workspace, data_root=self.root / "data",
            private_root=self.root / "data" / "private", debug_root=self.root / "data" / "debug",
        )

    def test_only_dangerous_public_configuration_is_supported(self) -> None:
        self.assertIs(self.settings.native_mode, NativeMode.DANGEROUS)
        self.settings.validate()
        for mode in (NativeMode.SAFE, NativeMode.TRUSTED):
            with self.subTest(mode=mode):
                with self.assertRaises(ReCTMError) as denied:
                    replace(self.settings, native_mode=mode).validate()
                self.assertEqual(denied.exception.code, "INVALID_NATIVE_MODE")
        environment = {
            "RE_CTM_WORKSPACE": str(self.workspace), "RE_CTM_DATA_ROOT": str(self.root / "data"),
            "RE_CTM_NATIVE_EXEC_BACKEND": "disabled",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertIs(Settings.from_env().native_mode, NativeMode.DANGEROUS)
            for mode in ("safe", "trusted", "unknown", "DANGEROUS"):
                with self.subTest(mode=mode), mock.patch.dict(os.environ, {"RE_CTM_NATIVE_MODE": mode}):
                    with self.assertRaises(ReCTMError):
                        Settings.from_env()

    def test_dangerous_does_not_relax_isolation(self) -> None:
        with self.assertRaises(ReCTMError) as denied:
            replace(self.settings, native_exec_backend="external").validate()
        self.assertEqual(denied.exception.code, "NATIVE_ISOLATION_REQUIRED")

    def test_helper_timeout_default_and_typed_bounds(self) -> None:
        request = {
            "request_id": "v11-helper", "workspace": str(self.workspace),
            "mode": "safe", "argv": ["/bin/true"],
        }
        captured = {"text": "", "total_bytes": 0, "retained_bytes": 0, "dropped_bytes": 0, "truncated": False}
        completed = {
            "status": "exited", "operation_outcome": "exited_0", "exit_code": 0,
            "signal": None, "timed_out": False, "elapsed_ms": 1,
            "stdout": captured, "stderr": captured,
        }
        with mock.patch("re_ctm.native_helper_bwrap._run_in_sandbox", return_value=completed) as run:
            self.assertEqual(_execute(request)["operation_outcome"], "exited_0")
            self.assertEqual(run.call_args.kwargs["timeout_ms"], 300000)
            self.assertEqual(run.call_args.kwargs["mode"], "safe")
        for timeout in (0, 600001, True, 1.5, "10"):
            with self.subTest(timeout=timeout):
                with mock.patch("re_ctm.native_helper_bwrap._run_in_sandbox") as run:
                    with self.assertRaises(HelperError):
                        _execute({**request, "timeout_ms": timeout})
                    run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
