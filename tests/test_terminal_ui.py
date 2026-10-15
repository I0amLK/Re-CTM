from __future__ import annotations

import io
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.app import build_application
from re_ctm.config import Settings
from re_ctm.debug import DebugEvent, DebugEventBus
from re_ctm.enums import LatexPolicy, NativeMode
from re_ctm.server import ReCTMHTTPServer, run_server
from re_ctm.terminal_ui import TerminalSession


def event(event_type: str, *, details: dict[str, object] | None = None) -> DebugEvent:
    return DebugEvent(
        timestamp="2026-08-31T22:55:00.000Z",
        trace_id="tr_terminal_123456",
        event_type=event_type,
        component="test",
        details=dict(details or {}),
    )


class TerminalSessionTestCase(unittest.TestCase):
    def test_startup_shows_generated_key_and_configured_password_is_not_echoed(self) -> None:
        generated_stream = io.StringIO()
        generated = TerminalSession(stream=generated_stream)
        generated.start(
            version="0.2.1",
            workspace=Path("/tmp/project"),
            mcp_url="http://127.0.0.1:8765/mcp",
            generated_oauth_key="generated-key-123",
        )
        generated.close()
        self.assertIn("generated-key-123", generated_stream.getvalue())

        configured_stream = io.StringIO()
        configured = TerminalSession(stream=configured_stream)
        configured.start(
            version="0.2.1",
            workspace=Path("/tmp/project"),
            mcp_url="http://127.0.0.1:8765/mcp",
            generated_oauth_key=None,
        )
        configured.close()
        self.assertIn("configured externally", configured_stream.getvalue())

    def test_tool_events_and_oauth_states_are_rendered_without_duplicate_connected(self) -> None:
        stream = io.StringIO()
        session = TerminalSession(stream=stream)
        session.start(
            version="0.2.1",
            workspace=Path("/tmp/project"),
            mcp_url="http://127.0.0.1:8765/mcp",
            generated_oauth_key="key",
        )
        session.observe(
            event("tool.call_started", details={"tool": "rethlas_step"})
        )
        session.observe(
            event("tool.call_finished", details={"tool": "rethlas_step"})
        )
        session.observe(event("oauth.authorization_code_issued"))
        session.observe(event("oauth.access_token_issued"))
        session.observe(event("oauth.access_token_accepted"))
        session.observe(event("oauth.access_token_accepted"))
        session.observe(
            event(
                "tool.call_failed",
                details={
                    "tool": "exec_command",
                    "error": {"code": "EXEC_DENIED"},
                },
            )
        )
        session.close()
        output = stream.getvalue()
        self.assertIn("rethlas_step", output)
        self.assertIn("exec_command", output)
        self.assertIn("EXEC_DENIED", output)
        self.assertEqual(output.count("OAuth status   connected"), 1)

    def test_dynamic_origin_updates_only_when_it_changes(self) -> None:
        stream = io.StringIO()
        session = TerminalSession(stream=stream)
        session.start(
            version="0.2.1",
            workspace=Path("/tmp/project"),
            mcp_url="http://127.0.0.1:8765/mcp",
            generated_oauth_key="key",
        )
        session.observe(
            event(
                "oauth.external_origin_resolved",
                details={"base_url": "http://127.0.0.1:8765"},
            )
        )
        session.observe(
            event(
                "oauth.external_origin_resolved",
                details={"base_url": "https://example.trycloudflare.com"},
            )
        )
        session.observe(
            event(
                "oauth.external_origin_resolved",
                details={"base_url": "https://example.trycloudflare.com"},
            )
        )
        session.close()
        output = stream.getvalue()
        self.assertEqual(output.count("https://example.trycloudflare.com/mcp"), 1)
        self.assertEqual(output.count("http://127.0.0.1:8765/mcp"), 1)

    def test_compact_output_shows_tool_once_and_keeps_failure_trace(self) -> None:
        stream = io.StringIO()
        session = TerminalSession(stream=stream)
        session._render_tool_event(event("tool.call_started", details={"tool": "read_file"}))
        session._render_tool_event(event("tool.call_finished", details={"tool": "read_file"}))
        session._render_tool_event(event("tool.call_failed", details={
            "tool": "exec_command", "error": {"code": "EXEC_DENIED", "message": "secret"},
        }))
        output = stream.getvalue()
        self.assertEqual(output.count("read_file"), 1)
        self.assertNotIn("[123456] read_file", output)
        self.assertIn("ERR [123456] exec_command  EXEC_DENIED", output)
        self.assertNotIn("secret", output)

    def test_verbose_output_retains_redacted_lifecycle(self) -> None:
        stream = io.StringIO()
        session = TerminalSession(stream=stream, verbose=True)
        for kind in ("tool.call_started", "tool.call_finished"):
            session._render_tool_event(event(kind, details={
                "tool": "read_file", "arguments": {"password": "never-print"},
                "result": "private source",
            }))
        output = stream.getvalue()
        self.assertEqual(output.count("[123456] read_file"), 2)
        self.assertIn("OK", output)
        self.assertNotIn("never-print", output)
        self.assertNotIn("private source", output)

    def test_compact_success_is_filtered_before_queueing_but_denials_are_kept(self) -> None:
        session = TerminalSession(stream=io.StringIO(), queue_size=1)
        session._started.set()
        session.observe(event("tool.call_finished", details={"tool": "read_file"}))
        self.assertTrue(session._queue.empty())
        denied = DebugEvent(
            timestamp="2026-10-14T12:00:00Z", trace_id="tr_denied",
            event_type="tool.call_finished", component="test", decision="deny",
            details={"tool": "request_permissions"},
        )
        session.observe(denied)
        self.assertIs(session._queue.get_nowait(), denied)

    def test_submission_correction_is_visible_without_claiming_replay_is_safe(self) -> None:
        stream = io.StringIO()
        session = TerminalSession(stream=stream)
        session._render_tool_event(event("tool.call_submission_rejected", details={
            "tool": "rethlas_step", "error": {"code": "INVALID_ARGUMENT"},
        }))
        output = stream.getvalue()
        self.assertIn("FIX [123456] rethlas_step", output)
        self.assertIn("inspect current task and retained writes", output)
        self.assertNotIn("OK", output)

    def test_quick_tunnel_public_url_suppresses_later_duplicate_origin_event(self) -> None:
        stream = io.StringIO()
        session = TerminalSession(stream=stream)
        session.start(
            version="0.2.1",
            workspace=Path("/tmp/project"),
            mcp_url="http://127.0.0.1:8765/mcp",
            generated_oauth_key="key",
        )
        session.show_public_mcp_url("https://example.trycloudflare.com/mcp")
        session.observe(
            event(
                "oauth.external_origin_resolved",
                details={"base_url": "https://example.trycloudflare.com"},
            )
        )
        session.close()
        self.assertEqual(
            stream.getvalue().count("https://example.trycloudflare.com/mcp"),
            1,
        )

    def test_full_queue_never_blocks_producer(self) -> None:
        session = TerminalSession(stream=io.StringIO(), queue_size=1)
        session._started.set()
        session._queue.put_nowait(event("tool.call_started", details={"tool": "server_info"}))
        started = time.perf_counter_ns()
        session.observe(event("tool.call_started", details={"tool": "server_info"}))
        elapsed_ns = time.perf_counter_ns() - started
        self.assertLess(elapsed_ns, 5_000_000)
        self.assertEqual(session._dropped, 1)

    def test_terminal_write_failure_isolated(self) -> None:
        class BrokenStream(io.StringIO):
            def write(self, _text: str) -> int:
                raise BrokenPipeError("closed")

        session = TerminalSession(stream=BrokenStream())
        session.start(
            version="0.2.1",
            workspace=Path("/tmp/project"),
            mcp_url="http://127.0.0.1:8765/mcp",
            generated_oauth_key="key",
        )
        session.observe(event("tool.call_started", details={"tool": "server_info"}))
        session.close()
        self.assertTrue(session._output_failed.is_set())

    def test_terminal_control_characters_are_not_emitted(self) -> None:
        stream = io.StringIO()
        session = TerminalSession(stream=stream)
        session.start(
            version="0.2.1\x1b[31m",
            workspace=Path("/tmp/project\nother"),
            mcp_url="http://127.0.0.1:8765/mcp",
            generated_oauth_key="key",
        )
        session.close()
        output = stream.getvalue()
        self.assertNotIn("\x1b", output)
        self.assertNotIn("project\nother", output)



class TerminalOutputBoundaryTestCase(unittest.TestCase):
    def _direct_session(self):
        stream = mock.Mock(encoding="ascii", errors="backslashreplace")
        stream.fileno.return_value = 2
        session = TerminalSession(stream=stream)
        session._direct_stderr = True
        return session, stream

    def test_partial_direct_writes_preserve_encoding_without_flush_or_close(self) -> None:
        session, stream = self._direct_session()
        emitted = bytearray()

        def partial(_fd, data):
            emitted.extend(data[:2])
            return min(2, len(data))

        with mock.patch("re_ctm.terminal_ui.os.write", side_effect=partial):
            session._safe_write("price \u20ac\n")
        self.assertEqual(bytes(emitted), b"price \\u20ac\n")
        stream.write.assert_not_called()
        stream.flush.assert_not_called()
        stream.close.assert_not_called()

    def test_direct_encoding_state_is_preserved_between_messages(self) -> None:
        session, stream = self._direct_session()
        stream.encoding = "utf-16"
        emitted = bytearray()

        def write(_fd, data):
            emitted.extend(data)
            return len(data)

        with mock.patch("re_ctm.terminal_ui.os.write", side_effect=write):
            session._safe_write("first")
            session._safe_write("second")
        self.assertEqual(bytes(emitted), "firstsecond".encode("utf-16"))

    def test_direct_encoder_tracks_explicit_encoding_change(self) -> None:
        session, stream = self._direct_session()
        emitted = bytearray()

        def write(_fd, data):
            emitted.extend(data)
            return len(data)

        with mock.patch("re_ctm.terminal_ui.os.write", side_effect=write):
            session._safe_write("a")
            stream.encoding = "utf-8"
            session._safe_write("\u20ac")
        self.assertEqual(bytes(emitted), b"a\xe2\x82\xac")

    def test_zero_progress_stops_future_observer_writes(self) -> None:
        session, _ = self._direct_session()
        with mock.patch("re_ctm.terminal_ui.os.write", return_value=0) as write:
            session._safe_write("first")
            session._safe_write("second")
        write.assert_called_once()
        self.assertTrue(session._output_failed.is_set())

    def test_closed_stream_is_checked_before_using_descriptor(self) -> None:
        session, stream = self._direct_session()
        stream.fileno.side_effect = ValueError("closed")
        with mock.patch("re_ctm.terminal_ui.os.write") as write:
            session._safe_write("ignored")
        write.assert_not_called()
        self.assertTrue(session._output_failed.is_set())

    def test_keyboard_interrupt_is_not_swallowed(self) -> None:
        session, _ = self._direct_session()
        with mock.patch("re_ctm.terminal_ui.os.write", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                session._safe_write("interrupted")
        self.assertFalse(session._output_failed.is_set())

    def test_falsey_explicit_stream_is_honored(self) -> None:
        class FalseyStream(io.StringIO):
            def __bool__(self):
                return False

        stream = FalseyStream()
        session = TerminalSession(stream=stream)
        session._safe_write("custom")
        self.assertEqual(stream.getvalue(), "custom")
        self.assertFalse(session._direct_stderr)
        session.close()
        self.assertFalse(stream.closed)

    def test_replaced_stderr_preserves_custom_stream_behavior(self) -> None:
        stream = io.StringIO()
        with mock.patch("re_ctm.terminal_ui.sys.stderr", stream):
            session = TerminalSession()
            session._safe_write("replacement")
        self.assertEqual(stream.getvalue(), "replacement")
        self.assertFalse(session._direct_stderr)
        self.assertFalse(stream.closed)

    def test_waiting_writer_does_not_retry_after_failure(self) -> None:
        session, _ = self._direct_session()
        session._write_lock.acquire()
        threads = [threading.Thread(target=session._safe_write, args=("text",)) for _ in range(2)]
        with mock.patch("re_ctm.terminal_ui.os.write", side_effect=BrokenPipeError) as write:
            for thread in threads:
                thread.start()
            session._write_lock.release()
            for thread in threads:
                thread.join(timeout=1)
                self.assertFalse(thread.is_alive())
        write.assert_called_once()


class DebugObserverTestCase(unittest.TestCase):
    def test_observer_receives_redacted_event_and_failure_does_not_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captured: list[DebugEvent] = []

            def observer(item: DebugEvent) -> None:
                captured.append(item)
                raise RuntimeError("presentation failed")

            bus = DebugEventBus(
                root / "events.jsonl",
                root / "private",
                observer=observer,
            )
            bus.emit(
                "test.event",
                "test",
                trace_id="tr_test",
                details={"password": "must-not-leak", "safe": "visible"},
            )
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0].details["password"], "<redacted>")
            self.assertEqual(captured[0].details["safe"], "visible")
            persisted = json.loads((root / "events.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(persisted["details"]["password"], "<redacted>")


class TerminalServerIntegrationTestCase(unittest.TestCase):
    def _settings(self, root: Path, *, oauth_password: str) -> Settings:
        workspace = root / "workspace"
        workspace.mkdir()
        return Settings(
            workspace=workspace,
            data_root=root / "data",
            private_root=root / "data" / "private",
            debug_root=root / "data" / "debug",
            native_mode=NativeMode.DANGEROUS,
            native_exec_backend="disabled",
            latex_policy=LatexPolicy.STATIC_ONLY,
            oauth_password=oauth_password,
            token_secret=b"t" * 32,
            capability_secret=b"c" * 32,
        )

    def test_run_server_tui_hides_access_log_and_does_not_persist_generated_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = "operator-generated-key-should-stay-terminal-only"
            settings = self._settings(root, oauth_password=key)
            stream = io.StringIO()
            session = TerminalSession(stream=stream)
            application = build_application(settings, debug_observer=session.observe)
            observed_access_log: list[bool] = []

            def fake_serve(server: ReCTMHTTPServer) -> None:
                observed_access_log.append(server.access_log_enabled)

            with mock.patch.object(ReCTMHTTPServer, "serve_forever", fake_serve):
                code = run_server(
                    application,
                    host="127.0.0.1",
                    port=0,
                    reveal_generated_oauth_password=True,
                    terminal_session=session,
                )
            self.assertEqual(code, 0)
            self.assertEqual(observed_access_log, [False])
            self.assertIn(key, stream.getvalue())
            encoded = key.encode("utf-8")
            for path in (root / "data").rglob("*"):
                if path.is_file():
                    self.assertNotIn(encoded, path.read_bytes(), str(path))

    def test_configured_password_is_not_echoed_by_tui_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password = "configured-password-must-not-be-echoed"
            settings = self._settings(root, oauth_password=password)
            stream = io.StringIO()
            session = TerminalSession(stream=stream)
            application = build_application(settings, debug_observer=session.observe)
            with mock.patch.object(ReCTMHTTPServer, "serve_forever", return_value=None):
                code = run_server(
                    application,
                    host="127.0.0.1",
                    port=0,
                    reveal_generated_oauth_password=False,
                    terminal_session=session,
                )
            self.assertEqual(code, 0)
            self.assertNotIn(password, stream.getvalue())
            self.assertIn("configured externally", stream.getvalue())

    def test_bind_failure_does_not_reveal_generated_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = "never-display-if-bind-fails"
            settings = self._settings(root, oauth_password=key)
            stream = io.StringIO()
            session = TerminalSession(stream=stream)
            application = build_application(settings, debug_observer=session.observe)
            blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            blocker.bind(("127.0.0.1", 0))
            blocker.listen(1)
            port = int(blocker.getsockname()[1])
            try:
                with self.assertRaises(OSError):
                    run_server(
                        application,
                        host="127.0.0.1",
                        port=port,
                        reveal_generated_oauth_password=True,
                        terminal_session=session,
                    )
            finally:
                blocker.close()
            self.assertNotIn(key, stream.getvalue())

    def test_keyboard_interrupt_closes_terminal_session_and_returns_130(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = self._settings(root, oauth_password="operator-key")
            stream = io.StringIO()
            session = TerminalSession(stream=stream)
            application = build_application(settings, debug_observer=session.observe)
            with mock.patch.object(
                ReCTMHTTPServer,
                "serve_forever",
                side_effect=KeyboardInterrupt,
            ):
                code = run_server(
                    application,
                    host="127.0.0.1",
                    port=0,
                    reveal_generated_oauth_password=True,
                    terminal_session=session,
                )
            self.assertEqual(code, 130)
            self.assertTrue(session._stopping.is_set())

    def test_quick_tunnel_starts_after_bind_with_actual_local_origin_and_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = self._settings(root, oauth_password="operator-key")
            session = TerminalSession(stream=io.StringIO())
            application = build_application(settings, debug_observer=session.observe)
            tunnel = mock.Mock()
            with mock.patch.object(ReCTMHTTPServer, "serve_forever", return_value=None):
                code = run_server(
                    application,
                    host="127.0.0.1",
                    port=0,
                    reveal_generated_oauth_password=True,
                    terminal_session=session,
                    quick_tunnel=tunnel,
                )
            self.assertEqual(code, 0)
            tunnel.start.assert_called_once()
            local_origin = tunnel.start.call_args.args[0]
            self.assertRegex(local_origin, r"^http://127\.0\.0\.1:\d+$")
            self.assertNotIn("/mcp", local_origin)
            tunnel.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
