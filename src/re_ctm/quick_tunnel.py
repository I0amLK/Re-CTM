from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import urllib.parse
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from .terminal_ui import TerminalSession


_URL_CANDIDATE = re.compile(r"https://[^\s<>\"']+")
_TRY_CLOUDFLARE_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.trycloudflare\.com"
)
_MAX_LOG_CHUNK = 16_384
_SECRET_ENV_KEYS = frozenset(
    {
        "RE_CTM_OAUTH_PASSWORD",
        "RE_CTM_TOKEN_SECRET",
        "RE_CTM_CAPABILITY_SECRET",
        "TUNNEL_ORIGIN_CERT",
        "TUNNEL_CRED_FILE",
        "TUNNEL_CRED_CONTENTS",
        "TUNNEL_TOKEN",
        "TUNNEL_TOKEN_FILE",
    }
)


def extract_quick_tunnel_origin(text: str) -> str | None:
    """Return the first strict TryCloudflare HTTPS origin in one log chunk."""

    for match in _URL_CANDIDATE.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?)]}")
        try:
            parsed = urllib.parse.urlsplit(candidate)
            _ = parsed.port
        except ValueError:
            continue
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or _TRY_CLOUDFLARE_HOST.fullmatch(hostname) is None
        ):
            continue
        return f"https://{hostname}"
    return None


class QuickTunnel:
    """Own one opt-in cloudflared Quick Tunnel process and its output reader."""

    def __init__(
        self,
        terminal_session: TerminalSession,
        *,
        executable: str | None = None,
    ) -> None:
        self.terminal_session = terminal_session
        self.executable = executable
        self._process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._stopping = threading.Event()
        self._published_origin = ""

    def start(self, local_origin: str) -> bool:
        if self._process is not None or self._stopping.is_set():
            return False
        executable = self.executable or shutil.which("cloudflared")
        if not executable:
            self.terminal_session.show_tunnel_status(
                "unavailable: cloudflared not found; local MCP remains available"
            )
            return False
        environment = os.environ.copy()
        for key in _SECRET_ENV_KEYS:
            environment.pop(key, None)
        try:
            process = subprocess.Popen(
                [
                    executable,
                    "tunnel",
                    "--config",
                    os.devnull,
                    "--no-autoupdate",
                    "--url",
                    local_origin,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=environment,
            )
        except OSError as exc:
            self.terminal_session.show_tunnel_status(
                f"unavailable: failed to start cloudflared ({type(exc).__name__})"
            )
            return False
        self._process = process
        self.terminal_session.show_tunnel_status("starting")
        self._reader = threading.Thread(
            target=self._read_output,
            name="re-ctm-quick-tunnel",
            daemon=True,
        )
        self._reader.start()
        return True

    def close(self) -> None:
        self._stopping.set()
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
        reader = self._reader
        if reader is not None:
            reader.join(timeout=0.2)

    def _read_output(self) -> None:
        process = self._process
        stream: TextIO | None = process.stdout if process is not None else None
        if process is None or stream is None:
            return
        while not self._stopping.is_set():
            chunk = stream.readline(_MAX_LOG_CHUNK)
            if chunk == "":
                break
            origin = extract_quick_tunnel_origin(chunk)
            if origin and origin != self._published_origin:
                self._published_origin = origin
                self.terminal_session.show_public_mcp_url(origin.rstrip("/") + "/mcp")
                self.terminal_session.show_tunnel_status("connected")
        return_code = process.poll()
        if return_code is None:
            try:
                return_code = process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                return
        if self._stopping.is_set():
            return
        if self._published_origin:
            self.terminal_session.show_tunnel_status(
                f"disconnected: cloudflared exited with code {return_code}"
            )
        else:
            self.terminal_session.show_tunnel_status(
                f"unavailable: cloudflared exited with code {return_code}; local MCP remains available"
            )
