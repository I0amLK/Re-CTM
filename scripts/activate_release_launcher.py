#!/usr/bin/env python3
"""Verify and activate the accepted local 0.4.1 launcher with a disposable startup rehearsal.

This operator helper is deliberately separate from runtime defaults. It preserves
the accepted local deployment roots and does not read or migrate private state.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import tempfile
import uuid
import time
import urllib.request

VERSION = "0.4.1"
WHEEL_SHA256 = "492ae13dca4f458dac048d8084883acb2426cea397e342fb9a9094a7762932cb"
VERIFY_INSTALLED = r"""
import hashlib, importlib.metadata, json, sys, zipfile
from pathlib import Path
import re_ctm
prefix = Path(sys.prefix).resolve()
package = Path(re_ctm.__file__).resolve().parent
assert package.is_relative_to(prefix), "Runtime is outside selected venv"
assert re_ctm.__version__ == importlib.metadata.version("re-ctm") == sys.argv[2]
with zipfile.ZipFile(sys.argv[1]) as archive:
    members = {n: archive.read(n) for n in archive.namelist()
               if n.startswith("re_ctm/") and not n.endswith("/")}
    installed = {str(p.relative_to(package.parent)): p for p in package.rglob("*")
                 if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    assert set(installed) == set(members), "Installed runtime file set differs"
    for name, data in members.items():
        assert not installed[name].is_symlink(), "Runtime symlink"
        assert installed[name].read_bytes() == data, "Installed runtime differs: " + name
print(json.dumps({"version": re_ctm.__version__, "runtime_files": len(members),
                  "module": str(package), "prefix": str(prefix)}))
"""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_environment(home: Path) -> dict[str, str]:
    return {"HOME": str(home), "PATH": os.environ.get("PATH", os.defpath),
            "TERM": os.environ.get("TERM", "xterm")}


def verify_install(repo: Path, home: Path) -> dict:
    installation = repo / ".local-install-0.4.1"
    wheel = installation / "re_ctm-0.4.1-py3-none-any.whl"
    if wheel.is_symlink() or digest(wheel) != WHEEL_SHA256:
        raise ValueError("Qualified wheel digest mismatch")
    report = json.loads((installation / "install-report.json").read_text())
    if (report.get("passed") is not True or report.get("version") != VERSION
            or report.get("qualified_wheel", {}).get("sha256") != WHEEL_SHA256):
        raise ValueError("Installation report is not the accepted candidate")
    python = installation / "venv/bin/python"
    completed = subprocess.run(
        [str(python), "-I", "-B", "-c", VERIFY_INSTALLED, str(wheel), VERSION],
        env=clean_environment(home), capture_output=True, text=True, check=True, timeout=30)
    return json.loads(completed.stdout)


def launcher_bytes(repo: Path, home: Path) -> bytes:
    workspace = repo / ".local-install/workspace"
    if not workspace.is_dir():
        raise ValueError("Accepted workspace is missing")
    data = home / ".re-ctm-0.4-local"
    q = shlex.quote
    # Use only the same ordinary values as the accepted env -i launch. Inherited
    # OAuth secrets, Python injection and stale 0.3 settings are not forwarded.
    return ("#!/bin/sh\n# Re-CTM accepted local release " + VERSION + "\n"
            "exec /usr/bin/env -i HOME=" + q(str(home))
            + ' PATH="' + str(home).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
            + '/.local/bin:$PATH" TERM="${TERM:-xterm}"'
            + " RE_CTM_WORKSPACE=" + q(str(workspace))
            + " RE_CTM_DATA_ROOT=" + q(str(data))
            + " RE_CTM_PRIVATE_ROOT=" + q(str(data / "private"))
            + " RE_CTM_NATIVE_EXEC_BACKEND=bubblewrap"
            + " RE_CTM_LATEX_POLICY=required RE_CTM_HOST=127.0.0.1 RE_CTM_PORT=0 "
            + q(str(repo / ".local-install-0.4.1/venv/bin/python"))
            + ' -I -B -m re_ctm "$@"\n').encode()


def _regular_or_link(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
        raise ValueError("Launcher must be a regular file or symlink")
    return True


def write_receipt(path: Path, receipt: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(receipt, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def publish_launcher(target: Path, content: bytes, evidence: Path) -> dict:
    """Publish one launcher, keeping a reversible backup and durable receipt."""
    if not target.parent.is_dir() or target.parent.is_symlink():
        raise ValueError("Launcher directory must exist and must not be a symlink")
    evidence.mkdir(parents=True, exist_ok=False)
    lock_path = target.parent / ".re-ctm-activation.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(lock_path, flags, 0o600), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        existed = _regular_or_link(target)
        backup = target.with_name("re-ctm.backup-" + uuid.uuid4().hex)
        if existed:
            shutil.copy2(target, backup, follow_symlinks=False)
        receipt = {"version": VERSION, "target": str(target), "backup": str(backup) if existed else None,
                   "launcher_sha256": hashlib.sha256(content).hexdigest(), "status": "prepared"}
        receipt_path = evidence / "activation.json"
        write_receipt(receipt_path, receipt)
        fd, temporary = tempfile.mkstemp(prefix=".re-ctm-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o755)
            os.replace(temporary, target)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
        receipt["status"] = "activated"
        return receipt


def rollback(receipt_path: Path) -> dict:
    receipt = json.loads(receipt_path.read_text())
    target = Path(receipt["target"])
    with os.fdopen(os.open(target.parent / ".re-ctm-activation.lock",
                           os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if target.is_symlink() or digest(target) != receipt["launcher_sha256"]:
            raise ValueError("Launcher changed since activation; refusing rollback")
        backup = receipt["backup"]
        if backup:
            source = Path(backup)
            if source.parent != target.parent or not source.name.startswith("re-ctm.backup-"):
                raise ValueError("Invalid launcher backup location")
            if not _regular_or_link(source):
                raise ValueError("Launcher backup is missing")
            os.replace(source, target)
        else:
            target.unlink()
        receipt["status"] = "rolled_back"
        write_receipt(receipt_path, receipt)
    return receipt


def check_path_target(target: Path) -> None:
    directories = [Path(p or os.curdir).absolute()
                   for p in os.environ.get("PATH", os.defpath).split(os.pathsep)]
    if target.parent not in directories:
        raise ValueError("~/.local/bin is not on PATH; add it in the host shell first")
    selected = shutil.which("re-ctm")
    if selected is not None and Path(selected).absolute() != target:
        raise ValueError("Another PATH entry shadows ~/.local/bin/re-ctm; resolve it first")


def smoke_launcher(repo: Path) -> dict:
    """Use the identical wrapper template with fresh fixture roots, no tunnel.

    Raw terminal bytes may contain the generated OAuth key. Keep them only in
    bounded memory and never include them in logs, exceptions or result JSON.
    """
    with tempfile.TemporaryDirectory(prefix="re-ctm-launcher-smoke-") as directory:
        root = Path(directory)
        home, workspace = root / "home", root / "workspace"
        home.mkdir()
        workspace.mkdir()
        launcher = root / "re-ctm"
        launcher.write_bytes(launcher_bytes(repo, home))
        launcher.chmod(0o755)
        child = subprocess.Popen(
            [str(launcher), "tui", "--native-mode", "dangerous", "--workspace", str(workspace)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            start_new_session=True)
        ready = False
        clean_exit = False
        try:
            assert child.stderr is not None
            with selectors.DefaultSelector() as selector:
                selector.register(child.stderr, selectors.EVENT_READ)
                captured = b""
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and child.poll() is None:
                    for key, _ in selector.select(timeout=0.2):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            break
                        captured = (captured + chunk)[-65536:]
                        match = re.search(rb"MCP URL\s+(http://127\.0\.0\.1:[0-9]+)/mcp", captured)
                        if match:
                            origin = match.group(1).decode("ascii")
                            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                            with opener.open(origin + "/.well-known/oauth-authorization-server",
                                             timeout=3) as response:
                                document = json.loads(response.read(65536))
                            if document.get("issuer") != origin:
                                raise ValueError("Launcher smoke OAuth origin mismatch")
                            ready = True
                            break
                    if ready:
                        break
            if not ready:
                raise ValueError("Launcher smoke did not reach attested loopback readiness; raw output withheld")
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
            clean_exit = child.returncode == 130
            if child.stderr is not None:
                child.stderr.close()
        if not clean_exit:
            raise ValueError("Launcher smoke did not shut down cleanly")
        return {"passed": True, "loopback_oauth_discovery": True, "owned_shutdown_exit_code": child.returncode,
                "native_backend": "bubblewrap", "latex_policy": "required",
                "scope": "Same launcher template; disposable roots, no public tunnel or live state."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-only", action="store_true")
    mode.add_argument("--activate", action="store_true")
    mode.add_argument("--rollback", type=Path, metavar="RECEIPT")
    args = parser.parse_args()
    if args.rollback:
        print(json.dumps(rollback(args.rollback), indent=2))
        return 0
    repo = Path(__file__).resolve().parents[1]
    home = Path.home().resolve()
    verified = verify_install(repo, home)
    content = launcher_bytes(repo, home)
    if args.check_only:
        print(json.dumps({"passed": True, "installed": verified,
                          "launcher_sha256": hashlib.sha256(content).hexdigest(),
                          "scope": "Read-only candidate check; host launcher unchanged."}, indent=2))
        return 0
    report = json.loads((repo / ".local-install-0.4.1/install-report.json").read_text())
    if str(repo / ".local-install-0.4.1") != report["installation_root"]:
        raise ValueError("Run activation on the ordinary host, not a relocated or sandbox mount")
    target = home / ".local/bin/re-ctm"
    check_path_target(target)
    smoke = smoke_launcher(repo)
    evidence = repo / ".release-validation" / ("launcher-" + uuid.uuid4().hex)
    result = publish_launcher(target, content, evidence)
    try:
        actual = subprocess.run([str(target), "--version"], capture_output=True, text=True,
                                check=True, timeout=30)
        if actual.stdout.strip() != "re-ctm " + VERSION:
            raise ValueError("Activated launcher version mismatch")
        result["verified"] = verified
        result["smoke"] = smoke
        result["version_output"] = actual.stdout.strip()
        result["status"] = "activated_verified"
        result["receipt"] = str(evidence / "activation.json")
        write_receipt(evidence / "activation.json", result)
    except (OSError, ValueError, subprocess.SubprocessError):
        rollback(evidence / "activation.json")
        raise
    result["next"] = "hash -r; re-ctm --version; re-ctm tui --quick-tunnel --native-mode dangerous"
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
