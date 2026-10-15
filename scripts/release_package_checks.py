#!/usr/bin/env python3
"""Offline package checks in a newly created, disposable directory.

Run this on the destination host. Do not relocate the generated venv: its console
entry points deliberately retain the interpreter path at installation time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SOURCE_ITEMS = (
    "src", "tests", "scripts", "docs", "AGENTS.md", "pyproject.toml", "README.md", "LICENSE",
    "NOTICE", "engineering-graph.json", "code-optimization-graph.json",
    "manual-validation.json", "project-progress.json", "config.example.env", "MANIFEST.in",
)
FIXTURE_MODULES = (
    "test_native_catalog_v11", "test_command_v11", "test_command_parent_lifetime",
    "test_methodology", "test_rethlas_contracts",
    "test_protocol3_workflow", "test_research_state", "test_storage_recovery",
    "test_storage_boundaries", "test_fact_store", "test_fact_memory",
    "test_fact_workflow", "test_submission_recovery_integration",
    "test_packaged_engineering_graph", "test_release_package_checks", "test_activate_release_launcher",
)
INSPECT_INSTALLED = r"""
import hashlib, importlib, importlib.metadata, json, pkgutil, sys
from importlib.resources import files
from pathlib import Path
import re_ctm
from re_ctm.native_catalog import NATIVE_TOOL_NAMES, TOOL_CONTRACT_VERSION
from re_ctm.rethlas_contracts import RETHLAS_TOOL_NAMES
from re_ctm.storage import STATE_SCHEMA_VERSION
prefix = Path(sys.prefix).resolve()
assert Path(re_ctm.__file__).resolve().is_relative_to(prefix)
modules = []
for found in pkgutil.walk_packages(re_ctm.__path__, re_ctm.__name__ + "."):
    if found.name.endswith(".__main__"):
        continue
    module = importlib.import_module(found.name)
    assert Path(module.__file__).resolve().is_relative_to(prefix), module.__file__
    modules.append(found.name)
resources = {}
for name in ("methodology.json", "methodology_protocol3.json", "engineering-graph.json"):
    data = files("re_ctm").joinpath("resources/" + name).read_bytes()
    json.loads(data)
    resources[name] = hashlib.sha256(data).hexdigest()
assert re_ctm.__version__ == importlib.metadata.version("re-ctm")
assert len(NATIVE_TOOL_NAMES) == 19 and len(RETHLAS_TOOL_NAMES) == 6
assert TOOL_CONTRACT_VERSION == "mtm-tools-v11" and STATE_SCHEMA_VERSION == 8
print(json.dumps({"version": re_ctm.__version__, "module_file": re_ctm.__file__,
    "imported_modules": modules, "resources_sha256": resources,
    "catalog": list(NATIVE_TOOL_NAMES) + list(RETHLAS_TOOL_NAMES),
    "tool_contract": TOOL_CONTRACT_VERSION, "schema": STATE_SCHEMA_VERSION}, indent=2))
"""
RUN_FIXTURES = r"""
import json, sys, unittest
from pathlib import Path
import re_ctm
assert Path(re_ctm.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
sys.path.insert(0, sys.argv[1])
suite = unittest.defaultTestLoader.loadTestsFromNames(json.loads(sys.argv[2]))
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
"""


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_files(repo: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in SOURCE_ITEMS:
        root = repo / name
        if root.is_symlink():
            raise ValueError(f"Package snapshot refuses a source symlink: {name}")
        if not root.exists():
            continue
        paths = root.rglob("*") if root.is_dir() else [root]
        for path in paths:
            relative = path.relative_to(repo)
            if any(part == "__pycache__" or part.endswith(".egg-info") for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"Package snapshot refuses a source symlink: {relative}")
            if path.is_file() and path.suffix != ".pyc":
                result[str(relative)] = _digest(path)
    return dict(sorted(result.items()))


def run_package_checks(
    repo: Path, output_dir: Path, python: str = sys.executable
) -> dict[str, Any]:
    """Build, install and inspect offline; return the persisted evidence report."""
    repo = repo.resolve()
    output_dir = output_dir.absolute()
    if any(path.is_symlink() for path in (output_dir, *output_dir.parents)):
        raise ValueError("Package output must not use a symlink or symlink ancestor.")
    output_dir = output_dir.resolve()
    if repo.is_relative_to(output_dir):
        raise ValueError("Package output must not equal or contain the source repository.")
    if any(output_dir.is_relative_to(repo / item) for item in ("src", "tests", "scripts", "docs")):
        raise ValueError("Package output must be outside source-input directories.")
    output_dir.mkdir(parents=True, exist_ok=False)
    source, dist = output_dir / "source", output_dir / "dist"
    source.mkdir()
    dist.mkdir()
    for directory in ("home", "tmp"):
        (output_dir / directory).mkdir()
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(output_dir / "home"),
        "TMPDIR": str(output_dir / "tmp"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "SOURCE_DATE_EPOCH": "1791936000",
    }
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "passed": False,
        "environment": {"python": sys.version, "builder_python": python, "platform": sys.platform},
        "source_root": str(repo),
        "checks": checks,
        "artifacts": [],
        "installed": {},
        "console_shebangs": {},
        "limitations": [
            "Offline packaging and deterministic installed fixtures only.",
            "No production service, live database, real browser, Native isolation or real LaTeX acceptance.",
            "Venv entry points are valid only at their original installation path; do not relocate.",
        ],
    }

    def run(name: str, argv: list[str], cwd: Path) -> str:
        completed = subprocess.run(
            argv, cwd=cwd, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240, check=False,
        )
        log = output_dir / (name + ".log")
        log.write_text(completed.stdout, encoding="utf-8")
        checks.append({
            "name": name, "argv": argv, "cwd": str(cwd),
            "exit_code": completed.returncode, "passed": completed.returncode == 0,
            "log": str(log), "output_tail": completed.stdout[-12000:],
        })
        if completed.returncode:
            raise RuntimeError(f"{name} failed with exit code {completed.returncode}; see {log}")
        return completed.stdout

    try:
        source_files = _source_files(repo)
        for relative in source_files:
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repo / relative, destination)
        copied = _source_files(source)
        if copied != source_files:
            raise RuntimeError("Source changed during snapshot; rerun after source freeze.")
        manifest = json.dumps(source_files, sort_keys=True, indent=2) + "\n"
        (output_dir / "source-sha256.json").write_text(manifest, encoding="utf-8")
        report["source_manifest_sha256"] = hashlib.sha256(manifest.encode()).hexdigest()
        versions = run("build-environment", [python, "-I", "-c",
            "import importlib.metadata as m,json,sys; "
            "print(json.dumps({'python':sys.version,'executable':sys.executable,"
            "'versions':{x:m.version(x) for x in ['pip','setuptools','wheel']}}))"], output_dir)
        report["environment"]["build"] = json.loads(versions)
        run("build-sdist", [python, "-I", "-c",
            "import setuptools.build_meta as b; print(b.build_sdist(" + repr(str(dist)) + "))"], source)
        sdists = list(dist.glob("*.tar.gz"))
        if len(sdists) != 1:
            raise RuntimeError("Expected exactly one built sdist.")
        unpacked = output_dir / "sdist-unpacked"
        unpacked.mkdir()
        with tarfile.open(sdists[0]) as archive:
            if not hasattr(tarfile, "data_filter"):
                raise RuntimeError("This Python lacks tarfile.data_filter; use a current supported Python.")
            archive.extractall(unpacked, filter="data")
        roots = list(unpacked.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise RuntimeError("Unexpected sdist root structure.")
        sdist_files = _source_files(roots[0])
        if sdist_files != source_files:
            missing = sorted(set(source_files) - set(sdist_files))
            changed = sorted(key for key in source_files.keys() & sdist_files.keys()
                if source_files[key] != sdist_files[key])
            raise RuntimeError(f"Sdist source mismatch: missing={missing}, changed={changed}")
        report["sdist_source_exact"] = True
        run("sdist-compileall", [python, "-I", "-m", "compileall", "-q", "src", "scripts", "tests"], roots[0])
        for validator in ("validate_engineering_graph.py", "validate_code_optimization_graph.py",
                          "audit_error_contract.py", "validate_documentation_consistency.py"):
            run("sdist-" + validator.removesuffix(".py"), [python, "scripts/" + validator], roots[0])
        run("build-wheel", [python, "-I", "-c",
            "import setuptools.build_meta as b; print(b.build_wheel(" + repr(str(dist)) + "))"], roots[0])
        wheels = list(dist.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError("Expected exactly one built wheel.")
        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as archive:
            members = archive.namelist()
            for relative, expected in source_files.items():
                if relative.startswith("src/re_ctm/"):
                    packaged = relative.removeprefix("src/")
                    actual = hashlib.sha256(archive.read(packaged)).hexdigest()
                    if actual != expected:
                        raise RuntimeError(f"Wheel source mismatch: {packaged}")
            (output_dir / "wheel-members.json").write_text(json.dumps(members, indent=2) + "\n")
        report["artifacts"] = [
            {"file": str(path), "bytes": path.stat().st_size, "sha256": _digest(path)}
            for path in sorted(dist.iterdir()) if path.is_file()
        ]
        venv = output_dir / "venv"
        run("create-venv", [python, "-m", "venv", str(venv)], output_dir)
        installed_python = str(venv / "bin/python")
        run("install-wheel", [installed_python, "-I", "-m", "pip", "install",
            "--no-index", "--no-deps", str(wheel)], output_dir)
        run("pip-check", [installed_python, "-I", "-m", "pip", "check"], output_dir)
        for executable in ("re-ctm", "re-ctm-native-helper"):
            path = venv / "bin" / executable
            report["console_shebangs"][executable] = path.read_text().splitlines()[0]
            for option in ("--version", "--help"):
                run(executable + "-" + option.removeprefix("--"), [str(path), option], output_dir)
        run("console-validate-graph", [str(venv / "bin/re-ctm"), "validate-graph"], output_dir)
        installed = run("installed-imports", [installed_python, "-I", "-c", INSPECT_INSTALLED], output_dir)
        report["installed"] = json.loads(installed)
        run("installed-fixtures", [installed_python, "-I", "-c", RUN_FIXTURES,
            str(source / "tests"), json.dumps(FIXTURE_MODULES)], output_dir)
        report["source_unchanged"] = _source_files(repo) == source_files
        if not report["source_unchanged"]:
            raise RuntimeError("Source changed after snapshot; artifacts are not current-source evidence.")
        report["passed"] = all(check["passed"] for check in checks)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, tarfile.TarError, KeyError) as error:
        report["failure"] = str(error)
        report["passed"] = False
    report["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_package_checks(args.repo, args.output_dir)
    print(json.dumps({"passed": report["passed"], "report": str(args.output_dir.resolve() / "report.json")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
