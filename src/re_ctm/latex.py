from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .enums import LatexPolicy, NativeMode
from .errors import ReCTMError
from .latex_scan import LatexScanError, scan_source
from .native import BubblewrapExecBackend


_FORBIDDEN = {
    "shell_escape": re.compile(r"\\(?:immediate\s*)?write18\b", re.I),
    # TeX control words stop before digits, unlike regex word boundaries.
    "input": re.compile(r"\\(?:input|include|includeonly)(?![a-zA-Z])", re.I | re.ASCII),
    "file_write": re.compile(r"\\(?:openout|write|read)(?![a-zA-Z])", re.I | re.ASCII),
    "file_read": re.compile(r"\\(?:openin|newread|readline)(?![a-zA-Z])", re.I | re.ASCII),
    "shellesc_package": re.compile(r"\\usepackage(?:\[[^\]]*\])?\{shellesc\}", re.I),
    "bibliography_file": re.compile(r"\\(?:bibliography|addbibresource)(?![a-zA-Z])", re.I | re.ASCII),
    "external_graphic": re.compile(r"\\includegraphics(?![a-zA-Z])", re.I | re.ASCII),
    "external_listing": re.compile(r"\\(?:lstinputlisting|verbatiminput|includepdf)(?![a-zA-Z])", re.I | re.ASCII),
    "external_auxiliary": re.compile(r"\\externaldocument(?![a-zA-Z])", re.I | re.ASCII),
}


@dataclass(frozen=True)
class LatexValidationResult:
    policy: str
    static_valid: bool
    compile_attempted: bool
    compile_available: bool
    compile_passed: bool
    gate_passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    compiler_output: str = ""

    def to_payload(self) -> dict[str, object]:
        return asdict(self)


class LatexGate:
    def __init__(
        self,
        policy: LatexPolicy,
        *,
        timeout_seconds: int = 120,
        output_limit: int = 32_000,
    ) -> None:
        self.policy = policy
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit

    def validate(self, content: str, workdir: Path) -> LatexValidationResult:
        errors = _static_errors(content)
        warnings: list[str] = []
        static_valid = not errors
        latexmk = shutil.which("latexmk")
        bubblewrap = shutil.which("bwrap")
        compile_available = latexmk is not None and bubblewrap is not None
        compile_attempted = False
        compile_passed = False
        compiler_output = ""

        if static_valid and self.policy != LatexPolicy.STATIC_ONLY:
            if latexmk is None:
                warnings.append("latexmk is unavailable in the current environment")
            elif bubblewrap is None:
                warnings.append(
                    "bubblewrap is unavailable; Re-CTM refuses to compile model-generated LaTeX on the host"
                )
            else:
                compile_attempted = True
                workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
                with tempfile.TemporaryDirectory(prefix="re-ctm-latex-") as raw_scratch:
                    scratch = Path(raw_scratch)
                    source = scratch / "proof.tex"
                    source.write_text(content, encoding="utf-8")
                    try:
                        backend = BubblewrapExecBackend(output_limit=max(self.output_limit * 2, 65_536))
                        backend.attest(
                            workspace=scratch,
                            forbidden_paths=(workdir.resolve(strict=False),),
                        )
                        result = backend.execute(
                            workspace=scratch,
                            argv=[
                                latexmk,
                                "-pdf",
                                "-interaction=nonstopmode",
                                "-halt-on-error",
                                "-no-shell-escape",
                                "proof.tex",
                            ],
                            workdir=".",
                            timeout_ms=self.timeout_seconds * 1000,
                            mode=NativeMode.SAFE,
                        )
                        compiler_output = (
                            str(result.get("stdout") or "")
                            + ("\n" if result.get("stdout") and result.get("stderr") else "")
                            + str(result.get("stderr") or "")
                        )[-self.output_limit :]
                        compile_passed = (
                            result.get("exit_code") == 0
                            and result.get("timed_out") is not True
                            and (scratch / "proof.pdf").is_file()
                        )
                        if result.get("timed_out") is True:
                            errors.append(f"latexmk timed out after {self.timeout_seconds} seconds")
                        elif not compile_passed:
                            errors.append(f"latexmk exited with code {result.get('exit_code')}")
                    except ReCTMError as exc:
                        errors.append(f"isolated LaTeX compiler failed: {exc.code}")
                        compiler_output = exc.message[-self.output_limit :]
                    (workdir / "compiler.log").write_text(
                        compiler_output,
                        encoding="utf-8",
                    )

        if self.policy == LatexPolicy.STATIC_ONLY:
            compile_passed = static_valid
            warnings.append("static_only policy does not prove target LaTeX toolchain compatibility")
        elif self.policy == LatexPolicy.IF_AVAILABLE and not compile_available:
            compile_passed = static_valid
        gate_passed = static_valid and compile_passed
        return LatexValidationResult(
            policy=self.policy.value,
            static_valid=static_valid,
            compile_attempted=compile_attempted,
            compile_available=compile_available,
            compile_passed=compile_passed,
            gate_passed=gate_passed,
            errors=errors,
            warnings=warnings,
            compiler_output=compiler_output,
        )


def _static_errors(content: str) -> list[str]:
    errors: list[str] = []
    if not content.strip():
        return ["proof.tex is empty"]
    if len(content.encode("utf-8")) > 2 * 1024 * 1024:
        return ["proof.tex exceeds the 2 MiB source limit"]
    try:
        views = scan_source(content)
    except LatexScanError as exc:
        return [str(exc)]
    stripped = views.structure
    if not re.search(r"\\documentclass(?:\[[^\]]*\])?\{[^}]+\}", stripped):
        errors.append("missing documentclass")
    if stripped.count("\\begin{document}") != 1:
        errors.append("proof.tex must contain exactly one \\begin{document}")
    if stripped.count("\\end{document}") != 1:
        errors.append("proof.tex must contain exactly one \\end{document}")
    if stripped.find("\\begin{document}") > stripped.find("\\end{document}") >= 0:
        errors.append("document environment is out of order")
    if not _balanced_braces(stripped):
        errors.append("unbalanced LaTeX braces")
    for name, pattern in _FORBIDDEN.items():
        # Literal masking is only a structural convenience, not evidence that
        # arbitrary macros/packages cannot execute the apparent literal body.
        if pattern.search(views.operations):
            errors.append(f"forbidden LaTeX operation: {name}")
    return errors


def static_latex_errors(content: str) -> list[str]:
    """Return the same content-safety errors used before isolated compilation.

    This is intentionally narrower than a full LaTeX gate: callers such as
    portable project-summary generation can reject external file/shell behavior
    without compiling a non-proof artifact or weakening proof compilation policy.
    """

    return _static_errors(content)


def _balanced_braces(content: str) -> bool:
    depth = 0
    escaped = False
    for character in content:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0
