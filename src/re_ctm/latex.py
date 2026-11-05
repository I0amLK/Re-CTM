from __future__ import annotations

import re
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .enums import LatexPolicy
from .errors import ReCTMError
from .latex_scan import LatexScanError, scan_source
from .native_exec import ExecInvocation, find_host_executable, prepare_host_command
from .processes import CommandManager
from .toolchains import host_command_environment


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
_LOADER = re.compile(
    r"\\(?:documentclass|usepackage|RequirePackage(?:WithOptions)?|LoadClass(?:WithOptions)?)(?![a-zA-Z])",
    re.I | re.ASCII,
)
_LITERAL_LOAD_ARGUMENT = re.compile(r"\s*(?:\[[^\]]*\]\s*)?\{([^{}]*)\}")
_PACKAGE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", re.ASCII)


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
    compile_backend: str = "not_run"
    os_sandbox: bool = False

    def to_payload(self) -> dict[str, object]:
        return asdict(self)


class LatexGate:
    def __init__(
        self,
        policy: LatexPolicy,
        *,
        timeout_seconds: int = 120,
        output_limit: int = 32_000,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.policy = policy
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit
        self.environment = host_command_environment(environment=environment)

    def validate(self, content: str, workdir: Path) -> LatexValidationResult:
        errors = _static_errors(content)
        warnings: list[str] = []
        static_valid = not errors
        compile_available = find_host_executable(
            "latexmk", workdir=workdir, environment=self.environment,
        ) is not None
        compile_attempted = False
        compile_passed = False
        compiler_output = ""

        if static_valid and self.policy != LatexPolicy.STATIC_ONLY:
            workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix="re-ctm-latex-") as raw_scratch:
                scratch = Path(raw_scratch).resolve()
                environment = {**self.environment, "TMPDIR": str(scratch),
                               "openin_any": "p", "openout_any": "p", "shell_escape": "f"}
                latexmk = find_host_executable("latexmk", workdir=scratch, environment=environment)
                compile_available = latexmk is not None
                if latexmk is None:
                    message = "latexmk is unavailable in the host compiler PATH"
                    if self.policy == LatexPolicy.REQUIRED:
                        errors.append(message)
                    else:
                        warnings.append(message)
                else:
                    compile_attempted = True
                    warnings.append("LaTeX compilation uses host account permissions without an OS sandbox")
                    source = scratch / "proof.tex"
                    source.write_text(content, encoding="utf-8")
                    manager = CommandManager()
                    try:
                        invocation = ExecInvocation.parse({
                            "argv": [str(latexmk), "-norc", "-pdf", "-interaction=nonstopmode",
                                     "-halt-on-error", "-no-shell-escape", "proof.tex"],
                            "timeout_ms": self.timeout_seconds * 1000,
                        })
                        command, facts = prepare_host_command(invocation, workdir=scratch, environment=environment)
                        current, current_facts = prepare_host_command(invocation, workdir=scratch, environment=environment)
                        if current != command or current_facts != facts:
                            raise ReCTMError(
                                "NATIVE_EXECUTABLE_CHANGED", "Compiler executable metadata changed before start.",
                                category="security",
                            )
                        result = manager.start(
                            command, env=environment, cwd=str(scratch), creator_thread_required=False,
                            timeout_ms=invocation.timeout_ms, yield_time_ms=30_000,
                            max_output_bytes=min(self.output_limit, 1_048_576), stdin_text="",
                            tty=False, verbosity="full", preview_bytes=4096,
                        )
                        while True:
                            chunk = str(result.get("stdout") or "") + "\n" + str(result.get("stderr") or "")
                            compiler_output = (compiler_output + chunk)[-self.output_limit :]
                            if result.get("status") != "running":
                                break
                            result = manager.poll(
                                result["command_id"], chars="", yield_time_ms=30_000,
                                max_output_bytes=min(self.output_limit, 1_048_576), verbosity="full", preview_bytes=4096,
                            )
                        pdf = scratch / "proof.pdf"
                        fresh_pdf = False
                        if pdf.is_file() and not pdf.is_symlink():
                            with pdf.open("rb") as artifact:
                                fresh_pdf = artifact.read(5) == b"%PDF-"
                        compile_passed = (
                            result.get("exit_code") == 0
                            and result.get("timed_out") is not True
                            and fresh_pdf
                        )
                        if result.get("timed_out") is True:
                            errors.append(f"latexmk timed out after {self.timeout_seconds} seconds")
                        elif result.get("exit_code") != 0:
                            errors.append(f"latexmk exited with code {result.get('exit_code')}")
                        elif not fresh_pdf:
                            errors.append("latexmk did not produce a fresh regular PDF in this compilation")
                    except ReCTMError as exc:
                        errors.append(f"host LaTeX compiler failed: {exc.code}")
                        compiler_output = exc.message[-self.output_limit :]
                    except OSError:
                        errors.append("host LaTeX compiler could not start or produce a readable artifact")
                    finally:
                        manager.close()
            (workdir / "compiler.log").write_text(compiler_output, encoding="utf-8")

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
            compile_backend="host" if compile_attempted else "not_run",
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
    # Host TeX may accept explicit class/package filenames even with openin_any=p.
    # Require literal search-path names before compiling; this static policy is
    # not an OS sandbox and cannot isolate arbitrary TeX/package behavior.
    for loader in _LOADER.finditer(views.operations):
        argument = _LITERAL_LOAD_ARGUMENT.match(views.operations, loader.end())
        if argument is None or any(
            _PACKAGE_NAME.fullmatch(name.strip()) is None
            for name in argument.group(1).split(",")
        ):
            errors.append("forbidden LaTeX operation: external_or_dynamic_class_package")
            break
    return errors


def static_latex_errors(content: str) -> list[str]:
    """Return the same content-safety errors used before host compilation.

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
