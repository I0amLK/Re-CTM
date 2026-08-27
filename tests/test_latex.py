from __future__ import annotations

import tempfile
import unittest
import shutil
import sys
from pathlib import Path

from re_ctm.enums import LatexPolicy
from re_ctm.latex import LatexGate


class LatexGateTestCase(unittest.TestCase):
    def test_static_document_passes(self) -> None:
        source = r"""\documentclass{article}
\begin{document}
Hello $x^2$.
\end{document}
"""
        with tempfile.TemporaryDirectory() as temp:
            result = LatexGate(LatexPolicy.STATIC_ONLY).validate(source, Path(temp))
        self.assertTrue(result.gate_passed)
        self.assertTrue(result.static_valid)

    def test_external_input_is_rejected(self) -> None:
        source = r"""\documentclass{article}
\begin{document}
\input{secret.tex}
\end{document}
"""
        with tempfile.TemporaryDirectory() as temp:
            result = LatexGate(LatexPolicy.STATIC_ONLY).validate(source, Path(temp))
        self.assertFalse(result.gate_passed)
        self.assertTrue(any("input" in error for error in result.errors))

    def test_common_external_file_dependencies_are_rejected(self) -> None:
        source = r"""\documentclass{article}
\usepackage{graphicx}
\begin{document}
\includegraphics{host-file.pdf}
\end{document}
"""
        with tempfile.TemporaryDirectory() as temp:
            result = LatexGate(LatexPolicy.STATIC_ONLY).validate(source, Path(temp))
        self.assertFalse(result.gate_passed)
        self.assertTrue(any("external_graphic" in error for error in result.errors))

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap") and shutil.which("latexmk"),
        "isolated latexmk integration requires Linux, bubblewrap, and latexmk",
    )
    def test_required_policy_compiles_inside_bubblewrap(self) -> None:
        source = r"""\documentclass{article}
\begin{document}
Hello $x^2$.
\end{document}
"""
        with tempfile.TemporaryDirectory() as temp:
            result = LatexGate(LatexPolicy.REQUIRED).validate(source, Path(temp))
        self.assertTrue(result.static_valid)
        self.assertTrue(result.compile_attempted)
        self.assertTrue(result.compile_passed)
        self.assertTrue(result.gate_passed)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap") and shutil.which("latexmk"),
        "isolated latexmk integration requires Linux, bubblewrap, and latexmk",
    )
    def test_required_policy_cannot_read_host_absolute_class(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = Path(temp)
            host_class = workdir / "host-secret.cls"
            host_class.write_text(
                "\\NeedsTeXFormat{LaTeX2e}\n"
                "\\ProvidesClass{host-secret}\n"
                "\\LoadClass{article}\n",
                encoding="utf-8",
            )
            class_path = host_class.with_suffix("").as_posix()
            source = (
                f"\\documentclass{{{class_path}}}\n"
                "\\begin{document}\n"
                "Host file must be hidden.\n"
                "\\end{document}\n"
            )
            result = LatexGate(LatexPolicy.REQUIRED).validate(source, workdir / "compile")
        self.assertTrue(result.static_valid)
        self.assertTrue(result.compile_attempted)
        self.assertFalse(result.compile_passed)
        self.assertFalse(result.gate_passed)


if __name__ == "__main__":
    unittest.main()
