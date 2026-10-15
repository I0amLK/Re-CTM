from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from re_ctm.enums import LatexPolicy, NativeMode
from re_ctm.latex import LatexGate, static_latex_errors
from re_ctm.latex_scan import scan_source


def document(body: str) -> str:
    return (
        "\\documentclass{article}\n\\usepackage{fancyvrb}\n"
        f"\\begin{{document}}\n{body}\n\\end{{document}}\n"
    )


# MTM's verbatim-appendix.tex compiler fixture; tested here at the static boundary.
VERBATIM_APPENDIX = r"""\documentclass{article}
\usepackage{fancyvrb}
\begin{document}
A literal source appendix must not become another active document.
\begin{Verbatim}[fontsize=\small,numbers=left,frame=single]
\documentclass{article}
\begin{document}
\bibliography{references}
% A literal unmatched brace: {
\end{document}
\end{Verbatim}
Inline example: \verb|\input{literal}|.
\end{document}
"""


class LatexLiteralScanTestCase(unittest.TestCase):
    def test_source_appendix_is_literal_not_another_document(self) -> None:
        for environment in ("verbatim", "verbatim*", "Verbatim", "Verbatim*"):
            with self.subTest(environment=environment):
                body = (
                    f"\\begin{{{environment}}}\n"
                    "\\documentclass{article}\n\\begin{document}\n"
                    "Literal source body.\n\\end{document}\n"
                    "% literal percent and unmatched brace {\n"
                    f"\\end{{{environment}}}"
                )
                self.assertEqual(static_latex_errors(document(body)), [])

    def test_inline_literals_and_unicode_preserve_outer_structure(self) -> None:
        for body in (
            r"\verb|\begin{document} % { literal|",
            r"\verb*+\end{document} } literal+",
            r"中文 \verb|数学 { % }| 正文",
            "\\begin{Verbatim}\r\n数学 { % literal\r\n\\end{Verbatim}",
        ):
            with self.subTest(body=body):
                self.assertEqual(static_latex_errors(document(body)), [])

    def test_bounded_local_and_global_options_are_supported(self) -> None:
        for body in (
            "\\begin{Verbatim}[fontsize=\\small,numbers=left,frame=single,numbersep=4pt]\n"
            "\\begin{document}\n\\end{Verbatim}",
            "\\fvset{fontsize=\\footnotesize,showspaces=false,tabsize=4}\n"
            "\\begin{Verbatim}\n{\n\\end{Verbatim}",
            "\\begin{Verbatim*}[showspaces,showtabs=false,resetmargins=true,samepage=false,"
            "gobble=+000009,tabsize=64,framesep=.5em,framerule=0pt,xleftmargin=-2mm,xrightmargin=1.in]\n"
            "Unmatched literal brace {\n\\end{Verbatim*}",
        ):
            with self.subTest(body=body):
                self.assertEqual(static_latex_errors(document(body)), [])

    def test_all_active_forbidden_operations_on_both_sides_are_rejected(self) -> None:
        literal = "\\begin{Verbatim}\n{ literal\n\\end{Verbatim}"
        for operation, category in (
            (r"\write18{payload}", "shell_escape"),
            (r"\input{active}", "input"),
            (r"\openout1=file", "file_write"),
            (r"\openin1=file", "file_read"),
            (r"\usepackage{shellesc}", "shellesc_package"),
            (r"\bibliography{active}", "bibliography_file"),
            (r"\includegraphics{active}", "external_graphic"),
            (r"\lstinputlisting{active}", "external_listing"),
            (r"\externaldocument{active}", "external_auxiliary"),
        ):
            for body in (f"{operation}\n{literal}", f"{literal}\n{operation}"):
                with self.subTest(operation=operation, body=body):
                    self.assertIn(
                        f"forbidden LaTeX operation: {category}",
                        static_latex_errors(document(body)),
                    )

    def test_literal_bodies_never_hide_forbidden_operations(self) -> None:
        for operation, category in (
            (r"\write18{payload}", "shell_escape"),
            (r"\input{external}", "input"),
            (r"\openout1=file", "file_write"),
            (r"\openin1=file", "file_read"),
            (r"\usepackage{shellesc}", "shellesc_package"),
            (r"\bibliography{external}", "bibliography_file"),
            (r"\includegraphics{external}", "external_graphic"),
            (r"\lstinputlisting{external}", "external_listing"),
            (r"\externaldocument{external}", "external_auxiliary"),
        ):
            bodies = [f"\\verb|% {operation}|", f"\\verb*+% {operation}+"]
            bodies.extend(
                f"\\begin{{{environment}}}\n% {operation}\n\\end{{{environment}}}"
                for environment in ("verbatim", "verbatim*", "Verbatim", "Verbatim*")
            )
            for body in bodies:
                with self.subTest(body=body):
                    self.assertIn(
                        f"forbidden LaTeX operation: {category}", static_latex_errors(document(body))
                    )

    def test_first_raw_terminator_does_not_hide_active_trailing_text(self) -> None:
        for environment in ("verbatim", "Verbatim"):
            for prefix in ("", "%", "\\", "literal "):
                with self.subTest(environment=environment, prefix=prefix):
                    body = (
                        f"\\begin{{{environment}}}\n{prefix}\\end{{{environment}}}"
                        f"\\input{{active}}\n\\end{{{environment}}}"
                    )
                    self.assertIn(
                        "forbidden LaTeX operation: input", static_latex_errors(document(body))
                    )

    def test_malformed_literal_contexts_fail_closed(self) -> None:
        for body in (
            "\\begin{Verbatim}\nunterminated",
            "\\verb|unterminated\n",
            "\\verb",
            "\\verb text ",
            "\\verbétexté",
            "\\begin{Verbatim}inline\\end{Verbatim}",
            "text \\begin{Verbatim}\nbody\n\\end{Verbatim}",
            "{\n\\begin{Verbatim}\nbody\n\\end{Verbatim}\n}",
            "{\\verb|\\input{active}|}",
            "\\begin{verbatim}[frame=single]\nbody\n\\end{verbatim}",
        ):
            with self.subTest(body=body):
                self.assertTrue(static_latex_errors(document(body)))

    def test_executable_and_unknown_literal_options_fail_closed(self) -> None:
        for option in (
            r"commandchars=\\\{\}",
            r"formatcom=\input{active}",
            r"codes=\relax",
            "unknown=true",
            "tabsize=0",
            "tabsize=65",
            "gobble=10",
            "numbers=both",
            "showspaces=1",
            "numbersep=1.2.3pt",
            r"fontsize=\input{active}",
            r"framesep=\baselineskip",
        ):
            with self.subTest(option=option):
                body = f"\\begin{{Verbatim}}[{option}]\ntext\n\\end{{Verbatim}}"
                errors = static_latex_errors(document(body))
                self.assertTrue(any("unsupported LaTeX literal configuration" in e for e in errors))

    def test_reconfiguration_before_and_after_literals_fails_closed(self) -> None:
        literal = "\\begin{Verbatim}\ntext\n\\end{Verbatim}"
        for configuration in (
            r"\fvset{codes=\relax}",
            r"\fvset",
            r"\setkeys{FV}{commandchars=![]}",
            r"\makeatletter",
            r"\renewenvironment{Verbatim}{}{}",
            r"\def\verb{}",
            r"\let\verb\relax",
            r"\AddToHook{env/Verbatim/begin}{}",
            r"\iffalse",
            r"\catcode`!=0",
            r"^^5cinput{active}",
        ):
            for body in (f"{configuration}\n{literal}", f"{literal}\n{configuration}"):
                with self.subTest(body=body):
                    errors = static_latex_errors(document(body))
                    self.assertTrue(any("unsupported LaTeX literal configuration" in e for e in errors))

    def test_obfuscated_redefinitions_cannot_turn_masked_literals_into_active_tex(self) -> None:
        for body in (
            "\\^^64ef\\^^76erb|#1|{#1}\n\\verb|\\input{external}|",
            "\\^^72enewenvironment{Verbatim}{}{}\n"
            "\\begin{Verbatim}\n\\input{external}\n\\end{Verbatim}",
            "\\^^64ef\\verbatim{}\n"
            "\\begin{verbatim}\n\\input{external}\n\\end{verbatim}",
        ):
            with self.subTest(body=body):
                errors = static_latex_errors(document(body))
                self.assertTrue(any("unsupported LaTeX literal configuration" in e for e in errors))

    def test_caret_sequences_in_true_literals_and_comments_remain_literal(self) -> None:
        for body in (
            "% \\^^64ef\\^^76erb|#1|{#1}\n\\verb|literal|",
            r"\verb|\^^64ef\^^76erb|",
            "\\begin{Verbatim}\n\\^^64ef\\^^76erb|#1|{#1}\n\\end{Verbatim}",
        ):
            with self.subTest(body=body):
                self.assertEqual(static_latex_errors(document(body)), [])

    def test_assignment_and_allocation_targets_cannot_impersonate_literal_commands(self) -> None:
        for command in (
            "chardef", "mathchardef", "Umathchardef", "Umathcharnumdef", "countdef",
            "dimendef", "skipdef", "muskipdef", "toksdef", "font", "newcount", "newdimen",
            "newskip", "newmuskip", "newtoks", "newbox", "newread", "newwrite", "newif",
            "newinsert", "newfam", "newlanguage", "newattribute", "newcatcodetable",
            "newmarks", "newlength", "newsavebox", "newcounter",
        ):
            with self.subTest(command=command):
                body = f"\\{command}\\verb=65 =\n\\verb|\\input{{external}}|"
                errors = static_latex_errors(document(body))
                self.assertIn("forbidden LaTeX operation: input", errors)

    def test_definition_and_copy_families_cannot_hide_direct_operations(self) -> None:
        for command in (
            "newcommand", "providecommand", "NewDocumentCommand", "RenewDocumentCommand",
            "ProvideDocumentCommand", "DeclareDocumentCommand", "NewExpandableDocumentCommand",
            "RenewExpandableDocumentCommand", "ProvideExpandableDocumentCommand",
            "DeclareExpandableDocumentCommand", "NewDocumentEnvironment", "RenewDocumentEnvironment",
            "ProvideDocumentEnvironment", "DeclareDocumentEnvironment", "NewCommandCopy",
            "RenewCommandCopy", "DeclareCommandCopy",
        ):
            with self.subTest(command=command):
                body = f"\\{command}\\verb=body=\n\\verb|\\input{{external}}|"
                errors = static_latex_errors(document(body))
                self.assertIn("forbidden LaTeX operation: input", errors)

    def test_token_consumers_cannot_turn_literal_markers_into_inert_arguments(self) -> None:
        for command in (
            "string", "meaning", "noexpand", "show", "showthe", "showtokens", "the",
            "expandafter", "expanded", "unexpanded", "detokenize", "afterassignment",
            "aftergroup", "uppercase", "lowercase", "romannumeral", "number", "UseName",
        ):
            for literal in (
                r"\verb|\input{external}|",
                "\\begin{Verbatim}\n\\input{external}\n\\end{Verbatim}",
            ):
                with self.subTest(command=command, literal=literal):
                    body = f"\\{command}\n{literal}"
                    errors = static_latex_errors(document(body))
                    self.assertIn("forbidden LaTeX operation: input", errors)

    def test_unknown_package_reconfiguration_cannot_hide_direct_operations(self) -> None:
        for configuration in (
            r"\cslet{verb}\relax",
            r"\csdef{Verbatim}{}",
            r"\arbitraryPackageCommand{verbatim}",
        ):
            for literal in (
                r"\verb|\input{external}|",
                "\\begin{Verbatim}\n\\input{external}\n\\end{Verbatim}",
            ):
                with self.subTest(configuration=configuration, literal=literal):
                    body = f"\\usepackage{{etoolbox}}\n{configuration}\n{literal}"
                    self.assertIn("forbidden LaTeX operation: input", static_latex_errors(document(body)))

    def test_comments_and_control_symbols_cannot_create_fake_literals(self) -> None:
        for body, category in (
            ("\\\\begin{Verbatim}\n\\input{active}\n\\end{Verbatim}", "input"),
            ("% \\begin{Verbatim}\n\\bibliography{active}\n% \\end{Verbatim}", "bibliography_file"),
            ("\\% \\input{active}", "input"),
            ("\\\\\\% \\input{active}", "input"),
        ):
            with self.subTest(body=body):
                self.assertIn(
                    f"forbidden LaTeX operation: {category}", static_latex_errors(document(body))
                )
        for body in ("\\\\% \\input{comment}", "\\\\\\\\% \\input{comment}"):
            with self.subTest(body=body):
                self.assertEqual(static_latex_errors(document(body)), [])

    def test_tex_control_words_end_at_digits_and_non_ascii(self) -> None:
        for operation, category in (
            (r"\openout1=file", "file_write"),
            (r"\openin1=file", "file_read"),
            (r"\write16{message}", "file_write"),
            (r"\input0.tex", "input"),
            (r"\inputı.tex", "input"),
        ):
            with self.subTest(operation=operation):
                self.assertIn(
                    f"forbidden LaTeX operation: {category}", static_latex_errors(document(operation))
                )
        self.assertEqual(
            static_latex_errors(document(r"\inputexample \openoutput \readable \verbx")), []
        )

    def test_checking_view_preserves_line_breaks_and_active_text(self) -> None:
        source = "% comment\r\n\\verb|数学 { %|\n\\input{active}\r"
        views = scan_source(source)
        view = views.structure
        self.assertEqual(len(view), len(source))
        self.assertEqual(
            [(i, c) for i, c in enumerate(view) if c in "\r\n"],
            [(i, c) for i, c in enumerate(source) if c in "\r\n"],
        )
        self.assertEqual(view[source.index(r"\input"):], "\\input{active}\r")
        self.assertNotIn("数学", view)
        self.assertNotIn("% comment", views.operations)
        self.assertIn(r"\verb|数学 { %|", views.operations)

    def test_literals_cannot_supply_document_structure(self) -> None:
        errors = static_latex_errors(
            "\\begin{Verbatim}\n\\documentclass{article}\n"
            "\\begin{document}\n\\end{document}\n\\end{Verbatim}"
        )
        self.assertIn("missing documentclass", errors)
        self.assertIn("proof.tex must contain exactly one \\begin{document}", errors)
        self.assertIn("proof.tex must contain exactly one \\end{document}", errors)
        self.assertIn("unbalanced LaTeX braces", static_latex_errors(document("{")))

    def test_literal_restrictions_do_not_expand_to_nonliteral_documents(self) -> None:
        self.assertEqual(
            static_latex_errors(document(r"\fvset{formatcom=\relax} ordinary text")), []
        )
        self.assertIn(
            "forbidden LaTeX operation: input",
            static_latex_errors(document(r"\fvset{formatcom=\input{active}} ordinary text")),
        )
        self.assertIn(
            "forbidden LaTeX operation: input",
            static_latex_errors(document("\\begin{lstlisting}\n\\input{active}\n\\end{lstlisting}")),
        )

    def test_source_and_option_byte_bounds(self) -> None:
        self.assertEqual(
            static_latex_errors("x" * (2 * 1024 * 1024 + 1)),
            ["proof.tex exceeds the 2 MiB source limit"],
        )
        self.assertEqual(
            static_latex_errors("数" * (2 * 1024 * 1024 // 3 + 1)),
            ["proof.tex exceeds the 2 MiB source limit"],
        )
        body = "\\begin{Verbatim}[" + " " * 4097 + "]\nx\n\\end{Verbatim}"
        self.assertIn("4096 bytes", " ".join(static_latex_errors(document(body))))

    def test_mtm_fixture_is_conservatively_rejected_for_literal_file_commands(self) -> None:
        self.assertEqual(static_latex_errors(VERBATIM_APPENDIX), [
            "forbidden LaTeX operation: input",
            "forbidden LaTeX operation: bibliography_file",
        ])

    def test_original_source_reaches_isolated_compiler_unchanged(self) -> None:
        source = VERBATIM_APPENDIX.replace(r"\bibliography{references}", "References example.")
        source = source.replace(r"\input{literal}", r"\begin{document}")
        source = source.replace("Inline example:", "中文 inline example:").replace("\n", "\r\n")
        with tempfile.TemporaryDirectory() as temp:
            with patch("re_ctm.latex.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
                with patch("re_ctm.latex.BubblewrapExecBackend") as backend_class:
                    backend = backend_class.return_value

                    def execute(*, workspace: Path, **kwargs: object) -> dict[str, object]:
                        self.assertEqual((workspace / "proof.tex").read_bytes(), source.encode("utf-8"))
                        self.assertIn("-no-shell-escape", kwargs["argv"])
                        self.assertEqual(kwargs["mode"], NativeMode.SAFE)
                        backend.attest.assert_called_once()
                        (workspace / "proof.pdf").write_bytes(b"mock PDF")
                        return {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": ""}

                    backend.execute.side_effect = execute
                    result = LatexGate(LatexPolicy.REQUIRED).validate(source, Path(temp))
                    backend.execute.assert_called_once()
        self.assertTrue(result.static_valid)
        self.assertTrue(result.compile_attempted)
        self.assertTrue(result.gate_passed)

    def test_static_rejection_never_invokes_compiler(self) -> None:
        source = document(r"\openout1=file")
        with tempfile.TemporaryDirectory() as temp:
            with patch("re_ctm.latex.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
                with patch("re_ctm.latex.BubblewrapExecBackend") as backend_class:
                    result = LatexGate(LatexPolicy.REQUIRED).validate(source, Path(temp))
                    backend_class.assert_not_called()
        self.assertFalse(result.static_valid)
        self.assertFalse(result.compile_attempted)
        self.assertFalse(result.gate_passed)


if __name__ == "__main__":
    unittest.main()
