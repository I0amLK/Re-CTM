"""Bounded lexical checking views, not a TeX interpreter or an isolation backend.

Only the structure view masks supported literal forms, preserving line breaks.
The operation view retains literal text so unknown macro/package behavior cannot
hide a directly written file/shell operation behind a presumed literal marker.
Find literal terminators before processing comments: percent is literal there.
Executable options and tokenization reconfiguration with literals fail closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_ENVIRONMENTS = frozenset({"verbatim", "verbatim*", "Verbatim", "Verbatim*"})
# Known configuration changes remain unsupported. This list is not relied on
# to certify arbitrary expansion: operation checks never mask literal bodies.
_RECONFIGURATION_COMMANDS = frozenset({
    "catcode", "endlinechar", "escapechar", "scantokens", "ExplSyntaxOn",
    "makeatletter", "setkeys", "AddToHook", "AddToHookNext", "AtBeginEnvironment",
    "BeforeBeginEnvironment", "csname", "def", "gdef", "edef", "xdef", "let",
    "futurelet", "renewcommand", "renewenvironment", "newenvironment",
    "provideenvironment", "DeclareRobustCommand", "DefineVerbatimEnvironment",
    "CustomVerbatimEnvironment", "RecustomVerbatimEnvironment", "CustomVerbatimCommand",
    "RecustomVerbatimCommand", "VerbatimEnvironment", "MakeShortVerb", "DefineShortVerb",
})
_OPTION_VALUES = {
    "frame": frozenset({"none", "single", "lines", "leftline", "topline", "bottomline"}),
    "numbers": frozenset({"none", "left", "right"}),
    "fontsize": frozenset({
        r"\tiny", r"\scriptsize", r"\footnotesize", r"\small", r"\normalsize",
        r"\large", r"\Large", r"\LARGE", r"\huge", r"\Huge",
    }),
}
_BOOLEAN_OPTIONS = frozenset({"showspaces", "showtabs", "resetmargins", "samepage"})
_DIMENSION_OPTIONS = frozenset({"numbersep", "framesep", "framerule", "xleftmargin", "xrightmargin"})
_LITERAL_DIMENSION = re.compile(r"-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:pt|em|ex|mm|cm|in)")


class LatexScanError(ValueError):
    """An unsupported or unterminated literal context must fail the static gate."""


@dataclass(frozen=True)
class LatexSourceViews:
    structure: str
    operations: str


def scan_source(source: str) -> LatexSourceViews:
    """Return checking-only views; neither replaces the original compiler input."""

    view = list(source)
    operations = list(source)
    cursor = 0
    depth = 0
    literal_seen = False
    reconfigured = False
    while cursor < len(source):
        start = cursor
        character = source[cursor]
        if character == "%":
            cursor = _line_end(source, cursor)
            _mask(view, start, cursor)
            _mask(operations, start, cursor)
        elif character == "{":
            depth += 1
            cursor += 1
        elif character == "}":
            depth = max(depth - 1, 0)
            cursor += 1
        elif source.startswith("^^", cursor):
            reconfigured = True
            cursor += 2
        elif character == "\\":
            cursor += 1
            while cursor < len(source) and _ascii_letter(source[cursor]):
                cursor += 1
            if cursor == start + 1:
                # A control symbol consumes the next character. In particular,
                # the second slash of \\\\ cannot start an active \\begin/input.
                if cursor < len(source):
                    # TeX's ^^ conversion precedes control-symbol tokenization:
                    # \\^^64ef can become \\def and redefine a masked literal.
                    if source.startswith("^^", cursor):
                        reconfigured = True
                    if source[cursor] == "\\":
                        _mask(view, start, cursor + 1)
                    cursor += 1
                continue
            command = source[start + 1:cursor]
            if command.startswith("if") or command in _RECONFIGURATION_COMMANDS:
                reconfigured = True
            if command == "fvset":
                options = _group(source, cursor)
                if options is None:
                    reconfigured = True
                else:
                    value, cursor = options
                    try:
                        _validate_options(value)
                    except LatexScanError:
                        reconfigured = True
            elif command == "verb":
                if depth:
                    raise _unsupported("verb inside a braced argument")
                literal_seen = True
                cursor = _inline_end(source, cursor)
                _mask(view, start, cursor)
            elif command == "begin":
                group = _group(source, cursor)
                if group is None or group[0] not in _ENVIRONMENTS:
                    continue
                environment, end = group
                if depth or not _line_prefix_is_whitespace(source, start):
                    raise _unsupported(
                        "literal environment must start on its own line outside a braced argument"
                    )
                literal_seen = True
                body_start = _environment_body(source, end, environment)
                terminator = f"\\end{{{environment}}}"
                offset = source.find(terminator, body_start)
                if offset == -1:
                    raise LatexScanError(f"unterminated LaTeX literal environment: {environment}")
                # The FIRST raw terminator ends the literal, even after '%' or
                # '\\'. Requiring a whole-line end could hide active trailing TeX.
                cursor = offset + len(terminator)
                _mask(view, start, cursor)
        else:
            cursor += 1
    if literal_seen and reconfigured:
        raise _unsupported("macro, environment or catcode reconfiguration with literal text")
    return LatexSourceViews(structure="".join(view), operations="".join(operations))


def _ascii_letter(character: str) -> bool:
    return "a" <= character <= "z" or "A" <= character <= "Z"


def _line_end(source: str, cursor: int) -> int:
    while cursor < len(source) and source[cursor] not in "\r\n":
        cursor += 1
    return cursor


def _mask(view: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if view[index] not in "\r\n":
            view[index] = " "


def _group(source: str, cursor: int) -> tuple[str, int] | None:
    while cursor < len(source) and source[cursor].isspace():
        cursor += 1
    if cursor >= len(source) or source[cursor] != "{":
        return None
    end = source.find("}", cursor + 1)
    if end == -1 or "{" in source[cursor + 1:end]:
        return None
    return source[cursor + 1:end], end + 1


def _line_prefix_is_whitespace(source: str, cursor: int) -> bool:
    start = max(source.rfind("\n", 0, cursor), source.rfind("\r", 0, cursor)) + 1
    return all(character in " \t" for character in source[start:cursor])


def _environment_body(source: str, cursor: int, name: str) -> int:
    while cursor < len(source) and source[cursor] in " \t":
        cursor += 1
    if name.startswith("V") and source[cursor:cursor + 1] == "[":
        end = source.find("]", cursor + 1)
        if end == -1:
            raise _unsupported("unterminated Verbatim options")
        _validate_options(source[cursor + 1:end])
        cursor = end + 1
        while cursor < len(source) and source[cursor] in " \t":
            cursor += 1
    if cursor >= len(source) or source[cursor] not in "\r\n":
        raise _unsupported("literal environment header must end with a newline")
    return cursor + 1


def _inline_end(source: str, cursor: int) -> int:
    if source[cursor:cursor + 1] == "*":
        cursor += 1
    if cursor >= len(source):
        raise _unsupported("missing verb delimiter")
    delimiter = source[cursor]
    if not "!" <= delimiter <= "~" or _ascii_letter(delimiter):
        raise _unsupported("verb requires a non-letter ASCII delimiter")
    end = source.find(delimiter, cursor + 1, _line_end(source, cursor))
    if end == -1:
        raise _unsupported("unterminated verb before line end")
    return end + 1


def _validate_options(options: str) -> None:
    if len(options.encode("utf-8")) > 4096:
        raise _unsupported("Verbatim options exceed 4096 bytes")
    for option in options.split(","):
        if not option.strip():
            continue
        key, separator, value = option.partition("=")
        key = key.strip()
        value = value.strip() if separator else "true"
        if key in _OPTION_VALUES:
            valid = value in _OPTION_VALUES[key]
        elif key in _BOOLEAN_OPTIONS:
            valid = value in {"true", "false"}
        elif key == "tabsize":
            valid = re.fullmatch(r"\+?0*(?:[1-9]|[1-5][0-9]|6[0-4])", value) is not None
        elif key == "gobble":
            valid = re.fullmatch(r"\+?0*[0-9]", value) is not None
        elif key in _DIMENSION_OPTIONS:
            valid = _LITERAL_DIMENSION.fullmatch(value) is not None
        else:
            valid = False
        if not valid:
            raise _unsupported(
                "only documented literal formatting options are supported; "
                "executable or unknown options are refused"
            )


def _unsupported(reason: str) -> LatexScanError:
    return LatexScanError(f"unsupported LaTeX literal configuration: {reason}")
