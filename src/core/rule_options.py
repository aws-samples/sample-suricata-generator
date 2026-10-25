"""
Quote-aware helpers for Suricata rule option text.

A rule's options (the text between the parentheses) are ``;``-separated
statements, but a ``;`` inside a double-quoted value (``msg:"a\\; b"``,
``content:"a\\;b"``, ``pcre:"/a\\;b/"``) is part of that value and must not
split it. This module holds one quote scanner (the S-scan) and the helpers
built on it, so the parser and the validator split option text the same way.

S-scan semantics: outside quotes, ``"`` opens a quoted value and ``;`` is a
statement separator; a backslash outside quotes has no special meaning.
Inside quotes, ``\\`` consumes the next character (so ``\\"`` and ``\\;``
never close the value or split), and ``"`` closes the value. If the scan ends
inside quotes the text is "unterminated" and every helper falls back to
today's ``str.split(';')`` behavior.

Stdlib only; no ``src.*`` imports, so any module can import this one without
creating an import cycle. Python 3.7+ compatible.
"""

import re
from typing import List, Tuple


# Option-statement prefixes that SuricataRule.from_string leaves out of
# SuricataRule.content (msg, sid and rev).
NON_CONTENT_PREFIXES = ('msg:', 'sid:', 'rev:')

# Pre-fix msg extraction, kept so the same msg:" occurrence is chosen.
_LEGACY_MSG_RE = re.compile(r'msg:"([^"]*)"')

# Escape-aware msg value: a backslash consumes the next character, so an
# escaped quote does not end the value.
_MSG_VALUE_RE = re.compile(r'msg:"((?:[^"\\]|\\.)*)"', re.DOTALL)


def _scan(text):
    # type: (str) -> Tuple[List[int], List[Tuple[int, int]], bool]
    """S-scan ``text``.

    Returns ``(separators, regions, terminated)``: the indices of ``;``
    statement separators outside quotes, the ``(open, close)`` indices of
    every completed quoted value, and whether the scan ended outside quotes.
    """
    separators = []  # type: List[int]
    regions = []  # type: List[Tuple[int, int]]
    in_quotes = False
    open_index = -1
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if in_quotes:
            if ch == '\\':
                i += 2  # escape: skip the next character
                continue
            if ch == '"':
                in_quotes = False
                regions.append((open_index, i))
        else:
            if ch == '"':
                in_quotes = True
                open_index = i
            elif ch == ';':
                separators.append(i)
        i += 1
    return separators, regions, not in_quotes


def option_spans(text):
    # type: (str) -> List[Tuple[int, int]]
    """Return raw ``(start, end)`` statement spans covering ``text``.

    Spans are contiguous and separated by exactly one ``;``. When ``text`` is
    terminated they split at the S-scan separators; otherwise at every ``;``
    (fallback). There is always at least one span, and the shape matches
    ``str.split(';')`` (including empty leading, middle and trailing
    statements).
    """
    text = text or ''
    separators, _regions, terminated = _scan(text)
    if not terminated:
        separators = [i for i, ch in enumerate(text) if ch == ';']
    spans = []  # type: List[Tuple[int, int]]
    start = 0
    for sep in separators:
        spans.append((start, sep))
        start = sep + 1
    spans.append((start, len(text)))
    return spans


def split_options_lossless(text):
    # type: (str) -> List[str]
    """Split ``text`` into raw (unstripped) statements, quote-aware.

    ``';'.join(split_options_lossless(text)) == text`` always holds, and the
    result equals ``text.split(';')`` exactly when
    ``not has_quoted_semicolon(text)``.
    """
    text = text or ''
    return [text[s:e] for (s, e) in option_spans(text)]


def has_quoted_semicolon(text):
    # type: (str) -> bool
    """True if ``text`` is terminated and a ``;`` lies inside a quoted value."""
    text = text or ''
    _separators, regions, terminated = _scan(text)
    if not terminated:
        return False
    for (open_index, close_index) in regions:
        if text.find(';', open_index + 1, close_index) != -1:
            return True
    return False


def quoted_regions(text):
    # type: (str) -> List[Tuple[int, int]]
    """Return the ``(open, close)`` quote indices, or ``[]`` if unterminated."""
    _separators, regions, terminated = _scan(text or '')
    if not terminated:
        return []
    return regions


def in_quoted_region(regions, index):
    # type: (List[Tuple[int, int]], int) -> bool
    """True if ``index`` lies strictly between an open and close quote."""
    for (open_index, close_index) in regions:
        if open_index < index < close_index:
            return True
    return False


def content_from_options(options):
    # type: (str) -> str
    """SuricataRule.from_string's derivation of ``content`` from options.

    Every statement is stripped; empty statements and msg/sid/rev statements
    are dropped; the rest are joined with ``'; '``. Identical to the pre-fix
    derivation except that the split is quote-aware (split_options_lossless).
    """
    if not options:
        return ''
    content_parts = []
    for part in split_options_lossless(options):
        part = part.strip()
        if part and not part.startswith(NON_CONTENT_PREFIXES):
            content_parts.append(part)
    return '; '.join(content_parts)


def extract_msg(options):
    # type: (str) -> str
    """Return the msg value from rule options, honoring ``\\"`` escapes.

    The legacy match picks the ``msg:"`` occurrence; the escape-aware match
    is anchored at the same position. If ``options`` is unterminated per the
    S-scan, or the escape-aware match fails (no real closing quote), the
    legacy value is returned, which is the pre-fix behavior (matching the
    ``str.split(';')`` fallback for unterminated text). Returns ``''`` when
    there is no msg.
    """
    if not options:
        return ''
    legacy = _LEGACY_MSG_RE.search(options)
    if legacy is None:
        return ''
    if not _scan(options)[2]:
        return legacy.group(1)
    aware = _MSG_VALUE_RE.match(options, legacy.start())
    if aware is not None:
        return aware.group(1)
    return legacy.group(1)


def split_option_statements(options):
    # type: (str) -> List[str]
    """Split rule options into statements without losing quoted text.

    Statements are ``;``-separated outside double quotes; a backslash escapes
    the next character (so ``\\"`` and ``\\;`` never toggle quoting or end a
    statement). Each statement is stripped; empty statements are dropped.
    These are the Rule Analyzer's semantics: unlike the S-scan used by the
    parser and validator, a backslash also escapes outside quotes, so the
    parser and validator do not use this helper.
    """
    statements = []
    current = []
    in_quotes = False
    escaped = False

    def _flush():
        statement = ''.join(current).strip()
        if statement:
            statements.append(statement)

    for ch in options or '':
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == '\\':
            current.append(ch)
            escaped = True
        elif ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == ';' and not in_quotes:
            _flush()
            current = []
        else:
            current.append(ch)
    _flush()
    return statements


def mask_quoted_values(text):
    # type: (str) -> str
    """Return ``text`` with the inside of every double-quoted value removed.

    The quote characters themselves are kept (``msg:"a b"`` -> ``msg:""``) and
    everything outside quotes is returned unchanged, so a substring test on
    the result behaves exactly like the same test on ``text`` except that it
    can no longer match text inside msg, content, pcre or any other quoted
    value. Uses the same quote/backslash rules as split_option_statements.
    """
    out = []
    in_quotes = False
    escaped = False
    for ch in text or '':
        if escaped:
            escaped = False
            if not in_quotes:
                out.append(ch)
        elif ch == '\\':
            escaped = True
            if not in_quotes:
                out.append(ch)
        elif ch == '"':
            in_quotes = not in_quotes
            out.append(ch)
        elif not in_quotes:
            out.append(ch)
    return ''.join(out)
