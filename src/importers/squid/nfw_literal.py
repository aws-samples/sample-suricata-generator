"""
Required-literal extraction for NFW `pcre` compatibility.

AWS Network Firewall rejects a rule using `pcre` unless it also carries one of
[tls.sni, http.host, dns.query, http.uri, content]. For matches on other
buffers (http.header, http.user_agent, http.content_type, ...) the only way to
keep the regex is to add a `content:` prefilter.

That is only safe if the literal is REQUIRED by the regex - i.e. every string
the regex matches contains it. Then `content` is a pure prefilter: the
conjunction `content AND pcre` selects exactly what `pcre` alone selected, so
the policy is unchanged. The prefilter is always emitted with `nocase`, which
can only widen it, and widening a prefilter cannot change the final verdict
because the pcre still decides.

The extractor is deliberately conservative. It only trusts literal runs at the
TOP level of the regex (outside every group), because anything inside a group
may be alternated or optional. When it cannot prove a literal is required it
returns None, and the caller reports the line as not convertible rather than
emitting a rule Network Firewall would refuse.
"""

from typing import List, Optional

# Escaped characters that denote a literal of themselves (\. -> '.').
_ESCAPED_LITERALS = set(".^$*+?()[]{}|/-\\\"'<>=!:,;@#%&~` \t")

# Minimum useful prefilter length. One character is still semantically safe,
# just less selective, so this only affects quality, never correctness.
MIN_LITERAL = 1


def _skip_class(regex: str, i: int) -> int:
    """Return the index just past a [...] character class starting at i."""
    j = i + 1
    if j < len(regex) and regex[j] == "^":
        j += 1
    if j < len(regex) and regex[j] == "]":   # literal ']' first in the class
        j += 1
    while j < len(regex):
        if regex[j] == "\\":
            j += 2
            continue
        if regex[j] == "]":
            return j + 1
        j += 1
    return len(regex)


def literal_runs(regex: str) -> Optional[List[str]]:
    """All literal runs guaranteed at the top level of `regex`.

    Returns None when nothing can be guaranteed - specifically when the regex
    has a top-level alternation, since then no single literal is required.
    """
    runs: List[str] = []
    cur: List[str] = []
    depth = 0
    i, n = 0, len(regex)

    def flush() -> None:
        if cur:
            runs.append("".join(cur))
            cur.clear()

    while i < n:
        c = regex[i]

        if c == "\\" and i + 1 < n:
            nxt = regex[i + 1]
            if nxt == "x":
                # \xHH - a hex-escaped byte (our own escaping for " and ;).
                # Treat as a break rather than guessing the character.
                flush()
                i += 4
                continue
            if nxt in _ESCAPED_LITERALS:
                # A quantifier may follow and make it optional; handled below.
                if depth == 0:
                    cur.append(nxt)
                else:
                    flush()
                i += 2
                continue
            # \d \w \s \b \r \n ... not a literal
            flush()
            i += 2
            continue

        if c == "[":
            flush()
            i = _skip_class(regex, i)
            continue

        if c == "(":
            flush()
            depth += 1
            i += 1
            continue

        if c == ")":
            flush()
            depth = max(0, depth - 1)
            i += 1
            continue

        if c == "|":
            if depth == 0:
                # The whole pattern is an alternation: nothing is required.
                return None
            flush()
            i += 1
            continue

        if c in "^$.":
            flush()
            i += 1
            continue

        if c in "*?":
            # The preceding character is optional, so it is not required.
            if cur:
                cur.pop()
            flush()
            i += 1
            continue

        if c == "+":
            # The preceding character must appear at least once, so the run is
            # still required; just end it here.
            flush()
            i += 1
            continue

        if c == "{":
            # {0,n} makes the previous char optional; be conservative always.
            if cur:
                cur.pop()
            flush()
            j = regex.find("}", i)
            i = (j + 1) if j >= 0 else n
            continue

        if depth == 0:
            cur.append(c)
        else:
            flush()
        i += 1

    flush()
    return runs


def required_literal(regex: str) -> Optional[str]:
    """The longest literal every match of `regex` must contain, or None.

    None means the caller must not emit a pcre rule for a buffer that NFW
    requires a companion option on.
    """
    runs = literal_runs(regex)
    if runs is None:
        return None
    usable = [r for r in runs if len(r) >= MIN_LITERAL]
    if not usable:
        return None
    # Longest wins; ties broken deterministically by first appearance.
    best = max(usable, key=lambda r: (len(r), -runs.index(r)))
    return best
