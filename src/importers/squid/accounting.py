"""
Total-accounting invariant.

The converter's one guarantee is that it never silently changes a policy. That
guarantee only holds if nothing silently *disappears* either, so every directive
line read from the input must land in exactly one bucket:

    acl definition
    access line  -> emitted | not convertible | note only
    reported directive (ssl_bump, icp_access, ...)
    structural   (if/else/endif/include/quoted-values switch)
    ignored      (general setting, not access control)
    malformed    (recognised directive, unparseable)
    skipped      (inside an inactive `if` branch)

`build()` cross-checks the parser's ledger against the emitter's per-line
outcomes and reports any line that is unaccounted for or double-counted.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .emitter import EMITTED, NOT_CONVERTIBLE, NOTE_ONLY, EmitResult
from .parser import (ACCESS, ACL, DISPOSITIONS, IGNORED, MALFORMED, REPORTED,
                    SKIPPED, STRUCTURAL, ParsedConfig, where)

OUTCOMES = (EMITTED, NOT_CONVERTIBLE, NOTE_ONLY)

# Human-readable labels, in report order.
_LABELS = [
    (ACL, "acl definition"),
    (EMITTED, "access line -> emitted rule(s)"),
    (NOT_CONVERTIBLE, "access line -> not convertible"),
    (NOTE_ONLY, "access line -> note only, no rule"),
    (REPORTED, "reported directive (not converted)"),
    (STRUCTURAL, "structural (if/include/...)"),
    (IGNORED, "ignored general setting"),
    (MALFORMED, "malformed, skipped"),
    (SKIPPED, "skipped (inactive `if` branch)"),
]


@dataclass
class Accounting:
    total_directive_lines: int = 0
    counts: Dict[str, int] = field(default_factory=dict)
    # Lines the ledger recorded as access lines but the emitter never reported.
    unaccounted: List[str] = field(default_factory=list)
    # Outcomes the emitter reported for lines absent from the ledger.
    orphaned: List[str] = field(default_factory=list)
    # Ledger keys seen more than once.
    duplicated: List[str] = field(default_factory=list)
    rule_count: int = 0

    def bucket_total(self) -> int:
        return sum(self.counts.values())

    def is_complete(self) -> bool:
        return (not self.unaccounted and not self.orphaned
                and not self.duplicated
                and self.bucket_total() == self.total_directive_lines)

    def summary_lines(self) -> List[str]:
        out = ["Accounting: %d directive line(s) read, %d rule(s) emitted."
               % (self.total_directive_lines, self.rule_count)]
        for key, label in _LABELS:
            n = self.counts.get(key, 0)
            if n:
                out.append("  %-42s %d" % (label, n))
        if self.is_complete():
            out.append("  all lines accounted for.")
        return out

    def explain(self) -> str:
        out = list(self.summary_lines())
        if self.bucket_total() != self.total_directive_lines:
            out.append("  MISMATCH: buckets sum to %d, expected %d"
                       % (self.bucket_total(), self.total_directive_lines))
        for label, items in (("UNACCOUNTED", self.unaccounted),
                             ("ORPHANED", self.orphaned),
                             ("DUPLICATED", self.duplicated)):
            for item in items:
                out.append("  %s: %s" % (label, item))
        return "\n".join(out)


def _fmt(key: Tuple[int, Optional[str], str]) -> str:
    line_no, source, directive = key
    return "%s (`%s`)" % (where(line_no, source), directive)


def build(cfg: ParsedConfig, result: EmitResult) -> Accounting:
    """Cross-check the parser ledger against the emitter's line outcomes."""
    acct = Accounting(total_directive_lines=len(cfg.ledger),
                      rule_count=len(result.rules))

    seen: Dict[Tuple[int, Optional[str], str], int] = {}
    for entry in cfg.ledger:
        seen[entry.key] = seen.get(entry.key, 0) + 1
    for key, n in seen.items():
        if n > 1:
            acct.duplicated.append("%s recorded %d times" % (_fmt(key), n))

    outcomes = dict(result.line_outcomes)
    for entry in cfg.ledger:
        if entry.disposition == ACCESS:
            outcome = outcomes.pop(entry.key, None)
            if outcome is None:
                acct.unaccounted.append(
                    "%s is an access line but the emitter reported no outcome"
                    % _fmt(entry.key))
                # Still count it, so the mismatch is visible as a bucket gap.
                acct.counts[ACCESS] = acct.counts.get(ACCESS, 0) + 1
            else:
                acct.counts[outcome] = acct.counts.get(outcome, 0) + 1
        else:
            if entry.disposition not in DISPOSITIONS:
                acct.unaccounted.append("%s has unknown disposition %r"
                                        % (_fmt(entry.key), entry.disposition))
            acct.counts[entry.disposition] = \
                acct.counts.get(entry.disposition, 0) + 1

    for key, outcome in outcomes.items():
        acct.orphaned.append("%s reported outcome %r but is not in the ledger"
                             % (_fmt(key), outcome))
    return acct
