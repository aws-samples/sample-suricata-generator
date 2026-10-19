"""UI-free finding filter for the Static Analysis report ignore feature.

This module is the pure, tkinter-free logic layer behind the report's
session-only "ignore" (acknowledge) control. Given the analyzer's findings
dict and an in-memory ignore set, it decides which findings are visible and
which are hidden, and computes per-entry hidden counts.

The ignore set is a mixed ``Set[IgnoreEntry]`` where an ``IgnoreEntry`` is
either a :class:`RuleIdentity` (ignore one group-qualified rule) or a
:class:`CategoryIdentity` (ignore an entire analyzer category). A finding is
hidden when its category is an ignored ``CategoryIdentity`` OR one of the rule
identities it references is an ignored ``RuleIdentity`` (Req 2.7, 20.3).

Design principles (see .kiro/specs/report-ignore-findings/design.md):

* It NEVER imports tkinter and is fully unit-/property-testable headless
  (Req 10.1).
* It NEVER mutates its inputs (Req 9.5, 10.5): hiding is a pure recomputation
  over the existing findings dict and the ignore set.
* A finding is hidden if and only if its category is an ignored
  ``CategoryIdentity`` or at least one of the rule identities it references is
  an ignored ``RuleIdentity`` (Req 2.7, 20.3).
* It is defensive: a malformed or partial finding never raises; an
  unresolvable line field is simply skipped (Req 2.3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Union

# A finding is the analyzer's conflict dict; the findings dataset is the
# category-keyed dict {category: [finding, ...]}.
Finding = Dict[str, object]
FindingsDict = Dict[str, List[Finding]]


@dataclass(frozen=True)
class RuleIdentity:
    """Group-qualified identity of a rule: (group_name, in_group_line).

    ``group_name`` is the REAL group name from Attribution (not the Display
    form), so matching and hiding are unaffected by the ``.suricata`` display
    transform (Req 3, 13.14). Frozen + hashable so it is usable as an
    Ignore_Set member and a dict key. Two rules with equal line numbers in
    different groups are unequal identities (Req 3.6).
    """

    group_name: str
    in_group_line: int


@dataclass(frozen=True)
class CategoryIdentity:
    """Marker for an ignored analyzer CATEGORY (Req 20).

    ``category`` is the analyzer category KEY (e.g. ``"protocol_layering"``),
    NOT the human label. Frozen + hashable so it is usable as an Ignore_Set
    member and a dict key alongside :class:`RuleIdentity`. A category-ignore is
    its own marker: it hides only findings in that category and adds no
    RuleIdentity to the ignore set (Req 20.2, 20.3).
    """

    category: str


# A single member of the ignore set: a rule marker or a category marker. Uses
# typing.Union (NOT the PEP 604 ``X | Y`` form) so annotations stay valid on
# the Python 3.7 floor (Req 20 / project 3.7 convention).
IgnoreEntry = Union[RuleIdentity, CategoryIdentity]


# The first-side line field per finding shape, used to resolve First_Rule.
FIRST_SIDE_FIELDS = ("upper_line", "line1", "line")
# All line fields a finding may carry.
ALL_LINE_FIELDS = ("upper_line", "lower_line", "line", "line1", "line2")

# Stable field order used ONLY for count-dedup attribution (design
# "Count-dedup logic"). This deliberately differs from FIRST_SIDE_FIELDS /
# ALL_LINE_FIELDS: for attributing a hidden finding to exactly one ignored
# identity we prefer the first-side fields, then the second-side fields.
_DEDUP_FIELD_ORDER = ("upper_line", "line1", "line", "lower_line", "line2")


def _coerce_line(value: object) -> Optional[int]:
    """Return ``value`` as an int line number, or ``None`` if not coercible.

    Booleans are rejected (``True``/``False`` are ints in Python but are never
    valid line numbers). Any value that does not convert cleanly to an int is
    treated as unresolvable rather than raising (defensive, Req 2.3).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _identity_for_field(
    finding: Finding, field: str, single_group_name: Optional[str]
) -> Optional[RuleIdentity]:
    """Resolve one line field of a finding to a :class:`RuleIdentity`.

    Resolution order:

    1. Via ``finding['_attribution']['refs'][field]['attribution']`` when that
       structure is present and carries a usable ``group_name`` /
       ``in_group_line`` (multi-group path).
    2. Otherwise, in single-group mode, from
       ``(single_group_name, int(finding[field]))``.

    A missing/non-dict ``_attribution``, a missing ``refs`` entry, or a
    ``None``/non-integer value is treated as unresolvable and the field is
    skipped (returns ``None``). Never raises.
    """
    # 1. Attribution-based resolution (multi-group).
    attribution = finding.get("_attribution") if hasattr(finding, "get") else None
    if isinstance(attribution, dict):
        refs = attribution.get("refs")
        if isinstance(refs, dict):
            ref = refs.get(field)
            if isinstance(ref, dict):
                attr = ref.get("attribution")
                if attr is not None:
                    group_name = getattr(attr, "group_name", None)
                    in_group_line = _coerce_line(
                        getattr(attr, "in_group_line", None))
                    if group_name is not None and in_group_line is not None:
                        return RuleIdentity(group_name, in_group_line)
                # An attribution ref that is present but unresolvable (e.g.
                # attribution is None) falls through to the single-group
                # fallback below so a single-group finding that happens to
                # carry a partial _attribution is still resolvable.

    # 2. Single-group fallback.
    if single_group_name is not None and hasattr(finding, "get"):
        if field in finding:
            line = _coerce_line(finding.get(field))
            if line is not None:
                return RuleIdentity(single_group_name, line)

    return None


def referenced_identities(
    finding: Finding, single_group_name: Optional[str] = None
) -> Set[RuleIdentity]:
    """Return every RuleIdentity the finding references.

    For each present, resolvable Line_Field, produce its identity. A field is
    resolved via ``finding['_attribution']['refs'][field]['attribution']`` when
    present (multi-group); otherwise, in single-group mode, from
    ``(single_group_name, int(finding[field]))``. Absent or unresolvable fields
    are skipped (Req 2.2, 2.3, 3.1, 3.2).
    """
    identities = set()  # type: Set[RuleIdentity]
    if not hasattr(finding, "get"):
        return identities
    for field in ALL_LINE_FIELDS:
        identity = _identity_for_field(finding, field, single_group_name)
        if identity is not None:
            identities.add(identity)
    return identities


def first_rule_identity(
    finding: Finding, single_group_name: Optional[str] = None
) -> Optional[RuleIdentity]:
    """Return the First_Rule identity (upper_line / line1 / line, first present),
    or None when no first-side field resolves (Req 1.3, 3.1, 3.2)."""
    if not hasattr(finding, "get"):
        return None
    for field in FIRST_SIDE_FIELDS:
        identity = _identity_for_field(finding, field, single_group_name)
        if identity is not None:
            return identity
    return None


def is_hidden(
    finding: Finding, ignore_set: Set[IgnoreEntry],
    single_group_name: Optional[str] = None
) -> bool:
    """True iff at least one referenced rule identity is in ignore_set
    (hidden-iff-referenced, Req 2.1, 2.4, 2.7). Empty ignore_set => False.

    This checks ONLY the rule-match condition; category matching is applied in
    :func:`compute_visible`, which has the per-finding category key in hand. A
    :class:`CategoryIdentity` in the ignore set never equals a
    :class:`RuleIdentity`, so it is simply inert here."""
    if not ignore_set:
        return False
    for identity in referenced_identities(finding, single_group_name):
        if identity in ignore_set:
            return True
    return False


def category_ignored(category: str, ignore_set: Set[IgnoreEntry]) -> bool:
    """True iff ``CategoryIdentity(category)`` is in the ignore set (Req 20.3)."""
    return CategoryIdentity(category) in ignore_set


def _category_token(finding: Finding, bucket_key: str) -> str:
    """Return the authoritative category token for a finding's ignore decision.

    Prefers the per-finding ``category`` field (set by ``tag_finding``, e.g.
    ``'rule_shadowing'`` for every Rule_Shadowing finding regardless of which
    ``critical``/``warning``/``info`` dict bucket stores it), falling back to
    the dict storage ``bucket_key`` when the finding carries no token. For the
    14 one-to-one categories the per-finding token equals the bucket key, so
    this is backward-compatible; for the synthetic findings in the existing
    tests (no token) the bucket key is used, preserving today's behavior.
    """
    if hasattr(finding, "get"):
        token = finding.get("category")
        if token:
            return token
    return bucket_key


def _dedup_identity(
    finding: Finding, ignore_set: Set[IgnoreEntry],
    single_group_name: Optional[str]
) -> Optional[RuleIdentity]:
    """Pick the single ignored identity a hidden finding is attributed to.

    Walks the finding's line fields in the fixed dedup order
    (``upper_line, line1, line, lower_line, line2``) and returns the first
    whose resolved identity is in ``ignore_set``. Returns ``None`` when the
    finding references no ignored RuleIdentity (it may still be hidden by an
    ignored category — that attribution is handled by the caller).

    A :class:`CategoryIdentity` in ``ignore_set`` never equals a resolved
    :class:`RuleIdentity`, so category members are inert here and need no
    special handling.
    """
    for field in _DEDUP_FIELD_ORDER:
        identity = _identity_for_field(finding, field, single_group_name)
        if identity is not None and identity in ignore_set:
            return identity
    return None


def compute_visible(
    findings: FindingsDict, ignore_set: Set[IgnoreEntry],
    single_group_name: Optional[str] = None
) -> Tuple[FindingsDict, Dict[IgnoreEntry, int]]:
    """Return (visible_findings, hidden_counts).

    visible_findings preserves category keys and within-category order, holding
    only non-hidden findings. A finding is hidden when its category key is an
    ignored :class:`CategoryIdentity` OR one of its referenced rules is an
    ignored :class:`RuleIdentity` (Req 20.3).

    hidden_counts maps each ignored entry (either kind) to the number of hidden
    findings attributed to it, where each hidden finding is attributed to
    EXACTLY ONE entry (Req 4.1, 10.2, 20.4). Count-dedup / rule-wins tiebreak:
    a hidden finding is attributed to its ignored RuleIdentity when one resolves
    (via the stable dedup field order); ONLY when no rule matches but the
    category is ignored is it attributed to the CategoryIdentity. So a finding
    hidden by both an ignored rule AND its ignored category counts against the
    rule, never both (Req 20.4). Every ignored entry (both kinds) is pre-seeded
    at 0, so an entry that hides nothing reports 0 (Req 10.3, 20.4). Pure and
    side-effect-free: inputs are never mutated (Req 9.5, 10.5)."""
    visible = {}  # type: FindingsDict
    # Pre-seed every ignored entry (rules AND categories) at 0 so an entry that
    # hides nothing reports 0 (Req 10.3, 20.4).
    hidden_counts = {entry: 0 for entry in ignore_set}  # type: Dict[IgnoreEntry, int]

    if not hasattr(findings, "items"):
        return visible, hidden_counts

    for category, finding_list in findings.items():
        kept = []  # type: List[Finding]
        if finding_list:
            for finding in finding_list:
                # The category-ignore decision keys on the finding's OWN
                # category token (``finding['category']``) when present, falling
                # back to the dict storage key. This lets a single
                # ``CategoryIdentity('rule_shadowing')`` hide the Rule_Shadowing
                # findings stored under the three ``critical``/``warning``/
                # ``info`` buckets, while the 14 categories whose per-finding
                # token equals their bucket key (and the synthetic findings that
                # carry no token) behave exactly as before.
                cat_token = _category_token(finding, category)
                cat_ignored = CategoryIdentity(cat_token) in ignore_set
                rule_hidden = is_hidden(finding, ignore_set, single_group_name)
                if rule_hidden or cat_ignored:
                    # Attribute to exactly one entry. Rule-wins: prefer the
                    # ignored RuleIdentity from the stable dedup order; only
                    # fall back to the CategoryIdentity when no rule matched
                    # (Req 20.4). The category attribution credits the token's
                    # identity so all three shadowing buckets accumulate on the
                    # one ``CategoryIdentity('rule_shadowing')`` count.
                    identity = _dedup_identity(
                        finding, ignore_set, single_group_name)
                    if identity is not None:
                        hidden_counts[identity] = hidden_counts.get(identity, 0) + 1
                    elif cat_ignored:
                        entry = CategoryIdentity(cat_token)
                        hidden_counts[entry] = hidden_counts.get(entry, 0) + 1
                else:
                    kept.append(finding)
        visible[category] = kept
    return visible, hidden_counts


@dataclass(frozen=True)
class JumpTarget:
    """A single referenced rule a finding can jump to (jump-to-finding-rule).

    ``group_name`` is the REAL group name (not the display form).
    ``in_group_line`` is the 1-based in-group line. ``sid`` is the Expected_Sid
    for SID_Verification, or ``None`` when no companion rule object carried one.
    ``file_path`` is the on-disk path the group resolves to, or ``None`` when the
    group is not on disk (AWS, unmapped, or an unsaved single-group file) — the
    view shows an Edit item iff ``file_path`` is not ``None`` (Req 1.2, 1.5).
    """

    group_name: str
    in_group_line: int
    sid: Optional[object]
    file_path: Optional[str]


# Field order for enumerating referenced rules (Req 1.1). Pairs each line field
# with its companion rule-object field so the Expected_Sid can be read.
_JUMP_FIELD_PAIRS = (
    ("upper_line", "upper_rule"),
    ("lower_line", "lower_rule"),
    ("line", "rule"),
    ("line1", "rule1"),
    ("line2", "rule2"),
)


def resolve_group_files(
    single_group_name: Optional[str],
    single_group_path: Optional[str],
    policy_set: object = None,
) -> Dict[str, Optional[str]]:
    """Build the Group_Name -> File_Path map (Req 3).

    Single-group mode (``policy_set is None``): returns ``{single_group_name:
    single_group_path}`` — the path is the app's ``current_file``, or ``None``
    when the file is unsaved. Multi-group mode: for each group in
    ``policy_set.ordered_groups()``, maps ``group.name -> group.origin_path``
    when ``group.kind`` is ``'current'``/``'local'``, else ``None`` (every
    ``'aws'`` group -> ``None``, so the firewall path shows no Edit items).

    This is a PURE PATH LOOKUP: it does not call ``os.path.exists`` and does not
    inspect ``group.load_error``, so a ``current``/``local`` group whose file
    failed to load (``load_error`` set) still maps to its non-``None``
    ``origin_path`` — the missing/unparseable case is handled at jump time (Req
    8.1/8.2), not here. An unsaved current group (``name == '(unsaved)'``,
    ``origin_path is None``) maps to ``None``.

    Never touches the filesystem; never raises; never mutates its inputs.

    Note on the single-group unsaved case: the map KEY may be a non-``None``
    sentinel while the VALUE is ``None``. ``show_analysis_report`` labels an
    unsaved single-group review's group name as the literal ``'current file'``
    (non-``None``) but passes ``single_group_path = self.current_file``
    (``None``). The show/hide decision keys on the VALUE (``file_path``) being
    ``None``, never on the key.
    """
    result = {}  # type: Dict[str, Optional[str]]
    if policy_set is None:
        # Single-group mode: one entry keyed by the single group name.
        if single_group_name is not None:
            result[single_group_name] = single_group_path
        return result

    # Multi-group mode: pure path lookup over the policy set's groups.
    ordered = getattr(policy_set, "ordered_groups", None)
    if not callable(ordered):
        return result
    try:
        groups = ordered()
    except Exception:
        return result
    if not groups:
        return result
    for group in groups:
        name = getattr(group, "name", None)
        if name is None:
            continue
        kind = getattr(group, "kind", None)
        if kind in ("current", "local"):
            result[name] = getattr(group, "origin_path", None)
        else:
            result[name] = None
    return result


def jump_targets(
    finding: Finding,
    single_group_name: Optional[str],
    group_files: Dict[str, Optional[str]],
) -> List[JumpTarget]:
    """Enumerate the finding's referenced rules as JumpTargets (Req 1).

    Walks ``_JUMP_FIELD_PAIRS`` in order; for each present line field resolves
    ``(group_name, in_group_line)`` via the existing ``_identity_for_field``
    attribution logic (skipping fields that do not resolve) and reads the
    Expected_Sid from the companion rule object, preferring its
    ``_original_rule.sid``. De-duplicates identical ``(group_name,
    in_group_line)`` targets (Req 1.7), first field wins. Attaches
    ``file_path = group_files.get(group_name)``. A minimally-populated finding
    with no companion rule object yields ``sid = None`` — an expected, tested
    fallback path. Pure; does not mutate the finding (Req 9.4, 12.3).
    """
    targets = []  # type: List[JumpTarget]
    if not hasattr(finding, "get"):
        return targets
    files = group_files if group_files is not None else {}
    seen = set()  # type: Set[Tuple[str, int]]
    for line_field, rule_field in _JUMP_FIELD_PAIRS:
        identity = _identity_for_field(finding, line_field, single_group_name)
        if identity is None:
            continue
        key = (identity.group_name, identity.in_group_line)
        if key in seen:
            continue
        seen.add(key)
        rule_obj = finding.get(rule_field)
        sid = getattr(getattr(rule_obj, "_original_rule", rule_obj), "sid", None)
        file_path = files.get(identity.group_name)
        targets.append(
            JumpTarget(identity.group_name, identity.in_group_line,
                       sid, file_path))
    return targets


def display_group_name(group_name: str) -> str:
    """Strip a single trailing '.suricata' extension for display surfaces only;
    a name without it is returned unchanged (Req 13.12, 13.13). Display-only;
    does not affect RuleIdentity matching (Req 13.14)."""
    suffix = ".suricata"
    if group_name.endswith(suffix):
        return group_name[: -len(suffix)]
    return group_name
