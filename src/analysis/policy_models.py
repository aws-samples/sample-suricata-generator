"""
Policy Set Data Models for Multi-Rule-Group Analysis

This module defines the UI-free data models used by the multi-rule-group
review feature. A Policy_Set assembles one or more Rule_Groups (the editor's
Current_Group plus optional local .suricata files) in evaluation order
(Group_Order), stitches them into a single Combined_Rule_Stream for the
unchanged RuleAnalyzer, and attributes every finding back to its source group.

These models hold no tkinter state and never mutate editor state; they are the
testable core of the feature (see design.md, "New: src/analysis/policy_models.py").
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.core.suricata_rule import SuricataRule


# ---------------------------------------------------------------------------
# Group kind constants
# ---------------------------------------------------------------------------
# A Rule_Group is either the group open in the editor ("current") or a rule
# group loaded from a local .suricata file ("local"). These string tokens are
# stored on RuleGroupSource.kind and RuleAttribution.group_kind.
GROUP_KIND_CURRENT = "current"
GROUP_KIND_LOCAL = "local"


def _is_analyzable(rule: SuricataRule) -> bool:
    """Return True if a rule participates in conflict analysis.

    Mirrors RuleAnalyzer.analyze_rule_conflicts' ``actual_rules`` filter
    exactly: a rule is analyzable when it is neither a comment row nor a blank
    row. Uses getattr with a False default so plain rule objects (which may not
    set these attributes) are still treated as analyzable, matching the
    analyzer's defensive access.
    """
    return (
        not getattr(rule, "is_comment", False)
        and not getattr(rule, "is_blank", False)
    )


@dataclass
class RuleGroupSource:
    """One Rule_Group in a Policy_Set.

    Represents either the Current_Group (kind == GROUP_KIND_CURRENT) or a
    Local_Group loaded from disk (kind == GROUP_KIND_LOCAL). ``rules`` is kept
    in the group's in-group order and includes comment/blank placeholder rows
    (retained for in-group line numbering). ``variables`` is the normalized
    dict shape produced by FileManager.load_variables_file, i.e.
    ``{name: {"definition", "description"[, "type"]}}``.
    """

    kind: str
    name: str
    rules: List[SuricataRule]
    variables: Dict[str, dict]
    origin_path: Optional[str] = None
    load_error: Optional[str] = None

    def analyzable_rule_count(self) -> int:
        """Count of non-comment, non-blank rules.

        Matches RuleAnalyzer's ``actual_rules`` filter so counts shown in the
        Policy_Set_Config and report headers agree with what the analyzer
        actually processes (see Analyzable_Rules in requirements.md).
        """
        return sum(1 for rule in self.rules if _is_analyzable(rule))


@dataclass
class RuleAttribution:
    """Maps a rule in the Combined_Rule_Stream back to its source group.

    ``in_group_line`` is 1-based and counts comment/blank rows, using the same
    counting basis as the single-group analyzer (position within the group's
    rules), consistent with Requirements 4.5 / 7.6.
    """

    group_name: str
    group_kind: str
    in_group_line: int


@dataclass
class CombinedStream:
    """The stitched Combined_Rule_Stream plus its attribution.

    ``rules`` is the concatenation of each group's rules in Group_Order.
    ``attribution`` is parallel to ``rules`` (same index). ``by_rule_id`` maps
    ``id(rule)`` to its attribution as an identity fallback for finding fields
    that carry rule object references rather than line numbers.
    """

    rules: List[SuricataRule]
    attribution: List[RuleAttribution]
    by_rule_id: Dict[int, RuleAttribution]

    def attribution_for_line(self, one_based_line: int) -> Optional[RuleAttribution]:
        """Return the attribution for a 1-based combined-stream line.

        Returns None when the line is out of range. The analyzer computes
        finding line numbers as 1-based positions into the analyzed list, so
        ``one_based_line`` indexes directly into ``attribution``.
        """
        index = one_based_line - 1
        if 0 <= index < len(self.attribution):
            return self.attribution[index]
        return None


@dataclass
class PolicySet:
    """The ordered collection of Rule_Groups assembled for one review.

    The list order IS Group_Order: ``groups[0]`` is evaluated first (top of the
    ordered list). There are no priority numbers; the user arranges the list via
    Move Up / Move Down (Req 2.3). The Current_Group may sit anywhere but cannot
    be removed (Req 2.5).
    """

    groups: List[RuleGroupSource] = field(default_factory=list)

    def ordered_groups(self) -> List[RuleGroupSource]:
        """Return groups in Group_Order (the current list order, as-is)."""
        return list(self.groups)

    def move_up(self, index: int) -> None:
        """Move the group at ``index`` one position earlier in Group_Order.

        No-op when ``index`` is at the top (0) or out of range.
        """
        if 0 < index < len(self.groups):
            self.groups[index - 1], self.groups[index] = (
                self.groups[index],
                self.groups[index - 1],
            )

    def move_down(self, index: int) -> None:
        """Move the group at ``index`` one position later in Group_Order.

        No-op when ``index`` is at the bottom or out of range.
        """
        if 0 <= index < len(self.groups) - 1:
            self.groups[index + 1], self.groups[index] = (
                self.groups[index],
                self.groups[index + 1],
            )

    def total_group_count(self) -> int:
        """Total number of Rule_Groups in the Policy_Set."""
        return len(self.groups)

    def total_analyzable_rules(self) -> int:
        """Sum of every group's analyzable rule count."""
        return sum(group.analyzable_rule_count() for group in self.groups)

    def current_group(self) -> Optional[RuleGroupSource]:
        """Return the Current_Group, or None if the set has no current group.

        There is normally exactly one Current_Group; the first one found is
        returned.
        """
        for group in self.groups:
            if group.kind == GROUP_KIND_CURRENT:
                return group
        return None

    def home_net_value(self) -> Optional[str]:
        """Return the policy-wide $HOME_NET (the Current_Group's definition).

        $HOME_NET is the one policy-wide variable (Policy_Level_HomeNet, Req
        5.6): its value is taken from the Current_Group. Returns None when there
        is no current group or the current group does not define $HOME_NET with
        a non-empty definition.
        """
        current = self.current_group()
        if current is None:
            return None
        entry = current.variables.get("$HOME_NET")
        if isinstance(entry, dict):
            definition = entry.get("definition", "")
            if definition:
                return definition
        return None

    def home_net_differs(self) -> bool:
        """Return True if any group's $HOME_NET differs from the policy value.

        Compares each group that defines a non-empty $HOME_NET against the
        Current_Group's chosen value (Req 5.6). Groups without a $HOME_NET
        definition do not count as differing. Returns False when no policy-wide
        $HOME_NET value is available.
        """
        chosen = self.home_net_value()
        if chosen is None:
            return False
        for group in self.groups:
            entry = group.variables.get("$HOME_NET")
            if isinstance(entry, dict):
                definition = entry.get("definition", "")
                if definition and definition != chosen:
                    return True
        return False


@dataclass
class PolicyReviewResult:
    """Result of a multi-group review.

    ``findings`` is the RuleAnalyzer output (unchanged Findings_Dict shape).
    ``combined`` and ``policy_set`` carry the analyzed stream and its source
    groups for attribution and header rendering. ``home_net_chosen`` /
    ``home_net_differed`` surface the policy-wide $HOME_NET decision (Req 5.6,
    8.3). ``cancelled`` is True when the user cancelled the run.
    """

    findings: Dict[str, List[dict]]
    combined: CombinedStream
    policy_set: PolicySet
    home_net_chosen: Optional[str]
    home_net_differed: bool
    cancelled: bool = False
