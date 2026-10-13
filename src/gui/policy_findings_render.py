"""
Policy Overview + policy-level findings renderers for the Review Firewall
Policy feature.

This module is a set of PURE text/HTML formatters. Despite living under
``src/gui/`` it imports NO tkinter and holds no global state: every function
takes an already-ingested ``PolicyFacts`` (``src/analysis/policy_facts.py``) or
a list of ``PolicyFinding`` (``src/analysis/policy_best_practice.py``) and
returns a ``str``. That makes the whole module headless-testable.

The four public entry points are:

- ``format_policy_overview_text(facts)`` / ``format_policy_overview_html(facts)``
  -- the Policy Overview section (policy identity, rule order, stateful default
  actions, stream exception, policy ``$HOME_NET``, a stateless-groups note, and
  the ordered stateful-group table). (Req 7.1-7.3)
- ``format_policy_findings_text(findings)`` /
  ``format_policy_findings_html(findings)`` -- the Policy-Level Best-Practice
  Findings section, ordered critical -> warning -> informational, grouped under
  severity headers, with a dedicated empty-state note. (Req 7.5, 7.7, 7.8)

HTML variants escape every dynamic string with ``html.escape`` (the task
mandates this even though the legacy ``rule_analyzer`` report does not).

See .kiro/specs/analyze-firewall-policy/design.md and requirements.md
(Requirement 7).
"""

from __future__ import annotations

import html
from typing import List, Tuple

from src.analysis.policy_facts import (
    format_default_action,
    PolicyFacts,
    RULE_ORDER_STRICT,
    StatefulGroupRef,
)
from src.analysis.policy_best_practice import (
    PolicyFinding,
    SEV_CRITICAL,
    SEV_INFO,
    SEV_WARNING,
)


# ---------------------------------------------------------------------------
# Section titles + severity label maps
# ---------------------------------------------------------------------------
_OVERVIEW_TITLE = "Policy Overview"
_FINDINGS_TITLE = "Policy-Level Best-Practice Findings"

# Em dash used for "not applicable" cells (matches the \u2014 the existing HTML
# header uses).
_EM_DASH = "\u2014"

# Empty-state note shown when no policy-level findings were flagged (Req 7.8).
_EMPTY_FINDINGS_NOTE = (
    "No policy-level issues found. The policy-level best-practice checks ran "
    "and nothing was flagged."
)

# Severity ordering (critical -> warning -> informational, Req 7.7). Defensive:
# an unknown severity sorts last.
_SEVERITY_ORDER = {SEV_CRITICAL: 0, SEV_WARNING: 1, SEV_INFO: 2}

# Plain-text severity sub-header labels.
_SEV_TEXT = {
    SEV_CRITICAL: "CRITICAL",
    SEV_WARNING: "WARNING",
    SEV_INFO: "INFORMATIONAL",
}

# HTML severity (label, css-suffix, emoji) triples. The css suffix matches the
# existing rule-group report's .critical/.warning/.info convention so the
# policy-level findings inherit the SAME colored styling as the rule-group
# report they sit above (shared <style> block in rule_analyzer's HTML). The
# emoji matches the analyzer's own severity headers (🚨/⚠️/ℹ️).
_SEV_HTML = {
    SEV_CRITICAL: ("CRITICAL", "critical", "\U0001F6A8"),
    SEV_WARNING: ("WARNING", "warning", "\u26A0\uFE0F"),
    SEV_INFO: ("INFORMATIONAL", "info", "\u2139\uFE0F"),
}


# ---------------------------------------------------------------------------
# Module-private pure helpers
# ---------------------------------------------------------------------------
def _rule_order_note(rule_order: str) -> str:
    """Return the rule-order string with an analyzability parenthetical.

    STRICT_ORDER is analyzable; DEFAULT_ACTION_ORDER (or anything else) is not.
    """
    if rule_order == RULE_ORDER_STRICT:
        return rule_order + " (analyzable)"
    return (rule_order or "(unset)") + " (not analyzable)"


def _default_actions_display(facts: PolicyFacts) -> str:
    """Return the stateful default actions as friendly, comma-joined labels.

    Each raw ``aws:*`` token is mapped to the AWS-console display name (with the
    token kept in parentheses) via ``format_default_action``; an empty list
    renders as ``(none)``.
    """
    return (
        ", ".join(format_default_action(a) for a in facts.stateful_default_actions)
        or "(none)"
    )


def _home_net_display(facts: PolicyFacts) -> str:
    """Return the joined policy ``$HOME_NET`` or the inherits-default sentinel."""
    if facts.policy_home_net:
        return ", ".join(facts.policy_home_net)
    return "inherits default"


def _stateless_note(facts: PolicyFacts) -> str:
    """Return the stateless-rule-groups note.

    'none' when the policy attaches no stateless groups, otherwise
    'N attached (not analyzed)'.
    """
    if not facts.has_stateless_refs:
        return "none"
    return "{0} attached (not analyzed)".format(facts.stateless_ref_count)


def _owner_label(ref: StatefulGroupRef) -> str:
    """Return 'Customer' for a customer-owned ref, else 'Managed'."""
    return "Customer" if ref.is_customer_owned else "Managed"


def _priority_cell(ref: StatefulGroupRef) -> str:
    """Return the priority as a string, or the em dash when it is None."""
    if ref.priority is None:
        return _EM_DASH
    return str(ref.priority)


def _name_cell(ref: StatefulGroupRef) -> str:
    """Return the ref name, falling back to the ARN tail when name is empty."""
    if ref.name:
        return ref.name
    if ref.arn:
        return ref.arn.rsplit("/", 1)[-1]
    return _EM_DASH


def _format_cell(ref: StatefulGroupRef) -> str:
    """Return the rule format for customer rows, em dash for managed rows."""
    if ref.is_customer_owned:
        return ref.rule_format
    return _EM_DASH


def _rules_cell(ref: StatefulGroupRef) -> str:
    """Return the analyzable rule count for customer rows, else 'not analyzed'."""
    if ref.is_customer_owned:
        return str(ref.analyzable_rule_count)
    return "not analyzed"


def _sorted_refs(facts: PolicyFacts) -> List[StatefulGroupRef]:
    """Return ``stateful_refs`` defensively sorted ascending by priority.

    ``stateful_refs`` is already held in ascending-priority order; this re-sorts
    defensively (stable), placing refs with ``priority is None`` last.
    """
    return sorted(
        facts.stateful_refs,
        key=lambda ref: (ref.priority is None, ref.priority if ref.priority is not None else 0),
    )


def _sorted_findings(findings: List[PolicyFinding]) -> List[PolicyFinding]:
    """Return findings stable-sorted critical -> warning -> informational."""
    return sorted(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )


def _analyzable_summary(facts: PolicyFacts) -> Tuple[int, int]:
    """Return (customer group count, total analyzable rule count)."""
    customer = facts.customer_refs()
    group_count = len(customer)
    rule_count = sum(ref.analyzable_rule_count for ref in customer)
    return group_count, rule_count


# ---------------------------------------------------------------------------
# Overview -- plain text
# ---------------------------------------------------------------------------
def format_policy_overview_text(facts: PolicyFacts) -> str:
    """Render the Policy Overview as a plain-text section (Req 7.1-7.3).

    Includes policy identity, rule order (with analyzability note), stateful
    default actions, stream exception policy, policy ``$HOME_NET``, a
    stateless-groups note, and the ordered stateful-group table, closing with
    the analyzable summary line.
    """
    lines = [_OVERVIEW_TITLE, "=" * 30, ""]
    lines.append("Policy Name: {0}".format(facts.policy_name))
    lines.append("Policy ARN: {0}".format(facts.policy_arn))
    lines.append("Region: {0}".format(facts.region))
    lines.append("Rule Order: {0}".format(_rule_order_note(facts.rule_order)))
    lines.append(
        "Stateful Default Actions: {0}".format(_default_actions_display(facts))
    )
    lines.append(
        "Stream Exception Policy: {0}".format(facts.stream_exception_policy)
    )
    lines.append("Policy $HOME_NET: {0}".format(_home_net_display(facts)))
    lines.append("Stateless Rule Groups: {0}".format(_stateless_note(facts)))
    lines.append("")

    refs = _sorted_refs(facts)
    if not refs:
        lines.append("(no stateful rule groups referenced)")
    else:
        headers = ["Priority", "Name", "Owner", "Format", "Rules"]
        rows = [
            [
                _priority_cell(ref),
                _name_cell(ref),
                _owner_label(ref),
                _format_cell(ref),
                _rules_cell(ref),
            ]
            for ref in refs
        ]
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))

        def _fmt_row(cells):
            return "  ".join(
                cell.ljust(widths[i]) for i, cell in enumerate(cells)
            ).rstrip()

        lines.append(_fmt_row(headers))
        lines.append("  ".join("-" * w for w in widths))
        for row in rows:
            lines.append(_fmt_row(row))

    lines.append("")
    group_count, rule_count = _analyzable_summary(facts)
    lines.append(
        "Analyzable: {0} customer group(s), {1} rules.".format(
            group_count, rule_count
        )
    )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Overview -- HTML
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Inline-style constants matching rule_analyzer.generate_html_report's palette.
#
# The policy fragments are prepended INTO the analyzer's HTML document, so they
# share its <style> block (.header/.summary/.critical/.warning/.info/.conflict/
# .conflict-*). The analyzer defines NO <table> rules, so the overview table is
# styled inline here with the same colors (header strip #2c3e50 title color,
# #f8f9fa light-grey cell fill, #dee2e6 borders, #e9ecef header-row fill) so it
# reads as part of the same report rather than a bare browser-default table.
# ---------------------------------------------------------------------------
_TABLE_STYLE = (
    "border-collapse:collapse;width:100%;margin:15px 0;font-size:14px;"
)
_TH_STYLE = (
    "text-align:left;padding:8px 12px;background-color:#e9ecef;"
    "border:1px solid #dee2e6;color:#2c3e50;font-weight:bold;"
)
_TD_STYLE = "padding:8px 12px;border:1px solid #dee2e6;"
# Managed (not-analyzed) rows are muted so the eye lands on the analyzed
# customer rows, mirroring how the plain-text table reads.
_TD_STYLE_MANAGED = _TD_STYLE + "color:#6c757d;background-color:#f8f9fa;"


def _meta_html(label: str, value: str) -> str:
    """Return one escaped ``<strong>Label:</strong> value<br>`` meta line.

    Rendered inside the analyzer's ``.summary`` box so the scalar policy facts
    sit in the same light-grey rounded panel the analyzer uses for its own
    "Analysis Summary" block.
    """
    return "<strong>{0}:</strong> {1}<br>".format(
        html.escape(label), html.escape(value)
    )


def format_policy_overview_html(facts: PolicyFacts) -> str:
    """Render the Policy Overview as an HTML fragment (Req 7.1-7.3).

    Same information as :func:`format_policy_overview_text`, but styled to match
    rule_analyzer.generate_html_report: a ``.header`` title box, a ``.summary``
    panel for the scalar facts, and a colored, bordered stateful-group table.
    Every dynamic string is escaped with ``html.escape``. Managed rows are
    marked not-analyzed via muted cell styling and explicit "not analyzed" text.
    """
    # Title in the same grey rounded .header box the analyzer uses, with the
    # same .title typography.
    parts = [
        '<div class="header">',
        '<div class="title">{0}</div>'.format(html.escape(_OVERVIEW_TITLE)),
        "</div>",
    ]

    # Scalar facts inside the analyzer's .summary panel.
    parts.append('<div class="summary">')
    parts.append(_meta_html("Policy Name", facts.policy_name))
    parts.append(_meta_html("Policy ARN", facts.policy_arn))
    parts.append(_meta_html("Region", facts.region))
    parts.append(_meta_html("Rule Order", _rule_order_note(facts.rule_order)))
    parts.append(
        _meta_html("Stateful Default Actions", _default_actions_display(facts))
    )
    parts.append(
        _meta_html("Stream Exception Policy", facts.stream_exception_policy)
    )
    parts.append(_meta_html("Policy $HOME_NET", _home_net_display(facts)))
    parts.append(_meta_html("Stateless Rule Groups", _stateless_note(facts)))
    parts.append("</div>")

    refs = _sorted_refs(facts)
    if not refs:
        parts.append("<p><em>No stateful rule groups referenced.</em></p>")
    else:
        parts.append('<table style="{0}">'.format(_TABLE_STYLE))
        parts.append(
            "<thead><tr>"
            '<th style="{0}">Priority</th>'
            '<th style="{0}">Name</th>'
            '<th style="{0}">Owner</th>'
            '<th style="{0}">Format</th>'
            '<th style="{0}">Rules</th>'
            "</tr></thead>".format(_TH_STYLE)
        )
        parts.append("<tbody>")
        for ref in refs:
            td = _TD_STYLE if ref.is_customer_owned else _TD_STYLE_MANAGED
            parts.append(
                "<tr>"
                '<td style="{1}">{2}</td>'
                '<td style="{1}">{3}</td>'
                '<td style="{1}">{4}</td>'
                '<td style="{1}">{5}</td>'
                '<td style="{1}">{6}</td>'
                "</tr>".format(
                    "",
                    td,
                    html.escape(_priority_cell(ref)),
                    html.escape(_name_cell(ref)),
                    html.escape(_owner_label(ref)),
                    html.escape(_format_cell(ref)),
                    html.escape(_rules_cell(ref)),
                )
            )
        parts.append("</tbody>")
        parts.append("</table>")

    group_count, rule_count = _analyzable_summary(facts)
    parts.append(
        '<div class="summary"><strong>Analyzable:</strong> '
        "{0} customer group(s), {1} rules.</div>".format(group_count, rule_count)
    )
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Findings -- plain text
# ---------------------------------------------------------------------------
def format_policy_findings_text(findings: List[PolicyFinding]) -> str:
    """Render the policy-level findings as a plain-text section.

    Findings are ordered critical -> warning -> informational (sorted
    defensively) and grouped under severity sub-headers. Each finding shows its
    title, description, and recommendation. An empty list produces the
    empty-state note (Req 7.5, 7.7, 7.8).
    """
    lines = [_FINDINGS_TITLE, "=" * 30, ""]
    if not findings:
        lines.append(_EMPTY_FINDINGS_NOTE)
        return "\n".join(lines) + "\n"

    current_severity = None
    index = 0
    for finding in _sorted_findings(findings):
        if finding.severity != current_severity:
            current_severity = finding.severity
            index = 0
            header = _SEV_TEXT.get(finding.severity, finding.severity.upper())
            lines.append(header)
            lines.append("-" * 30)
        index += 1
        lines.append("{0}. {1}".format(index, finding.title))
        lines.append("   Description: {0}".format(finding.description))
        lines.append("   Recommendation: {0}".format(finding.recommendation))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Findings -- HTML
# ---------------------------------------------------------------------------
def format_policy_findings_html(findings: List[PolicyFinding]) -> str:
    """Render the policy-level findings as an HTML fragment.

    Same ordering and empty-state note as
    :func:`format_policy_findings_text`. Every dynamic string is escaped with
    ``html.escape`` (Req 7.5, 7.7, 7.8).
    """
    # Section title in the same grey rounded .header box as the overview, so
    # the two policy regions read as one styled block above the rule-group
    # report.
    parts = [
        '<div class="header">',
        '<div class="title">{0}</div>'.format(html.escape(_FINDINGS_TITLE)),
        "</div>",
    ]
    if not findings:
        # Match the analyzer's green ".success" treatment for its own
        # no-conflicts line.
        parts.append(
            '<div class="success">\u2713 {0}</div>'.format(
                html.escape(_EMPTY_FINDINGS_NOTE)
            )
        )
        return "\n".join(parts) + "\n"

    current_severity = None
    index = 0
    for finding in _sorted_findings(findings):
        label, css, emoji = _SEV_HTML.get(
            finding.severity, (finding.severity, "info", "\u2139\uFE0F")
        )
        if finding.severity != current_severity:
            current_severity = finding.severity
            index = 0
            # Severity header styled exactly like the analyzer's section
            # headers (<h2 class="critical|warning|info"> with the emoji).
            parts.append(
                '<h2 class="{0}">{1} {2}</h2>'.format(
                    html.escape(css), emoji, html.escape(label)
                )
            )
        index += 1
        # Each finding is a .conflict div with the colored left border, same as
        # a rule-group conflict card.
        parts.append(
            '<div class="conflict conflict-{0}">'.format(html.escape(css))
        )
        parts.append(
            "<strong>{0}. {1}</strong><br>".format(
                index, html.escape(finding.title)
            )
        )
        parts.append(
            "<strong>Description:</strong> {0}<br>".format(
                html.escape(finding.description)
            )
        )
        parts.append(
            "<strong>Recommendation:</strong> {0}".format(
                html.escape(finding.recommendation)
            )
        )
        parts.append("</div>")

    return "\n".join(parts) + "\n"
