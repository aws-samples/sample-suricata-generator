"""Two-axis finding model for the Suricata rule-group analyzer.

Every rule-group Finding carries two independent axes:

  * a **Category** — what kind of problem it is (Rule Shadowing, Protocol
    Layering, Sticky Buffer Ordering, ...). The Category identifiers are the
    existing Conflicts_Dict keys, kept as the grouping axis (design "Option B").
  * a **Severity** — how much it matters: Critical, Warning, or Informational.

This module is deliberately UI-free (no tkinter import, no global state) so it
can be unit-tested headlessly and imported by both the analyzer and the
consumers. It holds the Severity enum, the Category constant namespace, the
authoritative ALLOWED_SEVERITIES inventory (Requirement 2), and the
``tag_finding`` helper that attaches ``category`` + ``sev`` to a Finding dict
in place.

Python 3.7 floor: ``from __future__ import annotations`` defers annotation
evaluation; only 3.7-safe ``enum`` features are used (a plain ``enum.Enum`` with
``str`` member values).
"""

from __future__ import annotations

import enum


class Severity(enum.Enum):
    """The single severity axis every Finding carries (Requirements 1, 3).

    The ``str`` member values match the Policy_Finding severity strings used by
    ``_fold_policy_findings_into_counts`` (``critical`` / ``warning`` /
    ``informational``), so the status bar can use one uniform scale across
    rule-group Findings and Policy_Findings.
    """

    CRITICAL = "critical"
    WARNING = "warning"
    INFORMATIONAL = "informational"


class Category:
    """Category identifiers, equal to the Conflicts_Dict keys (design Data
    Models). Named constants avoid stringly-typed drift at the tagging sites.

    ``RULE_SHADOWING`` is a logical Category presented over the three dict keys
    ``critical`` / ``warning`` / ``info`` (its three Severities); every other
    Category is 1:1 with its Conflicts_Dict key.
    """

    RULE_SHADOWING = "rule_shadowing"
    PROTOCOL_LAYERING = "protocol_layering"
    STICKY_BUFFER_ORDER = "sticky_buffer_order"
    UDP_FLOW_ESTABLISHED = "udp_flow_established"
    PROTOCOL_KEYWORD_MISMATCH = "protocol_keyword_mismatch"
    PORT_PROTOCOL_MISMATCH = "port_protocol_mismatch"
    PORT_ON_PORTLESS_PROTOCOL = "port_on_portless_protocol"
    CONTRADICTORY_FLOW = "contradictory_flow"
    PACKET_DROP_FLOW_PASS = "packet_drop_flow_pass"
    ASYMMETRIC_FLOW = "asymmetric_flow"
    REJECT_IP_PROTOCOL = "reject_ip_protocol"
    REJECT_QUIC_PROTOCOL = "reject_quic_protocol"
    UNSUPPORTED_KEYWORDS = "unsupported_keywords"
    PCRE_RESTRICTIONS = "pcre_restrictions"
    THRESHOLD_LIMITED = "threshold_limited"
    PRIORITY_STRICT_ORDER = "priority_strict_order"


# The authoritative Category_Inventory (Requirement 2): for each Category, the
# set of Severities it can emit. Used by the model to document the contract and
# by the tests to assert Behavior_Preservation of the allowed severities.
ALLOWED_SEVERITIES = {
    Category.RULE_SHADOWING: {
        Severity.CRITICAL, Severity.WARNING, Severity.INFORMATIONAL,
    },
    Category.PROTOCOL_LAYERING: {Severity.WARNING, Severity.INFORMATIONAL},
    Category.STICKY_BUFFER_ORDER: {Severity.WARNING},
    Category.UDP_FLOW_ESTABLISHED: {Severity.WARNING},
    Category.PROTOCOL_KEYWORD_MISMATCH: {Severity.WARNING, Severity.INFORMATIONAL},
    Category.PORT_PROTOCOL_MISMATCH: {Severity.INFORMATIONAL},
    Category.PORT_ON_PORTLESS_PROTOCOL: {Severity.INFORMATIONAL},
    Category.CONTRADICTORY_FLOW: {Severity.WARNING},
    Category.PACKET_DROP_FLOW_PASS: {Severity.WARNING},
    Category.ASYMMETRIC_FLOW: {Severity.CRITICAL, Severity.WARNING},
    Category.REJECT_IP_PROTOCOL: {Severity.CRITICAL},
    Category.REJECT_QUIC_PROTOCOL: {Severity.CRITICAL},
    Category.UNSUPPORTED_KEYWORDS: {Severity.CRITICAL},
    Category.PCRE_RESTRICTIONS: {Severity.CRITICAL},
    Category.THRESHOLD_LIMITED: {Severity.WARNING},
    Category.PRIORITY_STRICT_ORDER: {Severity.WARNING},
}


def tag_finding(finding, category, sev):
    """Attach ``category`` + ``sev`` to a Finding dict in place and return it.

    Adds two keys:
      * ``category`` — the Category constant (equal to the Conflicts_Dict key)
      * ``sev`` — the ``Severity`` enum member (the authoritative Severity)

    The legacy string ``severity`` key is left untouched: for Rule_Shadowing it
    carries ``critical`` / ``warning`` / ``info`` (also the dict-keying), and for
    every other Category it keeps whatever literal it holds today (e.g.
    ``protocol_layering``) solely to satisfy the existing schema-contract tests.
    The legacy ``severity`` key is never read as a Severity once ``sev`` is set.

    Defensive: a non-dict ``finding`` is returned unchanged; ``tag_finding`` is
    idempotent (re-tagging overwrites ``category`` / ``sev`` with the new
    values and never raises).
    """
    if not hasattr(finding, "__setitem__"):
        return finding
    finding["category"] = category
    finding["sev"] = sev
    return finding
