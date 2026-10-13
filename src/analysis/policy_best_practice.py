"""
Policy-Level Best-Practice Checker for the Review Firewall Policy feature.

This module is the UI-free policy-level best-practice checker. It consumes an
already-ingested ``PolicyFacts`` (``src/analysis/policy_facts.py``) plus an
assembled ``PolicySet`` (``src/analysis/policy_models.py``) and returns an
ordered list of ``PolicyFinding``. It makes NO AWS calls, imports no tkinter,
and does not touch ``RuleAnalyzer`` or ``PolicyReviewService`` -- so it is fully
headless-testable.

Design note: the checks are a registry of pure bound methods (``self._checks``)
each returning ``Optional[PolicyFinding]`` (or a list), so adding a future
policy-level check is a one-line registry addition with no pipeline change
(Req 10.5). ``run()`` re-sorts findings by severity (critical -> warning ->
informational, Req 7.7), so the registry order is not the output order and
adding a check never perturbs existing output ordering.

See .kiro/specs/analyze-firewall-policy/design.md and requirements.md
(Requirements 7, 10, 11, 12, 14, 15, 16).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import FrozenSet, Iterator, List, Optional

from src.analysis.policy_facts import (
    AWS_DROP_APP_LAYER,
    AWS_DROP_APP_LAYER_TO_SERVER,
    DROP_TO_ALERT,
    format_default_action,
    FRAGMENTATION_UNSAFE_DROPS,
    PolicyFacts,
)
from src.analysis.policy_models import PolicySet
from src.core.suricata_rule import SuricataRule


# ---------------------------------------------------------------------------
# Severity constants + ordering
# ---------------------------------------------------------------------------
SEV_CRITICAL = "critical"
SEV_WARNING = "warning"
SEV_INFO = "informational"

# Sort key for run(): critical first, informational last (Req 7.7).
_SEVERITY_ORDER = {SEV_CRITICAL: 0, SEV_WARNING: 1, SEV_INFO: 2}

# Sentinel resolved value for a customer group that defines no own $HOME_NET and
# inherits no policy-level $HOME_NET. A distinct value that compares unequal to
# any concrete frozenset of CIDRs (Req 12.4).
_INHERITS_DEFAULT = "<inherits policy/VPC default>"

# ClientHello reassembly-dependent markers scanned in a rule's option/buffer
# text (case-insensitive). See _check_clienthello_fragmentation.
_CLIENTHELLO_MARKERS = ("tls.sni", "http.host", "ssl_state:client_hello")
_SSL_STATE_CLIENT_HELLO = "ssl_state:client_hello"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------
@dataclass
class PolicyFinding:
    """One policy-level best-practice finding.

    ``check_id`` is a stable identifier (e.g. ``"clienthello_fragmentation"``),
    ``severity`` is one of the ``SEV_*`` constants, ``title`` is a short human
    label, ``description`` explains what/why, and ``recommendation`` explains how
    to fix it.
    """

    check_id: str
    severity: str
    title: str
    description: str
    recommendation: str


# ---------------------------------------------------------------------------
# Module-level pure helpers (unit-reachable)
# ---------------------------------------------------------------------------
def _iter_customer_rules(policy_set: PolicySet) -> Iterator[SuricataRule]:
    """Yield each analyzable rule across the policy set's ordered groups.

    Skips comment and blank placeholder rows (matching
    ``policy_models._is_analyzable``). A policy-sourced ``PolicySet`` contains
    only customer Suricata groups, so no ``kind`` filtering is needed.
    """
    for group in policy_set.ordered_groups():
        for rule in group.rules:
            if getattr(rule, "is_comment", False):
                continue
            if getattr(rule, "is_blank", False):
                continue
            yield rule


def _rule_option_text(rule: SuricataRule) -> str:
    """Return a single lowercased blob of a rule's option/buffer text.

    Combines ``content``, ``original_options`` and the optional ``raw_text``
    attribute defensively (hand-built SuricataRule objects lack ``raw_text``),
    space-joined and lowercased. This is what the ClientHello keyword scan reads.
    """
    parts = [
        getattr(rule, "content", "") or "",
        getattr(rule, "original_options", "") or "",
        getattr(rule, "raw_text", "") or "",
    ]
    return " ".join(parts).lower()


def _normalize_cidr_set(definition: Optional[str]) -> Optional[FrozenSet[str]]:
    """Normalize a comma-joined CIDR string to a canonical frozenset.

    Splits on commas, strips whitespace and surrounding ``[`` ``]`` brackets
    from each token, drops empties, then parses each token with
    ``ipaddress.ip_network(token, strict=False)`` and collects its canonical
    string form. Returns a frozenset of those canonical strings (order-,
    whitespace- and bracket-independent, deduped via the set).

    Returns ``None`` when ``definition`` is falsy OR any token fails to parse: a
    single unparseable token makes the whole value UNPARSEABLE so the caller
    stays silent for it (Req 12.5).
    """
    if not definition:
        return None
    networks = set()
    for raw_token in definition.split(","):
        token = raw_token.strip().strip("[]").strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return None
        networks.add(str(network))
    if not networks:
        return None
    return frozenset(networks)


def _render_cidr_value(value) -> str:
    """Render a resolved HOME_NET value for the finding description."""
    if value == _INHERITS_DEFAULT:
        return "inherits the policy/VPC default"
    return ", ".join(sorted(value))


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------
class PolicyBestPracticeChecker:
    """Runs the policy-level best-practice checks over ingested facts.

    The checks are an instance-level registry of bound methods, each
    ``(PolicyFacts, PolicySet) -> Optional[PolicyFinding]`` (or a list). Adding a
    future check is a one-line addition to ``self._checks`` (Req 10.5).
    """

    def __init__(self) -> None:
        # Registry order is informational only; run() re-sorts by severity.
        self._checks = [
            self._check_clienthello_fragmentation,
            self._check_home_net_consistency,
            self._check_drop_without_alert,
            self._check_stream_exception,
            self._check_stateless_present,
        ]

    def run(self, facts: PolicyFacts, policy_set: PolicySet) -> List[PolicyFinding]:
        """Run every registered check and return findings sorted by severity.

        Collects non-None results (a check may return a single finding or a list)
        then stable-sorts critical -> warning -> informational (Req 7.7).
        """
        findings: List[PolicyFinding] = []
        for check in self._checks:
            result = check(facts, policy_set)
            if result is None:
                continue
            if isinstance(result, list):
                findings.extend(result)
            else:
                findings.append(result)
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        return findings

    # ---- individual checks ----

    def _check_clienthello_fragmentation(
        self, facts: PolicyFacts, policy_set: PolicySet
    ) -> Optional[PolicyFinding]:
        """SEV_CRITICAL: fragmented TLS ClientHellos dropped before SNI (Req 11).

        Fires iff all three hold: (a) a fragmentation-unsafe default drop is
        present; (b) at least one customer rule is ClientHello-reassembly
        dependent (text contains tls.sni / http.host / ssl_state:client_hello);
        (c) no reassembly-permitting mitigation present -- neither a
        fragmentation-safe default action (app_layer / _to_server) nor a customer
        rule with ssl_state:client_hello (which itself forces reassembly). An
        ssl_state:client_hello rule counts as BOTH a dependent rule and a
        mitigation, so a policy whose only dependent rule is ssl_state does not
        fire.
        """
        unsafe_present = bool(
            set(facts.stateful_default_actions) & FRAGMENTATION_UNSAFE_DROPS
        )
        if not unsafe_present:
            return None

        has_dependent = False
        has_ssl_state = False
        for rule in _iter_customer_rules(policy_set):
            text = _rule_option_text(rule)
            if any(marker in text for marker in _CLIENTHELLO_MARKERS):
                has_dependent = True
            if _SSL_STATE_CLIENT_HELLO in text:
                has_ssl_state = True

        if not has_dependent:
            return None

        safe_default_present = (
            AWS_DROP_APP_LAYER in facts.stateful_default_actions
            or AWS_DROP_APP_LAYER_TO_SERVER in facts.stateful_default_actions
        )
        if safe_default_present or has_ssl_state:
            return None

        unsafe_actions = sorted(
            set(facts.stateful_default_actions) & FRAGMENTATION_UNSAFE_DROPS
        )
        unsafe_list = ", ".join(
            format_default_action(a) for a in unsafe_actions
        )
        return PolicyFinding(
            check_id="clienthello_fragmentation",
            severity=SEV_CRITICAL,
            title="Fragmented TLS ClientHellos may be dropped before SNI inspection",
            description=(
                "The policy uses a fragmentation-unsafe stateful default drop "
                f"action ({unsafe_list}) together with domain/SNI-dependent "
                "customer rules (tls.sni / http.host) and no "
                "reassembly-permitting mitigation. A fragmented TLS ClientHello "
                "can be dropped before reassembly populates tls.sni, so the "
                "domain/SNI rules silently fail to match the connection."
            ),
            recommendation=(
                "Switch the stateful default action to "
                f"{format_default_action(AWS_DROP_APP_LAYER)} or "
                f"{format_default_action(AWS_DROP_APP_LAYER_TO_SERVER)}, which "
                "are fragmentation-safe, or disable the default drop and add a "
                "custom reassembly-permitting rule (e.g. an ssl_state:client_hello "
                "rule) so ClientHellos are reassembled before SNI inspection. See "
                "the AWS Network Firewall strict-order rule-evaluation and "
                "ClientHello fragmentation guidance."
            ),
        )

    def _check_home_net_consistency(
        self, facts: PolicyFacts, policy_set: PolicySet
    ) -> Optional[PolicyFinding]:
        """SEV_WARNING: $HOME_NET resolves to different values (Req 12).

        Resolves each customer group's Effective_HomeNet (own definition, else
        the policy-level value, else an inherits-default sentinel), normalizes
        concrete values to canonical CIDR sets (excluding unparseable ones,
        Req 12.5), and fires iff >= 2 distinct resolved values remain. Equal
        normalized sets -- including redundant same-value policy+group
        definitions -- do not fire (Req 12.2).
        """
        policy_defined = bool(facts.policy_home_net)
        if policy_defined:
            policy_norm = _normalize_cidr_set(",".join(facts.policy_home_net))
        else:
            policy_norm = None

        # (label, resolved_value) pairs for every usable location.
        pairs = []
        if policy_defined and policy_norm is not None:
            pairs.append(("policy level", policy_norm))

        for group in policy_set.ordered_groups():
            entry = group.variables.get("$HOME_NET")
            own_def = entry.get("definition") if isinstance(entry, dict) else None
            if own_def:
                norm = _normalize_cidr_set(own_def)
                if norm is None:
                    continue  # UNPARSEABLE: exclude (Req 12.5)
                pairs.append((group.name, norm))
            elif policy_defined:
                if policy_norm is None:
                    continue  # policy value unparseable -> exclude this group too
                pairs.append((group.name, policy_norm))
            else:
                pairs.append((group.name, _INHERITS_DEFAULT))

        # Invert to value -> sorted unique labels.
        value_to_labels = {}
        for label, value in pairs:
            value_to_labels.setdefault(value, set()).add(label)

        if len(value_to_labels) < 2:
            return None

        enumerated = []
        for value, labels in value_to_labels.items():
            location_list = ", ".join(sorted(labels))
            enumerated.append(
                f"{_render_cidr_value(value)} ({location_list})"
            )
        enumerated.sort()
        description = (
            "$HOME_NET resolves to more than one value across the policy. "
            "AWS Network Firewall derives $EXTERNAL_NET from the policy-level "
            "$HOME_NET and does not recompute it per rule group, so divergent "
            "$HOME_NET definitions misalign $EXTERNAL_NET and rules may match "
            "unexpected traffic. Distinct values found: "
            + "; ".join(enumerated)
            + "."
        )
        return PolicyFinding(
            check_id="home_net_consistency",
            severity=SEV_WARNING,
            title="$HOME_NET resolves to different values across the policy",
            description=description,
            recommendation=(
                "Make $HOME_NET consistent: prefer a single policy-level "
                "$HOME_NET value and have rule groups either match it exactly or "
                "omit their own definition so they inherit it. This keeps the "
                "derived $EXTERNAL_NET aligned across every group."
            ),
        )

    def _check_drop_without_alert(
        self, facts: PolicyFacts, policy_set: PolicySet
    ) -> Optional[PolicyFinding]:
        """SEV_WARNING: a default drop action without its alert partner (Req 14).

        For each drop present in ``stateful_default_actions`` whose matching
        ``aws:alert_*`` partner is absent, collect the pair. Fires iff at least
        one such pair exists, emitting one finding that enumerates all missing
        pairs.
        """
        actions = set(facts.stateful_default_actions)
        missing_pairs = []
        for drop, alert in DROP_TO_ALERT.items():
            if drop in actions and alert not in actions:
                missing_pairs.append((drop, alert))

        if not missing_pairs:
            return None

        pair_text = "; ".join(
            "{0} is missing {1}".format(
                format_default_action(drop), format_default_action(alert)
            )
            for drop, alert in missing_pairs
        )
        missing_alerts = ", ".join(
            format_default_action(alert) for _, alert in missing_pairs
        )
        return PolicyFinding(
            check_id="drop_without_alert",
            severity=SEV_WARNING,
            title="Default drop action without its matching alert variant",
            description=(
                "The policy selects a stateful default drop action without its "
                "matching alert variant, so dropped traffic is not logged "
                "(Network Firewall appends noalert to the generated default drop "
                f"rules). Missing pairings: {pair_text}."
            ),
            recommendation=(
                "Add the matching alert variant alongside each drop action so "
                f"dropped traffic is logged: {missing_alerts}."
            ),
        )

    def _check_stream_exception(
        self, facts: PolicyFacts, policy_set: PolicySet
    ) -> Optional[PolicyFinding]:
        """SEV_INFO: stream exception policy is not REJECT (Req 15)."""
        current = facts.stream_exception_policy or ""
        if current == "REJECT":
            return None
        return PolicyFinding(
            check_id="stream_exception",
            severity=SEV_INFO,
            title="Stream exception policy is not set to REJECT",
            description=(
                f"The stream exception policy is currently '{current}'. For most "
                "production environments the best practice is REJECT: Network "
                "Firewall sends a TCP RST so the client reconnects and the new "
                "connection is fully inspected. The right value is "
                "environment-dependent."
            ),
            recommendation=(
                "Consider setting the stream exception policy to REJECT so "
                "exception traffic triggers a reconnect that is fully inspected, "
                "unless your environment specifically requires DROP or CONTINUE."
            ),
        )

    def _check_stateless_present(
        self, facts: PolicyFacts, policy_set: PolicySet
    ) -> Optional[PolicyFinding]:
        """SEV_INFO: the policy attaches stateless rule groups (Req 16)."""
        if not facts.has_stateless_refs:
            return None
        count = facts.stateless_ref_count
        count_text = (
            f" The policy references {count} stateless rule group(s)."
            if count > 0
            else ""
        )
        return PolicyFinding(
            check_id="stateless_present",
            severity=SEV_INFO,
            title="Policy attaches stateless rule groups",
            description=(
                "The policy attaches stateless rule groups." + count_text + " "
                "Best practice for most inspection use cases is to rely on "
                "stateful rule groups, with the stateless default set to forward "
                "traffic to the stateful engine."
            ),
            recommendation=(
                "Set the stateless default action to forward to the stateful "
                "rule groups and perform inspection statefully, rather than "
                "duplicating logic in stateless rules."
            ),
        )
