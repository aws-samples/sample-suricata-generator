"""
Ingested Policy Facts for the Review Firewall Policy feature.

This module is the UI-free fact model for the "Review Firewall Policy" feature.
It carries everything the AWS ingestion layer reads from a live AWS Network
Firewall firewall policy -- the stateful default actions, the rule-order mode,
the stream-exception policy, the policy-level ``$HOME_NET``, the stateless
reference presence, and the ordered table of stateful rule group references --
independent of the analysis pipeline.

It holds no tkinter state and makes no AWS calls; it is pure data plus a handful
of derived helpers, so it tests headless. The AWS ingestion layer
(``src/aws/firewall_policy_api.py``) populates it; the policy-level checker
(``src/analysis/policy_best_practice.py``) and the overview renderer consume it.

See .kiro/specs/analyze-firewall-policy/design.md,
"New: src/analysis/policy_facts.py".
"""

from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------------
# Stateful default-action string constants
# ---------------------------------------------------------------------------
# The strict-order stateful default actions AWS Network Firewall supports.
# Each "drop" action has a matching "alert" action (see DROP_TO_ALERT); these
# strings are surfaced as context in the Policy_Overview and drive the
# Requirement-11 (ClientHello fragmentation) and Requirement-14 (drop-without-
# alert) checks.
AWS_DROP_STRICT = "aws:drop_strict"
AWS_DROP_ESTABLISHED = "aws:drop_established"
AWS_DROP_APP_LAYER = "aws:drop_established_app_layer"
AWS_DROP_APP_LAYER_TO_SERVER = "aws:drop_established_app_layer_to_server"
AWS_ALERT_STRICT = "aws:alert_strict"
AWS_ALERT_ESTABLISHED = "aws:alert_established"
AWS_ALERT_APP_LAYER = "aws:alert_established_app_layer"
AWS_ALERT_APP_LAYER_TO_SERVER = "aws:alert_established_app_layer_to_server"

# drop -> matching alert partner, for the Default_Action_Alert_Pairing check
# (Requirement 14). Selecting a drop without its matching alert causes blocked
# traffic to be silently discarded with no log entry.
DROP_TO_ALERT = {
    AWS_DROP_STRICT: AWS_ALERT_STRICT,
    AWS_DROP_ESTABLISHED: AWS_ALERT_ESTABLISHED,
    AWS_DROP_APP_LAYER: AWS_ALERT_APP_LAYER,
    AWS_DROP_APP_LAYER_TO_SERVER: AWS_ALERT_APP_LAYER_TO_SERVER,
}

# Human-readable display names for the stateful default actions, matching the
# labels the AWS Network Firewall console shows in its "Stateful default
# actions" dialog. The report surfaces these friendly names instead of the raw
# aws:* API tokens so it reads the way the console presents them. The raw token
# is kept alongside each label (via ``format_default_action``) so a reader can
# still correlate a finding with the API value.
DEFAULT_ACTION_LABELS = {
    AWS_DROP_STRICT: "Drop all",
    AWS_DROP_ESTABLISHED: "Drop established",
    AWS_DROP_APP_LAYER: "Application drop established (bidirectional)",
    AWS_DROP_APP_LAYER_TO_SERVER: "Application drop established (server-directed only)",
    AWS_ALERT_STRICT: "Alert all",
    AWS_ALERT_ESTABLISHED: "Alert established",
    AWS_ALERT_APP_LAYER: "Application alert established (bidirectional)",
    AWS_ALERT_APP_LAYER_TO_SERVER: "Application alert established (server-directed only)",
    "none": "None",
}


def format_default_action(action):
    """Return a human-readable label for a stateful default action token.

    Maps a raw ``aws:drop_*`` / ``aws:alert_*`` / ``none`` token to the friendly
    name the AWS console uses, with the raw token appended in parentheses so the
    API value stays visible, e.g.
    ``"Application drop established (server-directed only) (aws:drop_established_app_layer_to_server)"``.
    An unrecognized token is returned unchanged, so a future AWS value never
    disappears from the report.
    """
    label = DEFAULT_ACTION_LABELS.get(action)
    if label is None:
        return action
    return "{0} ({1})".format(label, action)

# Drop actions that are NOT ClientHello-fragmentation-safe (Requirement 11).
# aws:drop_strict and aws:drop_established can drop a fragmented TLS ClientHello
# before reassembly populates tls.sni, so SNI/domain rules silently fail to
# match. The app-layer drops (aws:drop_established_app_layer / _to_server) are
# fragmentation-safe and therefore excluded from this set.
FRAGMENTATION_UNSAFE_DROPS = frozenset({AWS_DROP_STRICT, AWS_DROP_ESTABLISHED})


# ---------------------------------------------------------------------------
# Rule-order mode constants
# ---------------------------------------------------------------------------
# StatefulEngineOptions.RuleOrder. Only STRICT_ORDER policies are analyzed; the
# analyzer's forward-only shadowing model cannot faithfully represent
# DEFAULT_ACTION_ORDER (the service default when unset).
RULE_ORDER_STRICT = "STRICT_ORDER"
RULE_ORDER_DEFAULT_ACTION = "DEFAULT_ACTION_ORDER"


# ---------------------------------------------------------------------------
# Rule_Group_Format classification constants
# ---------------------------------------------------------------------------
# The form a customer-owned stateful rule group expresses its rules in, as
# returned by DescribeRuleGroup. Only FORMAT_SURICATA parses into the
# SuricataRule shape the analyzer requires; the others block analysis via the
# Suricata-Format Gate (Requirement 13).
FORMAT_SURICATA = "suricata"        # RulesSource.RulesString
FORMAT_DOMAIN_LIST = "domain_list"  # RulesSource.RulesSourceList
FORMAT_STANDARD = "standard"        # RulesSource.StatefulRules
FORMAT_UNKNOWN = "unknown"          # unclassified / managed groups left unknown


@dataclass
class StatefulGroupRef:
    """One StatefulRuleGroupReference, enriched by classification/fetch.

    ``priority`` is the Reference_Priority (meaningful only under strict order).
    ``is_customer_owned`` is set by cross-referencing the ARN against
    ListRuleGroups(Scope=ACCOUNT). ``rule_format`` and ``analyzable_rule_count``
    are populated only for customer-owned Suricata groups; managed/shared groups
    are left at FORMAT_UNKNOWN / 0 because their rules are never analyzed.
    ``fetch_error`` records a per-group DescribeRuleGroup failure message.
    """

    arn: str
    name: str
    priority: Optional[int]
    is_customer_owned: bool
    rule_format: str = FORMAT_UNKNOWN
    analyzable_rule_count: int = 0
    fetch_error: Optional[str] = None


@dataclass
class PolicyFacts:
    """Everything read from a firewall policy, independent of analysis.

    ``stateful_refs`` is held in ascending Reference_Priority order (the policy's
    real strict-order evaluation order). ``policy_home_net`` is the policy-level
    ``$HOME_NET`` (PolicyVariables) or None when the policy does not define one.
    The derived helpers below are pure partitions/predicates over these fields.
    """

    policy_name: str
    policy_arn: str
    region: str
    rule_order: str
    stateful_default_actions: List[str]
    stream_exception_policy: str
    policy_home_net: Optional[List[str]]
    has_stateless_refs: bool
    stateless_ref_count: int
    stateful_refs: List[StatefulGroupRef]

    # ---- derived helpers (pure) ----

    def customer_refs(self) -> List[StatefulGroupRef]:
        """Return the customer-owned stateful references (analyzable groups).

        Preserves the ascending-priority order of ``stateful_refs``.
        """
        return [ref for ref in self.stateful_refs if ref.is_customer_owned]

    def managed_refs(self) -> List[StatefulGroupRef]:
        """Return the managed/shared-in stateful references (not analyzed).

        These are surfaced in the Policy_Overview for situational awareness only
        (Requirement 4.4). Preserves ascending-priority order.
        """
        return [ref for ref in self.stateful_refs if not ref.is_customer_owned]

    def unsupported_format_refs(self) -> List[StatefulGroupRef]:
        """Return customer-owned groups whose format is not Suricata-string.

        These are the Unsupported_Format_Groups that block analysis via the
        Suricata-Format Gate (Requirement 13). Managed/shared groups are never
        included (their format is left FORMAT_UNKNOWN but they are not analyzed).
        A customer group whose format has not yet been resolved (FORMAT_UNKNOWN,
        e.g. a fetch error before classification) is reported as unsupported so
        it cannot silently pass the gate.
        """
        return [
            ref
            for ref in self.stateful_refs
            if ref.is_customer_owned and ref.rule_format != FORMAT_SURICATA
        ]

    def is_strict_order(self) -> bool:
        """Return True when the policy uses STRICT_ORDER rule evaluation.

        Only strict-order policies are analyzable (Requirement 3). The ingestion
        layer resolves an unset rule order to DEFAULT_ACTION_ORDER (the service
        default), so an unset policy correctly reports False here.
        """
        return self.rule_order == RULE_ORDER_STRICT

    def has_customer_groups(self) -> bool:
        """Return True when the policy references >=1 customer-owned group."""
        return any(ref.is_customer_owned for ref in self.stateful_refs)

    def has_stateful_refs(self) -> bool:
        """Return True when the policy references >=1 stateful rule group."""
        return bool(self.stateful_refs)
