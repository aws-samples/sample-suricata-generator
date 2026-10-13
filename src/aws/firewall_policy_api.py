"""
UI-free AWS ingestion layer for the "Review Firewall Policy" feature.

This module reads a live AWS Network Firewall firewall policy and its
customer-owned stateful rule groups into the UI-free fact/data models
(``PolicyFacts`` / ``StatefulGroupRef`` in ``src/analysis/policy_facts.py`` and
``RuleGroupSource`` in ``src/analysis/policy_models.py``). It imports NO tkinter
and holds no editor state; every AWS call goes through an injected
``AWSSessionManager`` so it can be tested headless with stubbed boto3 clients.

Responsibilities:
- ``list_firewall_policies`` -- enumerate firewall policies (Name + Arn).
- ``describe_policy_facts`` -- read a policy's facts and the ordered table of
  stateful references, classifying each reference as customer-owned vs managed
  by cross-referencing ListRuleGroups(Scope=ACCOUNT). It does NOT fetch rule
  bodies.
- ``fetch_customer_group`` -- fetch and parse a single customer-owned Suricata
  rule group into a ``RuleGroupSource``.
- ``classify_group_format`` -- classify a rule group's rule format.

See .kiro/specs/analyze-firewall-policy/design.md,
"New: src/aws/firewall_policy_api.py".
"""

from typing import Dict, List

# Optional boto3 import with graceful degradation (mirrors other AWS modules).
HAS_BOTO3 = False
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    boto3 = None

from src.analysis.policy_facts import (
    StatefulGroupRef,
    PolicyFacts,
    RULE_ORDER_DEFAULT_ACTION,
    FORMAT_SURICATA,
    FORMAT_DOMAIN_LIST,
    FORMAT_STANDARD,
    FORMAT_UNKNOWN,
)
from src.analysis.policy_models import RuleGroupSource, GROUP_KIND_AWS
from src.importers.rule_group_parsing import (
    parse_rules_string,
    parse_rule_variables,
)
from src.mrg.aws.network_firewall import list_user_rule_groups


class FirewallPolicyApiError(Exception):
    """Raised when a firewall-policy ingestion AWS call fails."""
    pass


def list_firewall_policies(session_manager, region) -> List[Dict]:
    """List the firewall policies in a region.

    Args:
        session_manager: AWSSessionManager used to create the client.
        region: AWS region to query.

    Returns:
        List of dicts with keys ``Name`` and ``Arn``.

    Raises:
        FirewallPolicyApiError: If the AWS call fails (preserves the real
            message).
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        policies: List[Dict] = []
        paginator = client.get_paginator('list_firewall_policies')
        for page in paginator.paginate():
            for p in page.get('FirewallPolicies', []):
                policies.append({
                    'Name': p.get('Name', ''),
                    'Arn': p.get('Arn', ''),
                })
        return policies
    except Exception as e:
        raise FirewallPolicyApiError(
            "Failed to list firewall policies in {}: {}".format(region, str(e))
        ) from e


def classify_group_format(rule_group_dict) -> str:
    """Classify a rule group's rule format from its ``RulesSource`` block.

    Args:
        rule_group_dict: The ``RuleGroup`` dict from DescribeRuleGroup.

    Returns:
        ``FORMAT_SURICATA`` for ``RulesString``, ``FORMAT_DOMAIN_LIST`` for
        ``RulesSourceList``, ``FORMAT_STANDARD`` for ``StatefulRules``, else
        ``FORMAT_UNKNOWN``.
    """
    rules_source = (rule_group_dict or {}).get('RulesSource', {})
    if 'RulesString' in rules_source:
        return FORMAT_SURICATA
    if 'RulesSourceList' in rules_source:
        return FORMAT_DOMAIN_LIST
    if 'StatefulRules' in rules_source:
        return FORMAT_STANDARD
    return FORMAT_UNKNOWN


def describe_policy_facts(session_manager, region, policy_arn) -> PolicyFacts:
    """Read a firewall policy's facts into a ``PolicyFacts``.

    Reads the policy via DescribeFirewallPolicy and the ordered table of
    stateful references, classifying each reference as customer-owned vs managed
    by cross-referencing ListRuleGroups(Scope=ACCOUNT). Rule bodies are NOT
    fetched here.

    Args:
        session_manager: AWSSessionManager used to create the client.
        region: AWS region of the policy.
        policy_arn: The firewall policy ARN.

    Returns:
        A populated ``PolicyFacts`` with ``stateful_refs`` sorted ascending by
        priority (None last, stable).

    Raises:
        FirewallPolicyApiError: If DescribeFirewallPolicy fails, or -- as a
            DISTINCT error -- if the account ListRuleGroups cross-reference call
            fails so customer-vs-managed classification could not be performed.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        resp = client.describe_firewall_policy(FirewallPolicyArn=policy_arn)
    except Exception as e:
        raise FirewallPolicyApiError(
            "Failed to describe firewall policy {}: {}".format(policy_arn, str(e))
        ) from e

    fp = resp.get('FirewallPolicy', {})
    policy_response = resp.get('FirewallPolicyResponse', {})

    stateful_default_actions = fp.get('StatefulDefaultActions', [])

    engine_options = fp.get('StatefulEngineOptions', {})
    rule_order = engine_options.get('RuleOrder') or RULE_ORDER_DEFAULT_ACTION
    stream_exception_policy = engine_options.get('StreamExceptionPolicy') or "DROP"

    # Policy-level $HOME_NET (key is "HOME_NET" without the leading $).
    home_net_definition = (
        fp.get('PolicyVariables', {})
        .get('RuleVariables', {})
        .get('HOME_NET', {})
        .get('Definition')
    )
    policy_home_net = home_net_definition if home_net_definition else None

    stateless_refs = fp.get('StatelessRuleGroupReferences', [])
    has_stateless_refs = bool(stateless_refs)
    stateless_ref_count = len(stateless_refs)

    # Cross-reference stateful refs against the account's own rule groups so
    # each can be classified customer-owned vs managed. A failure here must be
    # surfaced as a DISTINCT error (never silently collapse the classification).
    try:
        account_groups = list_user_rule_groups(session_manager, region)
    except Exception as e:
        raise FirewallPolicyApiError(
            "Could not list account rule groups to classify customer-owned vs "
            "managed stateful references for policy {}: {}".format(policy_arn, str(e))
        ) from e

    account_arns = {g.get('Arn', '') for g in account_groups}

    stateful_raw = fp.get('StatefulRuleGroupReferences', [])
    stateful_refs: List[StatefulGroupRef] = []
    for ref in stateful_raw:
        arn = ref.get('ResourceArn', '')
        name = arn.rsplit('/', 1)[-1]
        priority = ref.get('Priority')
        stateful_refs.append(
            StatefulGroupRef(
                arn=arn,
                name=name,
                priority=priority,
                is_customer_owned=arn in account_arns,
            )
        )

    # Ascending priority; None sorts last; stable (Python sort is stable).
    stateful_refs = sorted(
        stateful_refs,
        key=lambda r: (r.priority is None, r.priority if r.priority is not None else 0),
    )

    policy_name = policy_response.get('FirewallPolicyName') or policy_arn.rsplit('/', 1)[-1]

    return PolicyFacts(
        policy_name=policy_name,
        policy_arn=policy_arn,
        region=region,
        rule_order=rule_order,
        stateful_default_actions=stateful_default_actions,
        stream_exception_policy=stream_exception_policy,
        policy_home_net=policy_home_net,
        has_stateless_refs=has_stateless_refs,
        stateless_ref_count=stateless_ref_count,
        stateful_refs=stateful_refs,
    )


def fetch_customer_group(session_manager, region, ref) -> RuleGroupSource:
    """Fetch and parse a single customer-owned stateful rule group.

    Reads the rule group via DescribeRuleGroup, classifies its format, and -- for
    Suricata-format groups -- parses the rules and variables into a
    ``RuleGroupSource``. Mutates ``ref`` in place: sets ``rule_format`` and
    (for Suricata) ``analyzable_rule_count``; on an expected AWS failure sets
    ``fetch_error``.

    Args:
        session_manager: AWSSessionManager used to create the client.
        region: AWS region of the rule group.
        ref: The ``StatefulGroupRef`` to fetch (its ``arn`` identifies it).

    Returns:
        A ``RuleGroupSource`` with ``kind == GROUP_KIND_AWS``. For a
        non-Suricata format the rules list is empty and ``load_error`` is None.
        On an expected AWS failure the source carries ``load_error`` (the real
        message) and this function does NOT raise.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        resp = client.describe_rule_group(RuleGroupArn=ref.arn, Type='STATEFUL')
    except Exception as e:
        message = str(e)
        ref.fetch_error = message
        return RuleGroupSource(
            kind=GROUP_KIND_AWS,
            name=ref.name,
            rules=[],
            variables={},
            origin_path=ref.arn,
            load_error=message,
        )

    rule_group = resp.get('RuleGroup', {})
    fmt = classify_group_format(rule_group)
    ref.rule_format = fmt

    if fmt != FORMAT_SURICATA:
        # Non-Suricata format: record the format on the ref and return an empty
        # source without raising.
        return RuleGroupSource(
            kind=GROUP_KIND_AWS,
            name=ref.name,
            rules=[],
            variables={},
            origin_path=ref.arn,
            load_error=None,
        )

    rules_string = rule_group.get('RulesSource', {}).get('RulesString', '')
    rules = parse_rules_string(rules_string)

    # Merge RuleVariables (IPSets/PortSets) with ReferenceSets so the shared
    # helper sees both in the single dict shape it reads.
    variables_input = dict(rule_group.get('RuleVariables', {}))
    variables_input['ReferenceSets'] = rule_group.get('ReferenceSets', {})
    variables = parse_rule_variables(variables_input)

    source = RuleGroupSource(
        kind=GROUP_KIND_AWS,
        name=ref.name,
        rules=rules,
        variables=variables,
        origin_path=ref.arn,
        load_error=None,
    )
    ref.analyzable_rule_count = source.analyzable_rule_count()
    return source
