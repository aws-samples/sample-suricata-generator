"""
Shared, UI-free parsing helpers for AWS Network Firewall stateful rule groups.

This module holds the pure parsing logic that turns a rule group's raw
``RulesString`` into ``SuricataRule`` objects and its ``RuleVariables`` /
``ReferenceSets`` into the normalized variables dict shape consumed by the
multi-rule-group review pipeline (``PolicyReviewService.build_namespaced_
variables``) and produced by ``FileManager.load_variables_file``.

It imports NO tkinter and makes NO AWS calls, so it is fully testable headless.
Both the JSON importer (``src/importers/stateful_rule_importer.py``) and the
live AWS ingestion layer (``src/aws/firewall_policy_api.py``) delegate rule
parsing here so the two paths cannot drift apart.
"""

from typing import Dict, List

from src.core.suricata_rule import SuricataRule
from src.core.constants import classify_reference_arn


def parse_rules_string(rules_string: str) -> List[SuricataRule]:
    """Parse a raw Suricata ``RulesString`` into ordered ``SuricataRule`` rows.

    Preserves in-group order and placeholder rows exactly as the JSON importer
    did: a blank line becomes a ``SuricataRule`` with ``is_blank = True``; a
    line starting with ``#`` becomes a ``SuricataRule`` with ``is_comment =
    True`` and ``comment_text`` set to the stripped line; any other line is
    parsed via ``SuricataRule.from_string`` and appended only when it parses to
    a truthy rule (unparseable lines are skipped, matching the importer).

    Args:
        rules_string: Raw Suricata rules as a single newline-delimited string.

    Returns:
        List of SuricataRule objects in source order.
    """
    rules: List[SuricataRule] = []
    lines = rules_string.split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            # Blank line
            blank_rule = SuricataRule()
            blank_rule.is_blank = True
            rules.append(blank_rule)
        elif line.startswith('#'):
            # Comment line
            comment_rule = SuricataRule()
            comment_rule.is_comment = True
            comment_rule.comment_text = line
            rules.append(comment_rule)
        else:
            # Parse as Suricata rule
            rule = SuricataRule.from_string(line)
            if rule:
                rules.append(rule)

    return rules


def parse_rule_variables(rule_variables: dict) -> Dict[str, dict]:
    """Parse ``RuleVariables`` + ``ReferenceSets`` into the normalized shape.

    Produces the normalized dict shape read by
    ``PolicyReviewService.build_namespaced_variables`` and emitted by
    ``FileManager.load_variables_file``: every key carries its leading ``$`` or
    ``@`` and maps to ``{"definition", "description"[, "type"]}``.

    - ``IPSets`` and ``PortSets`` (each ``{VarName: {"Definition": [list]}}``)
      become ``{"$VarName": {"definition": "comma,joined", "description": ""}}``.
    - ``ReferenceSets.IPSetReferences`` (``{VarName: {"ReferenceArn": arn}}``)
      become ``{"@VarName": {"definition": arn, "description": "",
      "type": classify_reference_arn(arn)}}``.

    Missing sub-keys are tolerated (treated as empty).

    Args:
        rule_variables: A dict that may contain ``IPSets``, ``PortSets``, and a
            nested ``ReferenceSets`` block.

    Returns:
        The normalized variables dict (keys include leading ``$``/``@``).
    """
    variables: Dict[str, dict] = {}

    # IPSets and PortSets -> $-prefixed, comma-joined definitions.
    for section in ('IPSets', 'PortSets'):
        for var_name, var_data in rule_variables.get(section, {}).items():
            definition = (var_data or {}).get('Definition', [])
            variables['${}'.format(var_name)] = {
                'definition': ','.join(definition),
                'description': '',
            }

    # ReferenceSets.IPSetReferences -> @-prefixed, ARN definitions.
    reference_sets = rule_variables.get('ReferenceSets', {})
    ip_set_references = reference_sets.get('IPSetReferences', {})
    for var_name, var_data in ip_set_references.items():
        reference_arn = (var_data or {}).get('ReferenceArn', '')
        variables['@{}'.format(var_name)] = {
            'definition': reference_arn,
            'description': '',
            'type': classify_reference_arn(reference_arn),
        }

    return variables
