"""
Test Mode Transformer for Managed Rule Group Generator

Transforms rules for Test Mode deployment:
- Changes all rule actions to 'alert'
- Prefixes each rule's msg field with [TEST-<ORIGINAL_ACTION>]

This matches the exact prefix format used by Suricata Generator's Test Mode
(e.g., [TEST-DROP], [TEST-REJECT], [TEST-PASS]).

The transformation is idempotent: rules already in test mode are not
double-transformed.
"""

import re
from typing import List

from .rule_parser import ParsedRule


# Regex to detect if a msg already starts with [TEST-...] prefix
_TEST_PREFIX_RE = re.compile(r'^\[TEST-[A-Z]+\]\s*')

# Regex to match the action keyword at the start of a rule line
_ACTION_RE = re.compile(r'^(\w+)(\s+)')

# Regex to match msg:"..." in rule options
_MSG_IN_RULE_RE = re.compile(r'(msg\s*:\s*")([^"]*?)(")')


def apply_test_mode(rule: ParsedRule) -> ParsedRule:
    """Apply Test Mode transformation to a single rule.

    Transformation steps:
    1. Record the original action keyword (e.g., 'drop').
    2. Replace the action keyword with 'alert'.
    3. Prepend [TEST-<ORIGINAL_ACTION>] to the msg field (uppercased).
    4. Skip if the msg already starts with [TEST-...] (idempotent).

    Creates a new ParsedRule with the transformed raw string. The original
    ParsedRule is not modified.

    Args:
        rule: The parsed rule to transform.

    Returns:
        A new ParsedRule with test mode applied. If the rule is a comment,
        blank, or already in test mode, returns the original rule unchanged.
    """
    # Skip comments, blanks, and rules without an action
    if rule.is_comment or rule.is_blank or not rule.action:
        return rule

    original_action = rule.action.upper()

    # Check if already in test mode (idempotent)
    if rule.msg and _TEST_PREFIX_RE.match(rule.msg):
        return rule

    # Transform the raw rule string
    raw = rule.raw.strip()

    # Step 1: Replace the action keyword with 'alert'
    new_raw = _ACTION_RE.sub(r'alert\2', raw, count=1)

    # Step 2: Prepend [TEST-<ACTION>] to the msg field
    test_prefix = f"[TEST-{original_action}] "

    def _prepend_test_prefix(match):
        msg_start = match.group(1)  # msg:"
        msg_content = match.group(2)  # actual message
        msg_end = match.group(3)  # "
        return f'{msg_start}{test_prefix}{msg_content}{msg_end}'

    new_raw = _MSG_IN_RULE_RE.sub(_prepend_test_prefix, new_raw, count=1)

    # Build a new ParsedRule with the transformed raw string
    # Copy all fields from the original, update the changed ones
    new_rule = ParsedRule(
        raw=new_raw,
        action="alert",
        protocol=rule.protocol,
        source=rule.source,
        source_port=rule.source_port,
        direction=rule.direction,
        destination=rule.destination,
        destination_port=rule.destination_port,
        options_raw=rule.options_raw,  # Will be updated below
        sid=rule.sid,
        rev=rule.rev,
        msg=f"{test_prefix}{rule.msg}" if rule.msg else rule.msg,
        metadata=rule.metadata.copy(),
        is_comment=rule.is_comment,
        is_blank=rule.is_blank,
        source_rule_group=rule.source_rule_group,
        source_last_modified=rule.source_last_modified,
        line_number=rule.line_number,
    )

    # Update options_raw with the new msg
    if rule.msg:
        new_rule.options_raw = _MSG_IN_RULE_RE.sub(
            _prepend_test_prefix, rule.options_raw, count=1
        )

    return new_rule


def apply_test_mode_bulk(rules: List[ParsedRule]) -> List[ParsedRule]:
    """Apply Test Mode transformation to a list of rules.

    Args:
        rules: List of ParsedRule objects to transform.

    Returns:
        List of new ParsedRule objects with test mode applied.
    """
    return [apply_test_mode(rule) for rule in rules]


def remove_test_mode(rule: ParsedRule) -> ParsedRule:
    """Remove Test Mode transformation from a single rule.

    Reverses the test mode transformation:
    1. Extracts the original action from [TEST-<ACTION>] prefix.
    2. Restores the original action keyword.
    3. Removes the [TEST-<ACTION>] prefix from the msg field.

    Args:
        rule: The parsed rule to un-transform.

    Returns:
        A new ParsedRule with test mode removed. If the rule is not in test
        mode, returns the original rule unchanged.
    """
    if rule.is_comment or rule.is_blank or not rule.msg:
        return rule

    # Check if in test mode
    prefix_match = _TEST_PREFIX_RE.match(rule.msg)
    if not prefix_match:
        return rule

    # Extract original action from prefix: [TEST-DROP] -> DROP -> drop
    prefix = prefix_match.group(0)  # e.g., "[TEST-DROP] "
    original_action = prefix.strip().lstrip('[').rstrip(']').replace('TEST-', '').lower()

    # Remove prefix from msg
    new_msg = rule.msg[len(prefix):].strip()
    if not new_msg:
        new_msg = rule.msg  # Safety: don't create empty msg

    # Rebuild raw string
    raw = rule.raw.strip()

    # Replace 'alert' action with original action
    new_raw = _ACTION_RE.sub(f'{original_action}\\2', raw, count=1)

    # Remove [TEST-<ACTION>] prefix from msg in raw string
    def _remove_test_prefix(match):
        msg_start = match.group(1)
        msg_content = match.group(2)
        msg_end = match.group(3)
        cleaned = _TEST_PREFIX_RE.sub('', msg_content).strip()
        return f'{msg_start}{cleaned}{msg_end}'

    new_raw = _MSG_IN_RULE_RE.sub(_remove_test_prefix, new_raw, count=1)

    return ParsedRule(
        raw=new_raw,
        action=original_action,
        protocol=rule.protocol,
        source=rule.source,
        source_port=rule.source_port,
        direction=rule.direction,
        destination=rule.destination,
        destination_port=rule.destination_port,
        options_raw=_MSG_IN_RULE_RE.sub(_remove_test_prefix, rule.options_raw, count=1) if rule.options_raw else rule.options_raw,
        sid=rule.sid,
        rev=rule.rev,
        msg=new_msg,
        metadata=rule.metadata.copy(),
        is_comment=rule.is_comment,
        is_blank=rule.is_blank,
        source_rule_group=rule.source_rule_group,
        source_last_modified=rule.source_last_modified,
        line_number=rule.line_number,
    )


def is_test_mode_rule(rule: ParsedRule) -> bool:
    """Check if a rule is currently in Test Mode.

    Args:
        rule: The parsed rule to check.

    Returns:
        True if the rule's msg starts with [TEST-...] prefix.
    """
    if not rule.msg:
        return False
    return bool(_TEST_PREFIX_RE.match(rule.msg))


def get_original_action(rule: ParsedRule) -> str:
    """Get the original action from a test mode rule.

    Args:
        rule: A parsed rule that may be in test mode.

    Returns:
        The original action string (e.g., 'drop'). If the rule is not in
        test mode, returns the current action.
    """
    if not rule.msg:
        return rule.action

    prefix_match = _TEST_PREFIX_RE.match(rule.msg)
    if not prefix_match:
        return rule.action

    prefix = prefix_match.group(0).strip()
    return prefix.lstrip('[').rstrip(']').replace('TEST-', '').lower()
