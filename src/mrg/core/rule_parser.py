"""
Rule Parser for Managed Rule Group Generator

Parses Suricata-format rules from AWS Network Firewall managed rule groups,
extracting metadata key-value pairs for filtering.

Handles:
- Single-line Suricata rules (action protocol src -> dst (options;))
- Metadata extraction from the options section
- Comment lines and blank lines
- Rules with missing or incomplete metadata
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ParsedRule:
    """Represents a parsed Suricata rule with extracted metadata.

    Attributes:
        raw: The original raw rule string (single line).
        action: The rule action keyword (e.g., 'drop', 'alert', 'pass', 'reject').
        protocol: The protocol (e.g., 'tcp', 'udp', 'ip', 'icmp', 'http', 'tls').
        source: Source address/network (e.g., '$HOME_NET').
        source_port: Source port (e.g., 'any', '80').
        direction: Direction operator ('->' or '<>').
        destination: Destination address/network.
        destination_port: Destination port.
        options_raw: The raw options string (everything between the outermost parentheses).
        sid: The Signature ID extracted from options, or None if not found.
        rev: The revision number extracted from options, or None if not found.
        msg: The message string extracted from options, or None if not found.
        metadata: Dictionary of metadata key-value pairs extracted from the metadata option.
        is_comment: True if this line is a comment (starts with #).
        is_blank: True if this line is blank/whitespace only.
        source_rule_group: Optional identifier for which source rule group this rule came from.
        source_last_modified: Optional datetime string for the source rule group's LastModifiedTime.
        line_number: Optional line number within the source rules string.
    """

    raw: str
    action: str = ""
    protocol: str = ""
    source: str = ""
    source_port: str = ""
    direction: str = ""
    destination: str = ""
    destination_port: str = ""
    options_raw: str = ""
    sid: Optional[int] = None
    rev: Optional[int] = None
    msg: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)
    is_comment: bool = False
    is_blank: bool = False
    source_rule_group: Optional[str] = None
    source_last_modified: Optional[str] = None
    line_number: Optional[int] = None


# Regex patterns for parsing
# Match the rule header: action protocol source source_port direction dest dest_port
_RULE_HEADER_RE = re.compile(
    r'^(?P<action>\w+)\s+'           # action (drop, alert, pass, reject, etc.)
    r'(?P<protocol>\w+)\s+'          # protocol (tcp, udp, ip, icmp, http, tls, etc.)
    r'(?P<source>\S+)\s+'            # source address
    r'(?P<source_port>\S+)\s+'       # source port
    r'(?P<direction>->|<>)\s+'       # direction
    r'(?P<destination>\S+)\s+'       # destination address
    r'(?P<destination_port>\S+)\s*'  # destination port
    r'\((?P<options>.*)\)\s*$'       # options in parentheses
)

# Match SID in options: sid:12345;
_SID_RE = re.compile(r'\bsid\s*:\s*(\d+)\s*;')

# Match rev in options: rev:3;
_REV_RE = re.compile(r'\brev\s*:\s*(\d+)\s*;')

# Match msg in options: msg:"some message";
_MSG_RE = re.compile(r'\bmsg\s*:\s*"([^"]*?)"\s*;')

# Match metadata section in options: metadata:key1 val1,key2 val2,...;
_METADATA_RE = re.compile(r'\bmetadata\s*:\s*([^;]+);')


def parse_metadata(metadata_str: str) -> Dict[str, str]:
    """Parse a metadata string into a dictionary of key-value pairs.

    Metadata format: comma-separated key-value pairs where keys and values
    are space-separated.

    Example:
        "created_at 2024_01_15,signature_severity Major,confidence High"
        -> {"created_at": "2024_01_15", "signature_severity": "Major", "confidence": "High"}

    Some metadata fields may have multi-word values (e.g., "tag Description_Generated_By_Proofpoint").
    In that case, the first token is the key and the remaining tokens are the value.

    Args:
        metadata_str: Raw metadata string (content between 'metadata:' and ';')

    Returns:
        Dictionary of metadata key-value pairs. Keys are lowercase.
    """
    result = {}
    if not metadata_str or not metadata_str.strip():
        return result

    # Split by comma to get individual key-value pairs
    pairs = metadata_str.split(',')
    for pair in pairs:
        pair = pair.strip()
        if not pair:
            continue

        # Split on first space to separate key from value
        parts = pair.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            result[key.strip().lower()] = value.strip()
        elif len(parts) == 1:
            # Key with no value - store with empty string
            result[parts[0].strip().lower()] = ""

    return result


def parse_rule(rule_line: str, line_number: Optional[int] = None,
               source_rule_group: Optional[str] = None,
               source_last_modified: Optional[str] = None) -> ParsedRule:
    """Parse a single Suricata rule line into a ParsedRule object.

    Handles:
    - Full Suricata rules with header and options
    - Comment lines (starting with #)
    - Blank/whitespace-only lines
    - Disabled rules (comments containing a valid rule after the #)

    Args:
        rule_line: A single line from a RulesString.
        line_number: Optional line number for tracking position.
        source_rule_group: Optional source rule group ARN/name.
        source_last_modified: Optional LastModifiedTime of the source rule group.

    Returns:
        A ParsedRule object with all extracted fields.
    """
    rule = ParsedRule(
        raw=rule_line,
        line_number=line_number,
        source_rule_group=source_rule_group,
        source_last_modified=source_last_modified,
    )

    stripped = rule_line.strip()

    # Blank line
    if not stripped:
        rule.is_blank = True
        return rule

    # Comment line
    if stripped.startswith('#'):
        rule.is_comment = True
        return rule

    # Try to match the rule header
    match = _RULE_HEADER_RE.match(stripped)
    if not match:
        # Not a valid rule line - treat as comment/other
        rule.is_comment = True
        return rule

    rule.action = match.group('action').lower()
    rule.protocol = match.group('protocol').lower()
    rule.source = match.group('source')
    rule.source_port = match.group('source_port')
    rule.direction = match.group('direction')
    rule.destination = match.group('destination')
    rule.destination_port = match.group('destination_port')
    rule.options_raw = match.group('options')

    # Extract SID
    sid_match = _SID_RE.search(rule.options_raw)
    if sid_match:
        rule.sid = int(sid_match.group(1))

    # Extract rev
    rev_match = _REV_RE.search(rule.options_raw)
    if rev_match:
        rule.rev = int(rev_match.group(1))

    # Extract msg
    msg_match = _MSG_RE.search(rule.options_raw)
    if msg_match:
        rule.msg = msg_match.group(1)

    # Extract metadata
    metadata_match = _METADATA_RE.search(rule.options_raw)
    if metadata_match:
        rule.metadata = parse_metadata(metadata_match.group(1))

    return rule


def parse_rules_string(rules_string: str,
                       source_rule_group: Optional[str] = None,
                       source_last_modified: Optional[str] = None) -> List[ParsedRule]:
    """Parse a complete RulesString into a list of ParsedRule objects.

    Splits the input by newlines and parses each line individually.
    Blank lines and comment lines are included in the output (with appropriate flags).

    Args:
        rules_string: The full RulesString from a managed rule group's DescribeRuleGroup response.
        source_rule_group: Optional source rule group ARN/name to tag each rule with.
        source_last_modified: Optional LastModifiedTime of the source rule group.

    Returns:
        List of ParsedRule objects, one per line in the input.
    """
    if not rules_string:
        return []

    lines = rules_string.split('\n')
    rules = []
    for i, line in enumerate(lines, start=1):
        rule = parse_rule(
            line,
            line_number=i,
            source_rule_group=source_rule_group,
            source_last_modified=source_last_modified,
        )
        rules.append(rule)

    return rules


def get_active_rules(rules: List[ParsedRule]) -> List[ParsedRule]:
    """Filter a list of parsed rules to only active (non-comment, non-blank) rules.

    Args:
        rules: List of ParsedRule objects.

    Returns:
        List of ParsedRule objects that are actual rules (not comments or blank lines).
    """
    return [r for r in rules if not r.is_comment and not r.is_blank]


def get_rules_with_sid(rules: List[ParsedRule]) -> List[ParsedRule]:
    """Filter a list of parsed rules to only those with a valid SID.

    Args:
        rules: List of ParsedRule objects.

    Returns:
        List of ParsedRule objects that have a non-None SID.
    """
    return [r for r in rules if r.sid is not None and not r.is_comment and not r.is_blank]
