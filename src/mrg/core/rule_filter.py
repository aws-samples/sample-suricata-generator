"""
Rule Filter Engine for Managed Rule Group Generator

Implements the row-based AND/OR filter model for filtering Suricata rules
based on metadata criteria.

Filter Logic:
- Between rows: AND (a rule must satisfy ALL rows to be included)
- Within a row: OR (a rule matches a row if it matches ANY value in that row)

Supported Operators:
- equals: Exact match (case-insensitive)
- not_equals: Negation of exact match (case-insensitive)
- in: Match any value in a list (case-insensitive)
- not_in: Match none of the values in a list (case-insensitive)
- contains: Substring match (case-insensitive)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .rule_parser import ParsedRule


@dataclass
class FilterCondition:
    """A single filter condition (one row in the filter builder).

    Attributes:
        field: The metadata field to filter on (e.g., 'signature_deployment').
        operator: The comparison operator ('equals', 'not_equals', 'in', 'not_in', 'contains').
        values: List of values to compare against. Multiple values are OR-combined.
    """
    field: str
    operator: str
    values: List[str]

    def __post_init__(self):
        """Normalize field name to lowercase."""
        self.field = self.field.strip().lower()
        self.operator = self.operator.strip().lower()
        # Don't strip values - they may contain meaningful whitespace
        # But do ensure they're strings
        self.values = [str(v) for v in self.values]


@dataclass
class FilterConfig:
    """Complete filter configuration with multiple conditions.

    Attributes:
        conditions: List of FilterCondition objects. Combined with AND logic.
        missing_metadata_behavior: How to handle rules missing a filtered metadata field.
            'exclude' (default): Rules missing the field are excluded.
            'include': Rules missing the field are included.
    """
    conditions: List[FilterCondition] = field(default_factory=list)
    missing_metadata_behavior: str = "exclude"

    def __post_init__(self):
        """Validate missing_metadata_behavior."""
        if self.missing_metadata_behavior not in ("exclude", "include"):
            raise ValueError(
                f"Invalid missing_metadata_behavior: '{self.missing_metadata_behavior}'. "
                f"Must be 'exclude' or 'include'."
            )


@dataclass
class FilterResult:
    """Result of applying filters to a set of rules.

    Attributes:
        matching_rules: Rules that passed all filter conditions.
        excluded_missing_metadata: Rules excluded because they were missing
            a metadata field referenced by a filter condition.
        total_scanned: Total number of active rules scanned.
        total_matching: Number of rules that matched all filters.
        total_missing_metadata: Number of rules affected by missing metadata.
    """
    matching_rules: List[ParsedRule] = field(default_factory=list)
    excluded_missing_metadata: List[ParsedRule] = field(default_factory=list)
    total_scanned: int = 0
    total_matching: int = 0
    total_missing_metadata: int = 0


# Valid operators
VALID_OPERATORS = {"equals", "not_equals", "in", "not_in", "contains"}

# Metadata field aliases: maps filter field names to alternative keys
# that may appear in actual rule metadata. The filter engine checks
# both the primary field name and any aliases.
# This handles cases where the spec uses a different name than what
# appears in the real managed rule group metadata.
_FIELD_ALIASES = {
    'signature_deployment': ['deployment'],
    'deployment': ['signature_deployment'],
}


def _resolve_field_value(field_name: str, metadata: Dict[str, str]) -> Optional[str]:
    """Resolve a metadata field value, checking aliases if the primary key is missing.

    Args:
        field_name: The filter field name (lowercase).
        metadata: The rule's metadata dictionary (keys are lowercase).

    Returns:
        The metadata value string if found (via primary key or alias), or None if missing.
    """
    # Check primary field name first
    if field_name in metadata:
        return metadata[field_name]

    # Check aliases
    aliases = _FIELD_ALIASES.get(field_name, [])
    for alias in aliases:
        if alias in metadata:
            return metadata[alias]

    return None


def _evaluate_condition(condition: FilterCondition, metadata: Dict[str, str],
                        missing_metadata_behavior: str) -> Optional[bool]:
    """Evaluate a single filter condition against a rule's metadata.

    Args:
        condition: The filter condition to evaluate.
        metadata: The rule's metadata dictionary (keys are lowercase).
        missing_metadata_behavior: 'exclude' or 'include' for missing fields.

    Returns:
        True if the condition is satisfied.
        False if the condition is not satisfied.
        None if the metadata field is missing (caller decides based on behavior).
    """
    field_name = condition.field.lower()
    operator = condition.operator

    # Resolve the field value, checking aliases if needed
    rule_value = _resolve_field_value(field_name, metadata)

    # Check if the metadata field exists (including aliases)
    if rule_value is None:
        return None  # Missing metadata - caller decides

    if operator == "equals":
        # OR across values: match if rule_value equals ANY of the condition values
        return any(
            rule_value.lower() == v.lower()
            for v in condition.values
        )

    elif operator == "not_equals":
        # NOT equals: rule_value must not equal ANY of the condition values
        # With multiple values: rule must not equal any of them
        return all(
            rule_value.lower() != v.lower()
            for v in condition.values
        )

    elif operator == "in":
        # IN: rule_value must be in the list of values (case-insensitive)
        return any(
            rule_value.lower() == v.lower()
            for v in condition.values
        )

    elif operator == "not_in":
        # NOT IN: rule_value must not be in the list of values (case-insensitive)
        return all(
            rule_value.lower() != v.lower()
            for v in condition.values
        )

    elif operator == "contains":
        # CONTAINS: rule_value must contain any of the specified substrings
        return any(
            v.lower() in rule_value.lower()
            for v in condition.values
        )

    else:
        raise ValueError(f"Unknown operator: '{operator}'. Valid operators: {VALID_OPERATORS}")


def evaluate_rule(rule: ParsedRule, filter_config: FilterConfig) -> Optional[bool]:
    """Evaluate whether a rule matches all filter conditions.

    Uses AND logic between conditions (all must match).
    Each condition uses OR logic within its values list.

    Args:
        rule: The parsed rule to evaluate.
        filter_config: The filter configuration with conditions and behavior settings.

    Returns:
        True if the rule matches all conditions.
        False if the rule fails any condition.
        None if the rule was affected by missing metadata (the actual inclusion/exclusion
        is determined by the caller based on missing_metadata_behavior, but this function
        returns None to signal the ambiguity).
    """
    if not filter_config.conditions:
        # No conditions = match everything
        return True

    has_missing_metadata = False

    for condition in filter_config.conditions:
        result = _evaluate_condition(
            condition, rule.metadata, filter_config.missing_metadata_behavior
        )

        if result is None:
            # Missing metadata field
            has_missing_metadata = True
            if filter_config.missing_metadata_behavior == "exclude":
                # In exclude mode, missing metadata means the condition fails
                return None
            else:
                # In include mode, skip this condition (treat as if it passed)
                continue

        if not result:
            # Condition explicitly failed (metadata was present but didn't match)
            return False

    if has_missing_metadata:
        # We only get here in "include" mode where missing fields were skipped
        return None

    return True


def apply_filters(rules: List[ParsedRule],
                  filter_config: FilterConfig) -> FilterResult:
    """Apply filter conditions to a list of parsed rules.

    Only active rules (non-comment, non-blank) with a SID are evaluated.
    Rules without a SID are silently skipped.

    Args:
        rules: List of ParsedRule objects to filter.
        filter_config: The filter configuration specifying conditions and behavior.

    Returns:
        FilterResult with matching rules and statistics.
    """
    result = FilterResult()

    # Only evaluate active rules with SIDs
    active_rules = [
        r for r in rules
        if not r.is_comment and not r.is_blank and r.sid is not None
    ]
    result.total_scanned = len(active_rules)

    for rule in active_rules:
        match_result = evaluate_rule(rule, filter_config)

        if match_result is True:
            # Rule explicitly matched all conditions
            result.matching_rules.append(rule)
        elif match_result is None:
            # Rule was affected by missing metadata
            result.excluded_missing_metadata.append(rule)
            if filter_config.missing_metadata_behavior == "include":
                # In include mode, missing metadata rules are included
                result.matching_rules.append(rule)
        # match_result is False: rule didn't match, skip it

    result.total_matching = len(result.matching_rules)
    result.total_missing_metadata = len(result.excluded_missing_metadata)

    return result


def validate_filter_config(filter_config: FilterConfig) -> List[str]:
    """Validate a filter configuration for correctness.

    Checks:
    - All operators are valid
    - All conditions have at least one value
    - All conditions have a non-empty field name

    Args:
        filter_config: The filter configuration to validate.

    Returns:
        List of error messages. Empty list if valid.
    """
    errors = []

    for i, condition in enumerate(filter_config.conditions):
        row_label = f"Row {i + 1}"

        if not condition.field:
            errors.append(f"{row_label}: Field name is empty.")

        if condition.operator not in VALID_OPERATORS:
            errors.append(
                f"{row_label}: Invalid operator '{condition.operator}'. "
                f"Valid operators: {', '.join(sorted(VALID_OPERATORS))}"
            )

        if not condition.values:
            errors.append(f"{row_label}: No values specified.")

    if filter_config.missing_metadata_behavior not in ("exclude", "include"):
        errors.append(
            f"Invalid missing_metadata_behavior: '{filter_config.missing_metadata_behavior}'. "
            f"Must be 'exclude' or 'include'."
        )

    return errors


def filter_config_from_dict(data: dict) -> FilterConfig:
    """Create a FilterConfig from a dictionary (e.g., from a .mrg JSON file).

    Expected format:
    {
        "logic": "AND",
        "conditions": [
            {"field": "signature_deployment", "operator": "equals", "values": ["Internal"]},
            ...
        ]
    }

    Args:
        data: Dictionary containing filter configuration.

    Returns:
        FilterConfig object.
    """
    conditions = []
    for cond_data in data.get("conditions", []):
        conditions.append(FilterCondition(
            field=cond_data.get("field", ""),
            operator=cond_data.get("operator", "equals"),
            values=cond_data.get("values", []),
        ))

    missing_behavior = data.get("missing_metadata_behavior", "exclude")

    return FilterConfig(
        conditions=conditions,
        missing_metadata_behavior=missing_behavior,
    )


def filter_config_to_dict(filter_config: FilterConfig) -> dict:
    """Convert a FilterConfig to a dictionary for JSON serialization.

    Args:
        filter_config: The filter configuration to serialize.

    Returns:
        Dictionary suitable for JSON serialization.
    """
    return {
        "logic": "AND",
        "conditions": [
            {
                "field": cond.field,
                "operator": cond.operator,
                "values": cond.values,
            }
            for cond in filter_config.conditions
        ],
    }
