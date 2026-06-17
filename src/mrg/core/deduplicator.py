"""
Rule Deduplicator for Managed Rule Group Generator

Deduplicates Suricata rules by SID (Signature ID). When the same SID appears
in multiple source rule groups, the rule from the most recently updated source
rule group takes precedence (based on LastModifiedTime).
"""

from typing import Dict, List, Optional, Tuple

from .rule_parser import ParsedRule


def deduplicate_rules(rules: List[ParsedRule]) -> List[ParsedRule]:
    """Deduplicate rules by SID, keeping the version from the most recently modified source.

    When the same SID appears in multiple source rule groups, the rule from the
    source rule group with the latest `source_last_modified` timestamp takes
    precedence. If two rules have the same SID and the same source timestamp
    (or no timestamp), the last one encountered wins.

    Rules without a SID are excluded from the output (they cannot be deduplicated).

    Args:
        rules: List of ParsedRule objects (may contain duplicates across sources).

    Returns:
        List of deduplicated ParsedRule objects, preserving the order of first
        occurrence of each SID.
    """
    # Track best rule per SID: {sid: ParsedRule}
    best_by_sid: Dict[int, ParsedRule] = {}
    # Track order of first occurrence: {sid: index}
    first_occurrence_order: Dict[int, int] = {}

    for rule in rules:
        if rule.sid is None:
            continue

        sid = rule.sid

        if sid not in best_by_sid:
            # First time seeing this SID
            best_by_sid[sid] = rule
            first_occurrence_order[sid] = len(first_occurrence_order)
        else:
            # Duplicate SID - compare source_last_modified timestamps
            existing = best_by_sid[sid]
            if _is_newer(rule, existing):
                best_by_sid[sid] = rule

    # Sort by first occurrence order to maintain stable output
    sorted_sids = sorted(best_by_sid.keys(), key=lambda s: first_occurrence_order[s])

    return [best_by_sid[sid] for sid in sorted_sids]


def _is_newer(candidate: ParsedRule, existing: ParsedRule) -> bool:
    """Determine if the candidate rule is from a more recently modified source.

    Comparison is based on `source_last_modified` strings. These are expected
    to be ISO 8601 or similar sortable timestamp strings from the AWS API
    (e.g., "2026-02-20T15:30:00Z").

    Args:
        candidate: The new rule being considered.
        existing: The currently stored rule for the same SID.

    Returns:
        True if the candidate should replace the existing rule.
    """
    # If candidate has no timestamp, don't replace
    if not candidate.source_last_modified:
        return False

    # If existing has no timestamp, candidate with timestamp wins
    if not existing.source_last_modified:
        return True

    # Compare timestamps as strings (ISO 8601 is lexicographically sortable)
    return candidate.source_last_modified > existing.source_last_modified


def find_duplicates(rules: List[ParsedRule]) -> Dict[int, List[ParsedRule]]:
    """Find all duplicate SIDs in a list of rules.

    Useful for reporting/diagnostics to show which rules were deduplicated.

    Args:
        rules: List of ParsedRule objects.

    Returns:
        Dictionary mapping SID to list of rules with that SID.
        Only includes SIDs that appear more than once.
    """
    sid_groups: Dict[int, List[ParsedRule]] = {}

    for rule in rules:
        if rule.sid is None:
            continue
        if rule.sid not in sid_groups:
            sid_groups[rule.sid] = []
        sid_groups[rule.sid].append(rule)

    # Return only duplicates (SIDs appearing more than once)
    return {sid: group for sid, group in sid_groups.items() if len(group) > 1}


def get_dedup_stats(rules_before: List[ParsedRule],
                    rules_after: List[ParsedRule]) -> Dict[str, int]:
    """Calculate deduplication statistics.

    Args:
        rules_before: Rules before deduplication.
        rules_after: Rules after deduplication.

    Returns:
        Dictionary with deduplication statistics:
        - total_before: Number of rules with SIDs before dedup
        - total_after: Number of rules after dedup
        - duplicates_removed: Number of duplicate rules removed
        - unique_sids: Number of unique SIDs
    """
    sids_before = [r.sid for r in rules_before if r.sid is not None]
    sids_after = [r.sid for r in rules_after if r.sid is not None]

    return {
        "total_before": len(sids_before),
        "total_after": len(sids_after),
        "duplicates_removed": len(sids_before) - len(sids_after),
        "unique_sids": len(set(sids_before)),
    }
