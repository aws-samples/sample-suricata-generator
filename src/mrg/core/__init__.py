"""
MRG Core modules.

Contains rule parsing, filtering, deduplication, test mode transformation,
and MRG configuration file management.
"""

from .rule_parser import ParsedRule, parse_rules_string, parse_rule, parse_metadata
from .rule_filter import (
    FilterCondition,
    FilterConfig,
    FilterResult,
    apply_filters,
    evaluate_rule,
    validate_filter_config,
    filter_config_from_dict,
    filter_config_to_dict,
)
from .deduplicator import deduplicate_rules, find_duplicates, get_dedup_stats
from .test_mode import apply_test_mode, apply_test_mode_bulk, remove_test_mode, is_test_mode_rule
from .mrg_file import (
    MRGConfig,
    MRGFileError,
    MRGFileFormatError,
    read_mrg_file,
    write_mrg_file,
    create_new_config,
    validate_mrg_config,
)

__all__ = [
    # rule_parser
    "ParsedRule",
    "parse_rules_string",
    "parse_rule",
    "parse_metadata",
    # rule_filter
    "FilterCondition",
    "FilterConfig",
    "FilterResult",
    "apply_filters",
    "evaluate_rule",
    "validate_filter_config",
    "filter_config_from_dict",
    "filter_config_to_dict",
    # deduplicator
    "deduplicate_rules",
    "find_duplicates",
    "get_dedup_stats",
    # test_mode
    "apply_test_mode",
    "apply_test_mode_bulk",
    "remove_test_mode",
    "is_test_mode_rule",
    # mrg_file
    "MRGConfig",
    "MRGFileError",
    "MRGFileFormatError",
    "read_mrg_file",
    "write_mrg_file",
    "create_new_config",
    "validate_mrg_config",
]
