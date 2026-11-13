"""Squid-to-Suricata converter (engine) for the Suricata Rule Generator.

Only the Converter_API is exported; see api.py. The package is
UI-free and offline, and imports nothing from the Generator except
src.core.version and src.core.aws_rule_constraints.
"""

from .api import (DENY_ACTIONS, EMITTED, NOT_CONVERTIBLE, NOTE_ONLY,
                  AccessLineOutcome, ConversionResult, ConvertedRule,
                  ConvertOptions, Prerequisite, RuleCheck, convert,
                  parse_config, read_config, render_html, render_report,
                  report_sections)

__all__ = [
    "RuleCheck", "DENY_ACTIONS", "ConvertOptions", "ConvertedRule",
    "AccessLineOutcome", "Prerequisite", "ConversionResult", "read_config",
    "parse_config", "convert", "render_report", "render_html",
    "report_sections",
    "EMITTED", "NOT_CONVERTIBLE", "NOTE_ONLY",
]
