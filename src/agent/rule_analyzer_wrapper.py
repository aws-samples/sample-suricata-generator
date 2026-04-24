"""
Rule Analyzer Wrapper for the Suricata Rule Generator AI Agent Layer.

Wraps the existing RuleAnalyzer from src/analysis/rule_analyzer.py and returns
structured AnalysisResult/AnalysisIssue objects for the agent pipeline.
"""

from src.agent.models import AnalysisIssue, AnalysisResult
from src.analysis.rule_analyzer import RuleAnalyzer
from src.core.suricata_rule import SuricataRule


# Map RuleAnalyzer conflict dict keys to (issue type, default severity)
_CATEGORY_MAP = {
    "critical": ("shadow", "error"),
    "warning": ("shadow", "warning"),
    "info": ("shadow", "info"),
    "protocol_layering": ("protocol_layering", "warning"),
    "sticky_buffer_order": ("sticky_buffer", "warning"),
    "udp_flow_established": ("keyword_mismatch", "warning"),
    "protocol_keyword_mismatch": ("keyword_mismatch", "warning"),
    "port_protocol_mismatch": ("keyword_mismatch", "warning"),
    "contradictory_flow": ("contradictory_flow", "error"),
    "packet_drop_flow_pass": ("contradictory_flow", "warning"),
    "asymmetric_flow": ("contradictory_flow", "warning"),
    "reject_ip_protocol": ("keyword_mismatch", "error"),
    "reject_quic_protocol": ("keyword_mismatch", "error"),
    "unsupported_keywords": ("keyword_mismatch", "error"),
    "pcre_restrictions": ("keyword_mismatch", "warning"),
    "threshold_limited": ("keyword_mismatch", "warning"),
    "priority_strict_order": ("keyword_mismatch", "info"),
}


class RuleAnalyzerWrapper:
    """Wraps RuleAnalyzer and returns structured AnalysisResult."""

    def __init__(self, variables: dict[str, str] | None = None):
        self.analyzer = RuleAnalyzer()
        self.variables = variables or {}

    def analyze(self, rule_strings: list[str]) -> AnalysisResult:
        """Analyze one or more rule strings for conflicts and quality issues.

        Parses each string via SuricataRule.from_string(), runs all analyzer
        checks, and returns a structured AnalysisResult.
        """
        rules = []
        for rs in rule_strings:
            parsed = SuricataRule.from_string(rs)
            if parsed:
                rules.append(parsed)

        if not rules:
            return AnalysisResult(passed=True)

        conflicts = self.analyzer.analyze_rule_conflicts(rules, self.variables)

        issues: list[AnalysisIssue] = []
        for category, items in conflicts.items():
            if not items:
                continue
            issue_type, default_severity = _CATEGORY_MAP.get(
                category, ("unknown", "info")
            )
            for item in items:
                severity = item.get("severity", default_severity)
                # Normalize severity values from analyzer
                if severity not in ("error", "warning", "info"):
                    severity = default_severity

                affected = []
                if "upper_rule" in item:
                    affected.append(str(item["upper_rule"]))
                if "lower_rule" in item:
                    affected.append(str(item["lower_rule"]))
                if "rule" in item:
                    affected.append(str(item["rule"]))

                issues.append(AnalysisIssue(
                    type=issue_type,
                    severity=severity,
                    message=item.get("message", item.get("description", category)),
                    affected_rules=affected,
                    recommendation=item.get("recommendation", ""),
                ))

        has_errors = any(i.severity == "error" for i in issues)
        return AnalysisResult(passed=not has_errors, issues=issues)
