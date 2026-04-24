"""
Data models for the Suricata Rule Generator AI Agent Layer.

All structured types used across the pipeline: detection intent, validation results,
analysis results, generation results, PCAP test results, and deploy results.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionIntent:
    """Structured detection intent extracted from natural language input.
    Maps directly to SuricataRule constructor parameters."""

    action: str = "alert"
    protocol: str = "tcp"
    src_net: str = "$HOME_NET"
    src_port: str = "any"
    dst_net: str = "$EXTERNAL_NET"
    dst_port: str = "any"
    direction: str = "->"
    message: str = ""
    content: str = ""
    sid: Optional[int] = None
    rev: Optional[int] = None
    metadata: Optional[dict] = None

    def to_suricata_kwargs(self) -> dict:
        """Returns dict suitable for SuricataRule(**kwargs)."""
        kwargs = {
            "action": self.action,
            "protocol": self.protocol,
            "src_net": self.src_net,
            "src_port": self.src_port,
            "dst_net": self.dst_net,
            "dst_port": self.dst_port,
            "direction": self.direction,
            "message": self.message,
            "content": self.content,
        }
        if self.sid is not None:
            kwargs["sid"] = self.sid
        if self.rev is not None:
            kwargs["rev"] = self.rev
        return kwargs


@dataclass
class ValidationError:
    """A single validation error with type, message, and location."""

    type: str       # "parse_failure" | "invalid_action" | "invalid_protocol" | "unknown_keyword" | "sid_out_of_range"
    message: str
    location: str   # e.g., "action field", "content keyword: foobar"


@dataclass
class ValidationResult:
    """Result of rule validation through suricata_rule.py."""

    valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    parsed_rule: object = None  # SuricataRule | None


@dataclass
class AnalysisIssue:
    """A single analysis issue found by rule_analyzer.py."""

    type: str           # "shadow" | "protocol_layering" | "sticky_buffer" | "keyword_mismatch" | "contradictory_flow"
    severity: str       # "error" | "warning" | "info"
    message: str
    affected_rules: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class AnalysisResult:
    """Result of conflict and quality analysis."""

    passed: bool
    issues: list[AnalysisIssue] = field(default_factory=list)


@dataclass
class GenerationResult:
    """Complete result from the agent loop pipeline."""

    rule: str = ""
    rules: list[str] = field(default_factory=list)
    explanation: str = ""
    validation_summary: dict = field(default_factory=dict)
    attempts: int = 0
    detection_intent: Optional[DetectionIntent] = None
    errors: list[str] = field(default_factory=list)


@dataclass
class PcapTestResult:
    """Result of running a rule against a PCAP file."""

    triggered: bool = False
    alert_count: int = 0
    alerts: list[dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class DeployResult:
    """Result of deploying rules to AWS Network Firewall."""

    success: bool = False
    rule_group_arn: str = ""
    update_token: str = ""
    error: Optional[str] = None
