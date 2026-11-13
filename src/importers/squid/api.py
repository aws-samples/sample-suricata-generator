"""
Converter_API: the only names Generator code may use from the Squid converter.

Typical use (this is what the Generator's import core does):

    from src.importers.squid import (ConvertOptions, read_config,
                                     parse_config, convert, render_report)

    text = read_config(path)                          # BOM, CRLF, binary check
    cfg = parse_config(text, os.path.dirname(path))   # reads only that folder
    result = convert(cfg, ConvertOptions(), rule_check)
    report = render_report(result)

A Rule_Check is any callable taking one complete rule line and returning a
list of error messages (an empty list means the rule is acceptable). The
converter calls it for every rule it builds, in final form (alert-on-pass and
msg applied, placeholder SID); one error makes the rule's whole Squid line
not convertible. There is no built-in checker: callers pass one (the
Generator passes its shared rule validator; pure-conversion tests pass
`lambda line: []`).

Everything here is offline: no network calls, no AWS credentials, no
third-party packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from src.core.version import get_squid_converter_version

from . import accounting as _accounting
from . import prerequisites as _prerequisites
from . import report as _report
from .emitter import DENY_ACTIONS, EMITTED, NOT_CONVERTIBLE, NOTE_ONLY, emit
from .files import read_config as _read_config
from .parser import ParsedConfig, parse
from .prerequisites import Prerequisite

# A Rule_Check takes one complete rule line and returns error messages
# (empty list = acceptable). Supplied by the caller.
RuleCheck = Callable[[str], List[str]]


@dataclass
class ConvertOptions:
    """Conversion options (the import dialog and the command line offer the
    same ones).

    deny_action: what a Squid `deny` becomes, "reject" (default) or "drop".
        To monitor first, export with the Generator's test mode instead.
    alert_on_pass: add `alert;` to every `pass` rule (default on).
    route53_resolved_domains: use AWS Network Firewall's
        aws_route_53_resolved_domain keyword (default off).
    """
    deny_action: str = "reject"
    alert_on_pass: bool = True
    route53_resolved_domains: bool = False


@dataclass
class ConvertedRule:
    """One converted rule.

    text: the complete rule line, with a content-derived SID.
    stable_sid: that content-derived SID (also inside `text`), in
        1000000-1999999 and unique within one conversion.
    origin: "squid" (from a Squid line) or "generated" (the proxy DNS rule).
    line_no / source: the Squid line it came from; source is the include
        file label, None for the main config (both None for "generated").
    action: pass | reject | drop.
    protocol: http | tls | ftp | dns.
    """
    text: str
    stable_sid: int
    origin: str
    line_no: Optional[int]
    source: Optional[str]
    action: str
    protocol: str


@dataclass
class AccessLineOutcome:
    """What happened to one http_access / http_reply_access line.

    outcome: "emitted", "not_convertible" or "note_only".
    short_reason: one short phrase for comment rows ("" when emitted).
    rule_indexes: indexes into ConversionResult.rules.
    text: the original line, joined and on one line.
    """
    line_no: int
    source: Optional[str]
    directive: str
    text: str
    outcome: str
    short_reason: str
    rule_indexes: List[int] = field(default_factory=list)


@dataclass
class ConversionResult:
    """Everything one conversion produced.

    rules: converted rules in Squid first-match order; the proxy DNS rule is
        always first.
    access_lines: every access line, http_access lines first, then
        http_reply_access, each in config order.
    variables: NAME (no `$`) -> {"acl": <Squid acl name>,
        "acl_type": "src" | "port", "values": [cidr | port]}. "src" ACLs
        become IP set variables, "port" ACLs become port set variables.
    notes, not_convertible, unhandled, problems, divergences: report items.
    prerequisites: firewall settings the rules depend on.
    posture: SslBump posture (opaque; shown through the report).
    sslbump_classification: where each SslBump ACL type is handled.
    accounting_ok / accounting_text: the total-accounting check.
    converter_version: from src/core/version.py.
    options: the ConvertOptions used.
    """
    rules: List[ConvertedRule]
    access_lines: List[AccessLineOutcome]
    variables: Dict[str, Dict]
    notes: List[str]
    not_convertible: List[str]
    unhandled: List[str]
    problems: List[str]
    divergences: List[str]
    prerequisites: List[Prerequisite]
    posture: object
    sslbump_classification: List[str]
    accounting_ok: bool
    accounting_text: List[str]
    converter_version: str
    options: ConvertOptions = field(default_factory=ConvertOptions)


def read_config(path: str) -> str:
    """Read a squid.conf as text (UTF-8 with or without BOM, CRLF or LF).

    Raises ValueError for binary input and OSError when it can't be read.
    """
    return _read_config(path)


def parse_config(text: str, config_dir: Optional[str]) -> ParsedConfig:
    """Parse squid.conf text. `include` files and ACL value files are read
    only from `config_dir` (the config's folder) and its subfolders."""
    return parse(text, base_dir=config_dir)


def convert(cfg: ParsedConfig, options: ConvertOptions,
            rule_check: RuleCheck) -> ConversionResult:
    """Convert a parsed config. `rule_check` is required (see module doc)."""
    if options.deny_action not in DENY_ACTIONS:
        raise ValueError("deny_action must be one of %s"
                         % ", ".join(DENY_ACTIONS))
    er = emit(cfg, rule_check, deny_action=options.deny_action,
              alert_on_pass=options.alert_on_pass,
              resolved_domains=options.route53_resolved_domains)
    acct = _accounting.build(cfg, er)

    rules = [ConvertedRule(text=text, stable_sid=sid, origin=spec.origin,
                           line_no=spec.line_no, source=spec.source,
                           action=spec.action, protocol=spec.protocol)
             for text, sid, spec in zip(er.rules, er.sids, er.specs)]

    access_lines: List[AccessLineOutcome] = []
    for ha in list(cfg.http_access) + list(cfg.http_reply_access):
        key = (ha.line_no, ha.source, ha.directive)
        outcome = er.line_outcomes.get(key, NOT_CONVERTIBLE)
        reason, indexes = er.line_info.get(key, ("", []))
        access_lines.append(AccessLineOutcome(
            line_no=ha.line_no, source=ha.source, directive=ha.directive,
            text=ha.text or "%s %s" % (ha.directive, ha.action),
            outcome=outcome,
            short_reason="" if outcome == EMITTED else reason,
            rule_indexes=list(indexes)))

    return ConversionResult(
        rules=rules,
        access_lines=access_lines,
        variables={name: {"acl": info["acl"],
                          "acl_type": info.get("acl_type", "src"),
                          "values": list(info["values"])}
                   for name, info in er.variables.items()},
        notes=list(er.notes),
        not_convertible=list(er.not_convertible),
        unhandled=list(er.unhandled),
        problems=list(er.problems) + list(er.generated_problems),
        divergences=list(er.divergences),
        prerequisites=_prerequisites.build(cfg, er,
                                           options.route53_resolved_domains),
        posture=er.posture,
        sslbump_classification=list(er.sslbump_classification),
        accounting_ok=acct.is_complete(),
        accounting_text=acct.explain().splitlines(),
        converter_version=get_squid_converter_version(),
        options=options,
    )


def report_sections(result: ConversionResult) -> List[Tuple[str, str, List[str]]]:
    """The report as (key, title, lines) sections in display order, for a
    tabbed view. Keys: divergences, problems, accounting_failure,
    prerequisites, not_convertible, notes, sslbump, sslbump_acls, unhandled,
    variables, accounting."""
    return _report.report_sections(result)


def render_report(result: ConversionResult,
                  extra_sections: Optional[List[Tuple[str, List[str]]]] = None) -> str:
    """Plain-text report. `extra_sections` are (title, lines) pairs appended
    at the end (the Generator adds SID scheme/range and validation)."""
    return _report.render_report(result, extra_sections)


def render_html(result: ConversionResult,
                extra_sections: Optional[List[Tuple[str, List[str]]]] = None) -> str:
    """Self-contained HTML report (same content as render_report, styled like
    the rule analyzer's HTML report). `extra_sections` are the same (title,
    lines) pairs render_report takes."""
    return _report.render_html(result, extra_sections)


__all__ = [
    "RuleCheck", "DENY_ACTIONS", "ConvertOptions", "ConvertedRule",
    "AccessLineOutcome", "Prerequisite", "ConversionResult", "read_config",
    "parse_config", "convert", "render_report", "render_html",
    "report_sections",
    "EMITTED", "NOT_CONVERTIBLE", "NOTE_ONLY",
]
