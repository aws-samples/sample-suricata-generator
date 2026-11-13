"""
Import_Core for the Squid configuration import (UI-free).

Shared by the GUI importer (squid_importer.py) and the command line
(squid_cli.py), so both produce the same rules, SIDs, msg traces, comment
rows, variables and report. It runs the converter (src.importers.squid) with a
Rule_Check backed by the Generator's shared RuleValidator, assigns SIDs,
builds SuricataRule objects and comment rows, converts the variables to the
Generator's format, and runs the same group checks File > Save applies.

No tkinter, no network, no AWS: the import is completely offline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date
from typing import Callable, Dict, List, Optional, Tuple

from src.analysis.rule_validation_messages import render_terse
from src.analysis.rule_validator import RuleValidator, load_keywords_data
from src.core.constants import SuricataConstants
from src.core.sid_generator import suggest_next_sid
from src.core.suricata_rule import SuricataRule
from src.core.version import get_main_version, get_squid_converter_version
from src.importers.squid import (ConversionResult, ConvertOptions, RuleCheck,
                                 convert, parse_config, read_config,
                                 render_html, render_report)
from src.managers import rule_file_io

# The tag a new file gets (suricata_generator.add_default_tags). An import is
# a new file, so the command line writes the same tag the GUI would save.
DEFAULT_TAGS = {"ManagedBy": "SuricataGenerator"}

# Comment row above the generated proxy DNS rule, always present.
DNS_RULE_COMMENT = (
    "# Squid import: lets the Network Firewall proxy resolve destination "
    "names through the Route 53 Resolver (169.254.169.253). Without it every "
    "proxied request fails. Keep this rule first.")

COMMENT_MAX = 400


@dataclass
class ImportOptions:
    """Options of one import (the dialog and the command line offer the same).

    convert: the converter options (deny action, alert on pass, Route 53).
    add_comments: one comment row per Squid access line.
    stable_sids: keep the converter's content-derived SIDs instead of the
        Generator's date-based ones.
    """
    convert: ConvertOptions = field(default_factory=ConvertOptions)
    add_comments: bool = True
    stable_sids: bool = False


@dataclass
class ImportPlan:
    """Everything needed to put an import in the editor or write it to disk.

    rows: comment rows and rules in final order (SuricataRule objects).
    variables: Generator format {"$NAME": {"definition", "description"}}.
    group_errors: [(row number, code, message)] from the shared validator's
        group check, as File > Save shows them.
    hard_save_error: the File > Save hard block (duplicate SID, undefined
        variable), or None.
    sid_scheme: "date" or "stable"; sid_range: (lowest, highest) or (0, 0).
    sid_notes: SID changes made to keep SIDs unique.
    parse_errors: rules SuricataRule.from_string() could not parse.
    report_text: the full report (plain text), what Save Report and --report
        write for a .txt path.
    report_html: the same report as a self-contained HTML document, what Save
        Report and --report write for a .html/.htm path.
    """
    rows: List[SuricataRule]
    variables: Dict[str, Dict]
    result: ConversionResult
    group_errors: List[Tuple[int, str, str]]
    hard_save_error: Optional[str]
    sid_scheme: str
    sid_range: Tuple[int, int]
    sid_notes: List[str]
    parse_errors: List[str]
    report_text: str
    report_html: str = ""
    extra_sections: List[Tuple[str, List[str]]] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return sum(1 for r in self.rows if not r.is_comment and not r.is_blank)

    @property
    def can_import(self) -> bool:
        """Import Rules is allowed unless accounting or the save check failed."""
        return self.result.accounting_ok and self.hard_save_error is None

    @property
    def deployable(self) -> bool:
        """No validator error, no save-check failure, accounting complete."""
        return (self.can_import and not self.group_errors
                and not self.parse_errors)


# ---------------------------------------------------------------------------
# Rule_Check
# ---------------------------------------------------------------------------
def build_rule_check(variables: Optional[Dict] = None) -> RuleCheck:
    """A Rule_Check backed by the shared RuleValidator: the same rule-local
    checks paste and the AI assistant use (errors_for_rule). Variables are not
    needed for rule-local checks; undefined variables are a group check."""
    validator = RuleValidator(load_keywords_data(), variables or {})

    def rule_check(line: str) -> List[str]:
        return [render_terse(f) for f in validator.errors_for_rule(line)]
    return rule_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def safe_comment(text: str) -> str:
    """One safe comment line: line breaks and tabs become spaces, `#` first,
    at most COMMENT_MAX characters."""
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = " ".join(text.split())
    if not text.startswith("#"):
        text = "# " + text
    if len(text) > COMMENT_MAX:
        text = text[:COMMENT_MAX - 3] + "..."
    return text


def _comment_row(text: str) -> SuricataRule:
    row = SuricataRule()
    row.is_comment = True
    row.comment_text = safe_comment(text)
    return row


def _blank_row() -> SuricataRule:
    row = SuricataRule()
    row.is_blank = True
    return row


def _header_rows(config_path: str, options: ImportOptions) -> List[SuricataRule]:
    """The metadata header comment block placed at the very top of every
    Squid import (CLI and GUI), always present regardless of add_comments.

    Mirrors the other importers' headers (see palo_alto_importer and
    stateful_rule_importer): a boxed `# Imported from ...` block with the
    source, versions, deployment assumption, the options that change the
    output, and the note that the proxy DNS rule must stay first.
    """
    convert = options.convert
    source_file = os.path.basename(config_path) or config_path
    now = date.today().strftime("%Y-%m-%d")
    opts = "deny->%s | alert on pass: %s | Route 53 resolved domains: %s" % (
        convert.deny_action,
        "on" if convert.alert_on_pass else "off",
        "on" if convert.route53_resolved_domains else "off",
    )
    bar = "# " + "=" * 48
    lines = [
        bar,
        "# Imported from Squid Proxy Configuration",
        "# Source File: %s" % source_file,
        "# Suricata Generator v%s (Squid Converter v%s)" % (
            get_main_version(), get_squid_converter_version()),
        "# Deployment: AWS Network Firewall explicit proxy",
        "# Converted: %s" % now,
        "# Options: %s" % opts,
        "# Note: the first rule passes the proxy's own DNS lookups and must "
        "stay first.",
        bar,
    ]
    rows = [_comment_row(line) for line in lines]
    rows.append(_blank_row())
    return rows


def _location(line_no: int, source: Optional[str]) -> str:
    return ("Squid %s line %d" % (source, line_no)) if source else ("Squid line %d" % line_no)


def access_comment(line) -> str:
    """Comment text for one AccessLineOutcome."""
    loc = _location(line.line_no, line.source)
    if line.outcome == "emitted":
        return "# %s: %s" % (loc, line.text)
    mark = "NOT CONVERTED" if line.outcome == "not_convertible" else "NO RULE NEEDED"
    reason = (" (%s)" % line.short_reason) if line.short_reason else ""
    return "# %s %s%s: %s" % (loc, mark, reason, line.text)


def convert_variables(variables: Dict[str, Dict]) -> Dict[str, Dict]:
    """Converter variables -> Generator variables.

    {"APPSUBNET": {"acl": "AppSubnet", "acl_type": "src",
                   "values": ["10.0.10.0/24"]}} ->
    {"$APPSUBNET": {"definition": "10.0.10.0/24",
                    "description": "Squid acl AppSubnet (src)"}}

    The Generator auto-detects a variable's type (IP set vs port set) from how
    it is used in the rules, so only the description reflects the ACL type.
    """
    out: Dict[str, Dict] = {}
    for name, info in variables.items():
        values = list(info.get("values", []))
        definition = values[0] if len(values) == 1 else "[" + ",".join(values) + "]"
        acl_type = info.get("acl_type", "src")
        out["$" + name] = {"definition": definition,
                           "description": "Squid acl %s (%s)"
                           % (info.get("acl", name), acl_type)}
    return out


def _assign_sids(result: ConversionResult, stable: bool, today: Optional[date]):
    """(sids in rule order, notes)."""
    used = set()
    sids: List[int] = []
    notes: List[str] = []
    for rule in result.rules:
        if stable:
            sid = rule.stable_sid
            if sid in used:
                new = sid + 1
                while new in used and new <= SuricataConstants.SID_MAX:
                    new += 1
                notes.append("SID %d changed to %d to stay unique" % (sid, new))
                sid = new
        else:
            sid = suggest_next_sid(used, today)
        used.add(sid)
        sids.append(sid)
    return sids, notes


def _rule_row(text: str, sid: int, parse_errors: List[str]) -> SuricataRule:
    rule = SuricataRule.from_string(text)
    if rule is None:
        parse_errors.append(text)
        return _comment_row("# [PARSE ERROR] " + text)
    rule.sid = sid
    return rule


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------
def run_import(config_path: str, options: Optional[ImportOptions] = None,
               today: Optional[date] = None,
               progress: Optional[Callable[[str], None]] = None) -> ImportPlan:
    """Convert one squid.conf into an ImportPlan.

    Raises OSError (cannot read) or ValueError (not a text file) for the
    selected config itself; every other problem is in the plan's report.
    `today` fixes the date for date-based SIDs (tests, reproducible runs).
    """
    options = options or ImportOptions()

    def step(text: str) -> None:
        if progress is not None:
            progress(text)

    step("Reading the configuration")
    text = read_config(config_path)
    config_dir = os.path.dirname(os.path.abspath(config_path))
    cfg = parse_config(text, config_dir)

    step("Converting")
    result = convert(cfg, options.convert, build_rule_check({}))

    step("Assigning SIDs")
    sids, sid_notes = _assign_sids(result, options.stable_sids, today)

    step("Building rows")
    parse_errors: List[str] = []
    rule_rows = [_rule_row(r.text, sid, parse_errors)
                 for r, sid in zip(result.rules, sids)]
    rows: List[SuricataRule] = _header_rows(config_path, options)
    placed = set()
    for i, rule in enumerate(result.rules):
        if rule.origin == "generated":
            rows.append(_comment_row(DNS_RULE_COMMENT))
            rows.append(rule_rows[i])
            placed.add(i)
    for line in result.access_lines:
        if options.add_comments:
            rows.append(_comment_row(access_comment(line)))
        for i in line.rule_indexes:
            if i not in placed:
                rows.append(rule_rows[i])
                placed.add(i)
    # Defensive: any rule not tied to a line keeps its place at the end.
    for i, row in enumerate(rule_rows):
        if i not in placed:
            rows.append(row)

    step("Checking the rules")
    variables = convert_variables(result.variables)
    validator = RuleValidator(load_keywords_data(), variables)
    findings = validator.errors_for_rule_group(rows, variables)
    group_errors = [(f.line_num, f.code, render_terse(f)) for f in findings]
    group_errors.sort(key=lambda item: item[0])
    hard_save_error = rule_file_io.find_hard_save_error(rows, variables)

    real = [s for s in sids]
    sid_range = (min(real), max(real)) if real else (0, 0)
    scheme = "stable" if options.stable_sids else "date"

    sid_lines = [
        "SID scheme: %s" % ("stable (content-based: the same config gives the "
                            "same SIDs on every run)" if options.stable_sids
                            else "date-based (YYMMDDNNNN, in rule order)"),
        "SID range: %d - %d (%d rules)" % (sid_range[0], sid_range[1], len(sids)),
    ] + sid_notes
    validation_lines = [
        "Every rule was checked by the Generator's shared rule validator "
        "before it was emitted; a Squid line with a rejected rule is listed "
        "under NOT CONVERTIBLE.",
    ]
    if group_errors:
        validation_lines.append("Rule set check: %d error(s):" % len(group_errors))
        validation_lines.extend("  row %d: %s" % (n, msg) for n, _code, msg in group_errors)
    else:
        validation_lines.append("Rule set check: no errors.")
    if hard_save_error:
        validation_lines.append("SAVE CHECK FAILED: %s. The rules cannot be "
                                "imported or saved." % hard_save_error)
    else:
        validation_lines.append("Save check (duplicate SIDs, undefined "
                                "variables): OK.")
    if parse_errors:
        validation_lines.append("%d rule(s) could not be parsed and became "
                                "[PARSE ERROR] comments (a converter defect):"
                                % len(parse_errors))
        validation_lines.extend("  " + t for t in parse_errors)
    extra = [("SIDs", sid_lines), ("VALIDATION", validation_lines)]

    step("Writing the report")
    report_text = render_report(result, extra_sections=extra)
    report_html = render_html(result, extra_sections=extra)
    return ImportPlan(rows=rows, variables=variables, result=result,
                      group_errors=group_errors, hard_save_error=hard_save_error,
                      sid_scheme=scheme, sid_range=sid_range, sid_notes=sid_notes,
                      parse_errors=parse_errors, report_text=report_text,
                      report_html=report_html, extra_sections=extra)


def write_files(plan: ImportPlan, suricata_path: str) -> None:
    """Write OUTPUT.suricata (and OUTPUT.var) exactly as File > Save would
    for the imported, untitled file: change tracking off, no header, the
    new-file default tag. Raises ValueError on a hard save error (nothing
    written) and Exception when the file can't be written."""
    rule_file_io.save_rules_to_file(suricata_path, plan.rows, plan.variables,
                                    tags=dict(DEFAULT_TAGS), has_header=False,
                                    tracking_enabled=False, pending_history=None)
