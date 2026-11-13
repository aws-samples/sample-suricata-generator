"""
Conversion report: sections and plain-text rendering.

`report_sections()` returns the report as (key, title, lines) sections in
display order, with the items that mean the converted policy differs from
the source or is incomplete first. `render_report()` joins them into the
plain text that the report window's "Full text" tab shows, Save Report
writes, and the command line writes with --report.
"""

import datetime
import html as _html
from typing import List, Optional, Tuple

from src.core.version import get_squid_converter_version

Section = Tuple[str, str, List[str]]

# Section key -> severity class for the HTML report's colored left border,
# reusing the rule analyzer's palette (.critical/.warning/.info/.success).
# "read first" items (divergences, read problems, converter error) are
# critical; not-convertible lines are warnings; everything else is neutral
# info.
_HTML_SEVERITY = {
    "divergences": "critical",
    "problems": "critical",
    "accounting_failure": "critical",
    "not_convertible": "warning",
}


def _options_line(result) -> str:
    opts = result.options
    return ("Options: Squid deny -> %s; alert on pass %s; Route 53 resolved "
            "domains %s. Output is for AWS Network Firewall's explicit proxy "
            "deployment." % (opts.deny_action,
                             "on" if opts.alert_on_pass else "off",
                             "on" if opts.route53_resolved_domains else "off"))


def summary_lines(result) -> List[str]:
    """Counts shown at the top of the report and by the command line."""
    return [
        "Rules: %d   Variables: %d   Divergences: %d   Not convertible: %d   "
        "Notes: %d   Config problems: %d"
        % (len(result.rules), len(result.variables), len(result.divergences),
           len(result.not_convertible), len(result.notes),
           len(result.problems)),
        "Accounting: %s" % ("OK, every directive line accounted for"
                            if result.accounting_ok else "FAILED"),
    ]


def report_sections(result) -> List[Section]:
    """The report as (key, title, lines) sections, in display order.

    Keys: divergences, problems, accounting_failure, prerequisites,
    not_convertible, notes, sslbump, sslbump_acls, unhandled, variables,
    accounting. Empty sections are left out, except prerequisites and
    accounting, which are always present.
    """
    sections: List[Section] = []

    def add(key: str, title: str, lines: List[str], always: bool = False):
        if lines or always:
            sections.append((key, title, list(lines)))

    add("divergences", "POLICY DIVERGENCES from the source Squid",
        ["DIVERGENCE: " + d for d in result.divergences])
    add("problems", "CONFIG READ PROBLEMS (the output may be incomplete)",
        ["PROBLEM: " + p for p in result.problems])
    if not result.accounting_ok:
        add("accounting_failure", "CONVERTER ERROR: accounting failed",
            ["Some input lines were not accounted for. This is a converter "
             "defect; the rules must not be used. Details are in the "
             "Accounting section."])
    prereq_lines: List[str] = []
    for item in result.prerequisites:
        prereq_lines.append("* " + item.title)
        prereq_lines.extend("    " + ln for ln in item.lines)
    add("prerequisites", "FIREWALL PREREQUISITES", prereq_lines, always=True)
    add("not_convertible", "NOT CONVERTIBLE (reported, no rule)",
        ["NOT CONVERTIBLE: " + u for u in result.not_convertible])
    add("notes", "NOTES (approximate conversions, defaults)", result.notes)
    posture = result.posture
    add("sslbump", "HTTPS / SslBump",
        posture.summary_lines() if posture is not None else [])
    add("sslbump_acls", "SslBump ACL types: where each is handled on AWS",
        result.sslbump_classification)
    add("unhandled", "DIRECTIVES REPORTED (not converted)", result.unhandled)
    var_lines = ["$%s = %s   (from acl %s)"
                 % (name, ", ".join(info["values"]), info["acl"])
                 for name, info in result.variables.items()]
    add("variables", "VARIABLES", var_lines)
    add("accounting", "ACCOUNTING (every input directive line is bucketed)",
        result.accounting_text, always=True)
    return sections


def render_report(result, extra_sections: Optional[List[Tuple[str, List[str]]]] = None) -> str:
    """Plain-text report for a ConversionResult.

    extra_sections: (title, lines) pairs appended after the converter's own
    sections, used by the Generator for what only it knows (SID scheme and
    range, validation results).
    """
    out: List[str] = []
    out.append("=" * 70)
    out.append("Squid Configuration Import report - Squid Converter v%s"
               % get_squid_converter_version())
    out.append(_options_line(result))
    out.extend(summary_lines(result))
    out.append("=" * 70)
    out.append("")
    for _key, title, lines in report_sections(result):
        out.append("---- %s ----" % title)
        out.extend(lines if lines else ["(none)"])
        out.append("")
    for title, lines in extra_sections or []:
        out.append("---- %s ----" % title)
        out.extend(lines if lines else ["(none)"])
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# HTML rendering (self-contained; styled like the rule analyzer's HTML report)
# ---------------------------------------------------------------------------
_HTML_CSS = """
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .title { color: #2c3e50; font-size: 24px; font-weight: bold; margin-bottom: 10px; }
        .meta { color: #6c757d; font-size: 14px; }
        .disclaimer { background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }
        .summary { background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .critical { color: #dc3545; font-weight: bold; }
        .warning { color: #fd7e14; font-weight: bold; }
        .info { color: #17a2b8; font-weight: bold; }
        .success { color: #28a745; font-weight: bold; }
        .section { margin: 15px 0; padding: 10px 15px; border-left: 3px solid #dee2e6; }
        .section-critical { border-left-color: #dc3545; }
        .section-warning { border-left-color: #fd7e14; }
        .section-info { border-left-color: #17a2b8; }
        .section h2 { font-size: 18px; margin: 0 0 8px 0; }
        .lines { font-family: monospace; background-color: #f8f9fa; padding: 10px;
                 border-radius: 3px; font-size: 12px; white-space: pre-wrap;
                 word-break: break-word; margin: 0; }
        .none { color: #6c757d; font-style: italic; }
"""


def _esc(text: str) -> str:
    return _html.escape(str(text), quote=False)


def _html_section(title: str, lines: List[str], severity: str) -> str:
    cls = "section-%s" % severity if severity in ("critical", "warning") else "section-info"
    head_cls = severity if severity in ("critical", "warning", "info") else "info"
    body = _esc("\n".join(lines)) if lines else None
    parts = ['<div class="section %s">' % cls]
    parts.append('<h2 class="%s">%s</h2>' % (head_cls, _esc(title)))
    if body:
        parts.append('<pre class="lines">%s</pre>' % body)
    else:
        parts.append('<p class="none">(none)</p>')
    parts.append('</div>')
    return "\n".join(parts)


def render_html(result, extra_sections: Optional[List[Tuple[str, List[str]]]] = None) -> str:
    """Self-contained HTML conversion report for a ConversionResult.

    Same content as render_report (the converter's own sections, then the
    Generator's extra_sections), styled like the rule analyzer's HTML report.
    extra_sections: (title, lines) pairs appended after the converter's
    sections (SID scheme/range and validation).
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    version = get_squid_converter_version()

    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append("<title>Squid Configuration Import Report</title>")
    parts.append("<style>%s</style>" % _HTML_CSS)
    parts.append("</head>")
    parts.append("<body>")

    parts.append('<div class="header">')
    parts.append('<div class="title">Squid Configuration Import Report</div>')
    parts.append('<div class="meta">')
    parts.append("<strong>Generated:</strong> %s<br>" % _esc(timestamp))
    parts.append("<strong>Squid Converter Version:</strong> %s<br>" % _esc(version))
    parts.append("%s" % _esc(_options_line(result)))
    parts.append("</div>")
    parts.append("</div>")

    parts.append('<div class="disclaimer">')
    parts.append("<strong>DISCLAIMER:</strong><br>")
    parts.append("This converted policy is a starting point. Review the policy "
                 "divergences, firewall prerequisites and notes below, and test "
                 "the rules in a non-production firewall before enforcing them.")
    parts.append("</div>")

    parts.append('<div class="summary">')
    parts.append("<strong>Conversion Summary:</strong><br>")
    parts.append("<br>".join(_esc(ln) for ln in summary_lines(result)))
    parts.append("</div>")

    for key, title, lines in report_sections(result):
        parts.append(_html_section(title, lines, _HTML_SEVERITY.get(key, "info")))
    for title, lines in extra_sections or []:
        parts.append(_html_section(title, lines, "info"))

    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"
