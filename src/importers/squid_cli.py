"""
Squid configuration import, command line.

Run from the Suricata Rule Generator's root folder:

    python -m src.importers.squid_cli squid.conf -o egress.suricata [options]

Writes the same egress.suricata (and egress.var) that File > Import Squid
Configuration followed by File > Save would, using the same Import_Core and
the same file writer. Completely offline: no network, no AWS credentials.

Exit codes:
    0    converted and acceptable
    1    converted but not deployable: a rule validator error, a save-check
         failure (duplicate SID, undefined variable; nothing written), or the
         accounting check failed
    2    the config can't be read, the output can't be written, or bad
         arguments
    130  interrupted
Lines that could not be converted are reported and do not change the exit
code; neither do validator warnings.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from src.core.version import get_squid_converter_version


class _ArgParser(argparse.ArgumentParser):
    def error(self, message):            # bad arguments -> exit 2
        self.print_usage(sys.stderr)
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


def build_arg_parser() -> argparse.ArgumentParser:
    p = _ArgParser(
        prog="python -m src.importers.squid_cli",
        description=("Convert a Squid proxy configuration into AWS Network "
                     "Firewall Suricata rules (.suricata + .var), the same "
                     "files the Generator's Squid import produces. The rules "
                     "are for Network Firewall's explicit proxy."))
    p.add_argument("--version", action="version",
                   version="Squid Converter v%s" % get_squid_converter_version())
    p.add_argument("config", metavar="CONFIG",
                   help="squid.conf. Its include files and ACL list files must "
                        "be in the same folder (subfolders such as conf.d/ "
                        "allowed); nothing outside that folder is read.")
    p.add_argument("-o", "--output", required=True, metavar="OUTPUT.suricata",
                   help="Rule file to write; OUTPUT.var is written next to it.")
    p.add_argument("--deny", choices=["reject", "drop"], default="reject",
                   help="What a Squid deny becomes (default reject). To monitor "
                        "first, export with the Generator's test mode.")
    p.add_argument("--no-alert-on-pass", action="store_true",
                   help="Don't add the alert keyword to pass rules.")
    p.add_argument("--no-comments", action="store_true",
                   help="Don't add the Squid lines as comment rows (the comment "
                        "above the proxy DNS rule is always added).")
    p.add_argument("--stable-sids", action="store_true",
                   help="Keep content-based SIDs (the same on every run) "
                        "instead of date-based SIDs.")
    p.add_argument("--route53-resolved-domains", action="store_true",
                   help="Use aws_route_53_resolved_domain (needs Route 53 "
                        "resolved IP validation on the firewall policy and "
                        "169.254.169.253/32 in its bypass ranges).")
    p.add_argument("--report", metavar="REPORT",
                   help="Also write the conversion report to this file. A "
                        ".html or .htm path writes an HTML report; any other "
                        "extension writes plain text.")
    return p


def _summary(plan) -> List[str]:
    from src.importers.squid.report import summary_lines
    r = plan.result
    lines = ["Squid Converter v%s" % r.converter_version]
    lines.extend(summary_lines(r))
    lines.append("SIDs: %s, %d - %d" % (plan.sid_scheme, plan.sid_range[0],
                                         plan.sid_range[1]))
    lines.append("Firewall prerequisites: " + "; ".join(p.title for p in r.prerequisites))
    if r.divergences:
        lines.append("WARNING: %d policy divergence(s) from the source Squid; "
                     "see the report." % len(r.divergences))
    if r.problems:
        lines.append("WARNING: %d config read problem(s); see the report."
                     % len(r.problems))
    return lines


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    from src.importers.squid import ConvertOptions
    from src.importers.squid_import_core import ImportOptions, run_import, write_files

    options = ImportOptions(
        convert=ConvertOptions(deny_action=args.deny,
                               alert_on_pass=not args.no_alert_on_pass,
                               route53_resolved_domains=args.route53_resolved_domains),
        add_comments=not args.no_comments,
        stable_sids=args.stable_sids)
    try:
        plan = run_import(args.config, options)
    except (OSError, ValueError) as e:
        print("error: cannot read config: %s" % e, file=sys.stderr)
        return 2

    for line in _summary(plan):
        print(line, file=sys.stderr)

    if args.report:
        report = plan.report_html if args.report.lower().endswith((".html", ".htm")) \
            else plan.report_text
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as e:
            print("error: cannot write report: %s" % e, file=sys.stderr)
            return 2

    if plan.hard_save_error:
        print("error: %s; no files written" % plan.hard_save_error, file=sys.stderr)
        return 1
    try:
        write_files(plan, args.output)
    except ValueError as e:
        print("error: %s; no files written" % e, file=sys.stderr)
        return 1
    except Exception as e:                       # noqa: BLE001 - file system
        print("error: cannot write output: %s" % e, file=sys.stderr)
        return 2
    print("wrote %d rule(s) to %s" % (plan.rule_count, args.output), file=sys.stderr)

    code = 0
    if plan.group_errors or plan.parse_errors:
        print("error: the rule validator reported %d error(s); see the report"
              % (len(plan.group_errors) + len(plan.parse_errors)), file=sys.stderr)
        code = 1
    if not plan.result.accounting_ok:
        print("error: accounting failed (a converter defect):", file=sys.stderr)
        for line in plan.result.accounting_text:
            print("  " + line, file=sys.stderr)
        code = 1
    return code


def _entry() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(_entry())
