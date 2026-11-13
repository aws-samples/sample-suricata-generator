"""
squid.conf parser.

Parses the directives relevant to converting access policy:

  acl <name> <type> [options...] <value> [<value>...]
  acl <name> req_header|rep_header <Header-Name> [options...] <regex>...
  http_access       allow|deny [!]<aclname> [[!]<aclname> ...]
  http_reply_access allow|deny [!]<aclname> [[!]<aclname> ...]

File-level syntax handled the way Squid reads it (squid.conf preamble):
  * Lines ending in a backslash continue on the next line (joined as-is).
  * `include <file|glob> ...` (quoting and wildcards, nested up to 16 levels).
  * ACL values from files: `"/path/file"` (when quoted values are off, the
    Squid default) and `parameters("/path/file")`.
  * `configuration_includes_quoted_values on|off`: when on, "quoted strings"
    are single values (spaces allowed); files must then use parameters().
  * `if <cond>` / `else` / `endif` with `true`, `false`, or `<int> = <int>`.
    ${process_number} is evaluated as 1 (worker 1); the use is noted.

Semantics captured (per Squid docs):
  * Multiple `acl` lines with the SAME name are ORed together (their values merge).
    For any-of/all-of groups each line is also kept separately (value_lines),
    because same-name all-of lines are ORed, not merged into one big AND.
  * Option flags (-i, +i, -n, -m, --) appear BEFORE the first value.
  * On an access line, multiple ACL names are ANDed; a leading `!` negates.
  * Access lines are evaluated top-to-bottom, first match wins.

Other access-control directives (icp_access, ssl_bump, ...) are not converted;
they are recorded in ParsedConfig.unhandled so the output can report them.
General settings (http_port, auth_param, logformat, ...) are ignored.

Files named in the config (`include` files and ACL value files) are read only
from the config's own folder and its subfolders, through files.FileResolver.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .files import FileResolver, read_config


# Recognised leading option flags on an `acl` line.
_ACL_OPTIONS = {"-i", "+i", "-n", "-m", "--"}

# ACL types whose first argument is a header name, not a value.
_HEADER_NAME_TYPES = {"req_header", "rep_header"}

# ACL types that legitimately take NO value. Squid rejects a value-less `acl`
# line for every other type, so one is treated as malformed. This set is taken
# from the shipped squid.conf.documented for Squid 6.13, where
# `acl aclname connections_encrypted` is the only value-less form.
_VALUELESS_TYPES = {"connections_encrypted"}

# Access-control directives we convert.
_CONVERTED_ACCESS = {"http_access", "http_reply_access"}

# Non-*_access directives that also carry access-control decisions.
_REPORTED_DIRECTIVES = {"ssl_bump", "sslproxy_cert_error", "sslproxy_cert_sign",
                        "sslproxy_cert_adapt"}

# General settings that are not access lines but change what the converted
# policy means, or enforce policy the converter cannot reproduce. They are
# reported with the reason instead of being silently ignored.
_FLAGGED_SETTINGS = {
    "follow_x_forwarded_for": (
        "Squid trusts X-Forwarded-For from some clients, so `src` ACLs may "
        "match the address in that header instead of the connecting client. "
        "Converted `src` rules match the connecting address only; check that "
        "clients reach the firewall directly, not through another proxy"),
    "acl_uses_indirect_client": (
        "with follow_x_forwarded_for, this makes `src` ACLs use the "
        "X-Forwarded-For address; converted `src` rules match the connecting "
        "address only"),
    "url_rewrite_program": (
        "an external URL redirector (for example SquidGuard or ufdbGuard) "
        "enforces policy outside squid.conf; its rules are not in this "
        "config and are not converted"),
    "request_body_max_size": (
        "request size limits have no AWS Network Firewall rule equivalent"),
    "reply_body_max_size": (
        "response size limits have no AWS Network Firewall rule equivalent"),
    "client_ip_max_connections": (
        "per-client connection limits have no AWS Network Firewall rule "
        "equivalent"),
    "auth_param": (
        "proxy authentication is configured; lines that use proxy_auth ACLs "
        "are reported as not convertible, and that traffic falls to the "
        "firewall's default action"),
    "external_acl_type": (
        "an external ACL helper is configured; lines that use `external` "
        "ACLs are reported as not convertible"),
    "delay_pools": "bandwidth limiting has no AWS Network Firewall equivalent",
    "delay_class": "bandwidth limiting has no AWS Network Firewall equivalent",
    "delay_parameters": "bandwidth limiting has no AWS Network Firewall equivalent",
    "client_delay_pools": "bandwidth limiting has no AWS Network Firewall equivalent",
    "client_delay_parameters": "bandwidth limiting has no AWS Network Firewall equivalent",
    "icap_service": (
        "content is sent to an ICAP service (DLP, anti-virus, ...); that "
        "inspection is not converted"),
    "ecap_service": (
        "content is sent to an eCAP service; that inspection is not converted"),
    "adaptation_service_set": (
        "content adaptation (ICAP/eCAP) is configured; not converted"),
    "adaptation_service_chain": (
        "content adaptation (ICAP/eCAP) is configured; not converted"),
    "redirect_program": (
        "the legacy name for url_rewrite_program: an external URL redirector "
        "enforces policy outside squid.conf; its rules are not converted"),
    "http_access2": (
        "a Squid 2.x directive (a very old config); review the policy by hand"),
    "auth_schemes": (
        "proxy authentication schemes are configured; lines that use "
        "proxy_auth ACLs are reported as not convertible"),
    "response_delay_pool": (
        "response bandwidth limiting has no AWS Network Firewall equivalent"),
    "host_verify_strict": (
        "Squid checks that an intercepted request's Host name matches the "
        "destination IP the client connected to, and this setting makes it "
        "block mismatches. Converted domain rules check the name only; "
        "--route53-resolved-domains also requires the destination IP to be "
        "one the Route 53 Resolver returned for the name, which is the "
        "closest equivalent"),
    "client_dst_passthru": (
        "this controls where Squid sends an intercepted request (the client's "
        "original destination IP, or the address Squid resolves for the Host "
        "name). AWS Network Firewall always forwards traffic to the client's "
        "destination IP, so this behaviour is not converted"),
}

_MAX_INCLUDE_DEPTH = 16                       # Squid's hard-coded limit
_PARAMETERS_RE = re.compile(r'^parameters\("(.*)"\)$')
_MACROS = {"${process_number}": "1", "${process_name}": "squid1",
           "${service_name}": "squid"}

_MISSING = "__MISSING_INCLUDE__:"


# ---------------------------------------------------------------------------
# Line dispositions (total-accounting ledger)
#
# Every directive line the parser reads is recorded with exactly one of these,
# so nothing can silently vanish between input and report.
# ---------------------------------------------------------------------------
ACL = "acl"                  # an `acl` definition
ACCESS = "access"            # http_access / http_reply_access (converted)
REPORTED = "reported"        # other access-control directive (ssl_bump, ...)
STRUCTURAL = "structural"    # if/else/endif/include/quoted-values switch
IGNORED = "ignored"          # general setting, not access control
MALFORMED = "malformed"      # directive recognised but unparseable
SKIPPED = "skipped"          # inside an inactive `if` branch

DISPOSITIONS = (ACL, ACCESS, REPORTED, STRUCTURAL, IGNORED, MALFORMED, SKIPPED)


@dataclass
class LedgerEntry:
    line_no: int
    source: Optional[str]
    directive: str
    disposition: str

    @property
    def key(self) -> Tuple[int, Optional[str], str]:
        return (self.line_no, self.source, self.directive)


@dataclass
class Acl:
    name: str
    acl_type: str
    values: List[str] = field(default_factory=list)
    case_insensitive: bool = False   # -i
    no_dns: bool = False             # -n
    list_membership: bool = False    # -m
    header_name: Optional[str] = None  # req_header / rep_header
    value_lines: List[List[str]] = field(default_factory=list)  # per acl line
    # Set when the config defines this name with two different ACL types.
    # Squid rejects such a config outright, so anything using this ACL cannot
    # be converted faithfully; the emitter refuses rather than guessing.
    conflict: Optional[str] = None


@dataclass
class AclRef:
    name: str
    negated: bool = False


@dataclass
class HttpAccess:
    action: str            # "allow" | "deny"
    refs: List[AclRef] = field(default_factory=list)   # ANDed together
    line_no: int = 0
    directive: str = "http_access"
    source: Optional[str] = None   # included file (relative label); None = main file
    # The original line (continuation lines joined, whitespace collapsed),
    # for comment rows and the report.
    text: str = ""


@dataclass
class SslBumpLine:
    """One `ssl_bump <action> [acl...]` line.

    The action decides whether Squid decrypts, which in turn decides whether
    the converted HTTPS rules match what Squid was actually enforcing.
    """
    action: str                 # peek | stare | splice | bump | terminate
    acls: List[str] = field(default_factory=list)
    line_no: int = 0
    source: Optional[str] = None


@dataclass
class ParsedConfig:
    acls: Dict[str, Acl] = field(default_factory=dict)
    http_access: List[HttpAccess] = field(default_factory=list)
    http_reply_access: List[HttpAccess] = field(default_factory=list)
    # (line_no, directive, source) for access-control directives not converted
    unhandled: List[Tuple[int, str, Optional[str]]] = field(default_factory=list)
    # File-level problems that affect what was read (missing includes, ...)
    problems: List[str] = field(default_factory=list)
    # Informational (conditionals evaluated, ...)
    notes: List[str] = field(default_factory=list)
    # Total-accounting ledger: one entry per directive line read, in order.
    ledger: List[LedgerEntry] = field(default_factory=list)
    # ssl_bump lines, in order. Still reported as "not converted to a rule",
    # but their decrypt/splice decisions drive HTTPS coverage and the TLS
    # inspection scope.
    ssl_bump: List[SslBumpLine] = field(default_factory=list)
    # (line_no, directive, source, reason) for general settings that change
    # what the converted policy means (follow_x_forwarded_for, ...).
    flagged: List[Tuple[int, str, Optional[str], str]] = field(default_factory=list)


def where(line_no: int, source: Optional[str]) -> str:
    """Human-readable location: 'line 12' or 'conf.d/acl.conf line 12'."""
    return ("%s line %d" % (source, line_no)) if source else ("line %d" % line_no)


# ---------------------------------------------------------------------------
# Tokenizing
# ---------------------------------------------------------------------------
class _Tok(str):
    """A token; `quoted` is True for a "quoted string" in quoted-values mode."""
    quoted = False


def _quoted_tok(value: str) -> _Tok:
    t = _Tok(value)
    t.quoted = True
    return t


def _tokenize(line: str, quoted_mode: bool) -> List[_Tok]:
    """Split a logical line into tokens and drop a trailing # comment.

    quoted_mode off (Squid default): whitespace split; a "quoted" token is kept
    with its quotes (an ACL file include). quoted_mode on: "..." with \\ escapes
    is one token with the quotes removed, and # inside quotes is not a comment.
    parameters("...") is always one token.
    """
    if not quoted_mode:
        line = line.split("#", 1)[0]
        return [_Tok(t) for t in line.split()]
    toks: List[_Tok] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c.isspace():
            i += 1
            continue
        if c == "#":
            break
        if c == '"':
            j, buf = i + 1, []
            while j < n and line[j] != '"':
                if line[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(line[j])
                j += 1
            toks.append(_quoted_tok("".join(buf)))
            i = j + 1
            continue
        if line.startswith("parameters(", i):
            j = line.find(")", i)
            j = n if j < 0 else j + 1
            toks.append(_Tok(line[i:j]))
            i = j
            continue
        j = i
        while j < n and not line[j].isspace():
            j += 1
        toks.append(_Tok(line[i:j]))
        i = j
    return toks


def _logical_lines(text: str):
    """Yield (first_line_no, logical_line); a trailing backslash joins the next
    physical line (Squid appends it directly, without adding a space)."""
    buf, start = None, 0
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if buf is None:
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            buf, start = stripped, idx
        else:
            buf += line
        if buf.endswith("\\"):
            buf = buf[:-1]
            continue
        yield start, buf
        buf = None
    if buf is not None:
        yield start, buf


# ---------------------------------------------------------------------------
# File resolution (see files.py: only the config's folder is ever read)
# ---------------------------------------------------------------------------
def _read_include_file(path: str, resolver: FileResolver) -> List[str]:
    """Read a Squid ACL value file: one value per line, `#` comments allowed.

    Returns the values, or a single sentinel value carrying the reason when
    the file is not read (not found in, or outside, the config's folder), so
    the emitter can report the line instead of silently dropping the values.
    """
    chosen, reason = resolver.resolve_file(path)
    if chosen is None:
        return [_MISSING + reason]
    try:
        with open(chosen, "r", encoding="utf-8-sig", errors="replace") as fh:
            out = []
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line)
            return out
    except OSError as e:
        return [_MISSING + "file '%s' could not be read (%s)" % (path, e)]


def _expand_values(values: List[_Tok], resolver: FileResolver) -> List[str]:
    """Expand ACL value-file references into their contents.

    Squid syntax:  acl name dstdomain "/etc/squid/allowed_domains.txt"
                   acl name dstdomain parameters("/etc/squid/allowed_domains.txt")
    A "quoted string" in quoted-values mode is a literal value instead.
    """
    expanded: List[str] = []
    for v in values:
        m = _PARAMETERS_RE.match(v)
        if m:
            expanded.extend(_read_include_file(m.group(1), resolver))
        elif getattr(v, "quoted", False):
            expanded.append(str(v))
        elif len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            expanded.extend(_read_include_file(v[1:-1], resolver))
        else:
            expanded.append(str(v))
    return expanded


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def _eval_condition(tokens: List[str]):
    """Evaluate an `if` condition. Returns (value, used_macro) or (None, _)."""
    used = any(m in t for t in tokens for m in _MACROS)
    vals = []
    for t in tokens:
        for m, v in _MACROS.items():
            t = t.replace(m, v)
        vals.append(t)
    if vals == ["true"]:
        return True, used
    if vals == ["false"]:
        return False, used
    if len(vals) == 3 and vals[1] == "=":
        try:
            return int(vals[0]) == int(vals[2]), used
        except ValueError:
            return None, used
    return None, used


class _Parser:
    def __init__(self, base_dir):
        self.cfg = ParsedConfig()
        self.base_dir = base_dir
        self.resolver = FileResolver(base_dir)
        self.quoted_mode = False
        self.stack: List[str] = []           # real paths of files being read

    def _label(self, path: str) -> str:
        """Location label for an included file, always with `/` separators so
        rule msg text and reports are the same on every OS (a Windows `\\`
        would otherwise be rewritten to `_` in the msg)."""
        if self.base_dir:
            try:
                rel = os.path.relpath(os.path.realpath(path),
                                      os.path.realpath(self.base_dir))
            except ValueError:            # different drive on Windows
                rel = ".."
            if not rel.startswith(".."):
                return rel.replace(os.sep, "/")
        return os.path.basename(path)

    def run_text(self, text: str, source: Optional[str]) -> None:
        cfg = self.cfg
        conds: List[dict] = []                # {"value", "else", "line"}

        def active() -> bool:
            for c in conds:
                v = c["value"]
                if v is None or (v if not c["else"] else not v) is False:
                    return False
            return True

        def record(line_no: int, directive: str, disposition: str) -> None:
            cfg.ledger.append(LedgerEntry(line_no=line_no, source=source,
                                          directive=directive,
                                          disposition=disposition))

        for ln, line in _logical_lines(text):
            loc = where(ln, source)
            tokens = _tokenize(line, self.quoted_mode)
            if not tokens:
                # A line that is only a comment or only quotes: still a
                # directive line in the file, so account for it.
                record(ln, "", IGNORED)
                continue
            directive = tokens[0].lower()

            if directive == "if":
                record(ln, directive, STRUCTURAL)
                value, used = _eval_condition([str(t) for t in tokens[1:]])
                cond = " ".join(tokens[1:])
                conds.append({"value": value, "else": False, "line": ln})
                if value is None:
                    cfg.problems.append(
                        "Squid %s: `if %s` could not be evaluated; directives in "
                        "both branches were skipped" % (loc, cond))
                elif used:
                    cfg.notes.append(
                        "Squid %s: `if %s` evaluated with ${process_number}=1 "
                        "(worker 1); other workers may load different directives"
                        % (loc, cond))
                continue
            if directive == "else":
                record(ln, directive, STRUCTURAL)
                if not conds or conds[-1]["else"]:
                    cfg.problems.append("Squid %s: `else` without matching `if`" % loc)
                else:
                    conds[-1]["else"] = True
                continue
            if directive == "endif":
                record(ln, directive, STRUCTURAL)
                if conds:
                    conds.pop()
                else:
                    cfg.problems.append("Squid %s: `endif` without matching `if`" % loc)
                continue
            if not active():
                record(ln, directive, SKIPPED)
                continue

            if directive == "configuration_includes_quoted_values" and len(tokens) > 1:
                record(ln, directive, STRUCTURAL)
                self.quoted_mode = tokens[1].lower() == "on"
            elif directive == "include":
                record(ln, directive, STRUCTURAL)
                self._include(tokens[1:], loc)
            elif directive == "acl":
                ok = self._acl(tokens)
                record(ln, directive, ACL if ok else MALFORMED)
                if not ok:
                    cfg.problems.append(
                        "Squid %s: malformed `acl` line (needs at least a name, "
                        "a type and a value); skipped" % loc)
            elif directive in _CONVERTED_ACCESS:
                ha = _parse_access(tokens, ln, directive)
                if ha is not None:
                    ha.source = source
                    ha.text = " ".join(line.split())
                    target = cfg.http_access if directive == "http_access" else cfg.http_reply_access
                    target.append(ha)
                    record(ln, directive, ACCESS)
                else:
                    record(ln, directive, MALFORMED)
                    cfg.problems.append(
                        "Squid %s: malformed `%s` line (needs allow|deny and at "
                        "least one ACL name); skipped" % (loc, directive))
            elif directive.endswith("_access") or directive in _REPORTED_DIRECTIVES:
                record(ln, directive, REPORTED)
                cfg.unhandled.append((ln, directive, source))
                if directive == "ssl_bump" and len(tokens) > 1:
                    cfg.ssl_bump.append(SslBumpLine(
                        action=str(tokens[1]).lower(),
                        acls=[str(t) for t in tokens[2:]],
                        line_no=ln, source=source))
            elif directive in _FLAGGED_SETTINGS:
                record(ln, directive, REPORTED)
                cfg.flagged.append((ln, directive, source,
                                    _FLAGGED_SETTINGS[directive]))
            else:
                # Everything else is a general setting and is ignored.
                record(ln, directive, IGNORED)

        for c in conds:
            cfg.problems.append("Squid %s: `if` without `endif`"
                                % where(c["line"], source))

    def _include(self, args: List[_Tok], loc: str) -> None:
        for raw in args:
            pattern = str(raw)
            if len(pattern) >= 2 and pattern[0] == '"' and pattern[-1] == '"':
                pattern = pattern[1:-1]
            files, reason = self.resolver.resolve_glob(pattern)
            if not files:
                self.cfg.problems.append(
                    "Squid %s: `include %s` was not read: include %s (keep "
                    "the Squid server's folder names, such as conf.d/); ACLs "
                    "and rules defined there are missing"
                    % (loc, pattern, reason))
                continue
            for path in files:
                real = os.path.realpath(path)
                label = self._label(path)
                if real in self.stack:
                    self.cfg.problems.append("Squid %s: `include %s` includes a "
                                             "file that is already being read "
                                             "(cycle); skipped" % (loc, label))
                    continue
                if len(self.stack) >= _MAX_INCLUDE_DEPTH:
                    self.cfg.problems.append("Squid %s: include nesting deeper than "
                                             "%d levels; `%s` skipped"
                                             % (loc, _MAX_INCLUDE_DEPTH, label))
                    continue
                try:
                    text = read_config(path)
                except (OSError, ValueError) as e:
                    self.cfg.problems.append("Squid %s: cannot read included "
                                             "file %s (%s)" % (loc, label, e))
                    continue
                self.stack.append(real)
                self.run_text(text, self._label(path))
                self.stack.pop()

    def _acl(self, tokens: List[_Tok]) -> bool:
        """Define or extend an ACL. Returns False when the line is malformed."""
        # acl <name> <type> [options] <values...>
        # acl <name> req_header|rep_header <Header-Name> [options] <regex...>
        if len(tokens) < 3:
            return False
        name, acl_type, rest = str(tokens[1]), str(tokens[2]), tokens[3:]
        header_name = None
        if acl_type in _HEADER_NAME_TYPES and rest:
            header_name, rest = str(rest[0]), rest[1:]
        flags, raw_values = _split_option_flags(rest)
        values = _expand_values(raw_values, self.resolver)

        if not raw_values and acl_type not in _VALUELESS_TYPES:
            # Squid requires at least one value for every other ACL type.
            return False
        if raw_values and not values:
            # Syntactically fine, but an included value file was empty.
            self.cfg.problems.append(
                "Squid acl `%s` [%s]: the referenced value file is empty, so "
                "the ACL has no values and cannot match anything."
                % (name, acl_type))

        existing = self.cfg.acls.get(name)
        if existing is None:
            self.cfg.acls[name] = Acl(
                name=name, acl_type=acl_type, values=list(values),
                case_insensitive=("-i" in flags), no_dns=("-n" in flags),
                list_membership=("-m" in flags), header_name=header_name,
                value_lines=[list(values)],
            )
        elif existing.acl_type != acl_type:
            # Squid FATALs on this, so there is no faithful conversion. Record
            # the conflict and do NOT merge the values: merging would put (say)
            # a domain into an address variable and emit an invalid rule.
            if existing.conflict is None:
                existing.conflict = (
                    "defined with two different ACL types (`%s` then `%s`); "
                    "Squid rejects this config" % (existing.acl_type, acl_type))
                self.cfg.problems.append(
                    "Squid acl `%s` is %s. Nothing using this ACL is converted."
                    % (name, existing.conflict))
        else:
            # Same-name ACL lines are ORed: merge values (and OR the flags).
            existing.values.extend(values)
            existing.value_lines.append(list(values))
            existing.case_insensitive = existing.case_insensitive or ("-i" in flags)
            existing.no_dns = existing.no_dns or ("-n" in flags)
            existing.list_membership = existing.list_membership or ("-m" in flags)
            if existing.header_name is None:
                existing.header_name = header_name
        return True


def _split_option_flags(tokens: List[_Tok]):
    """Peel leading option flags off the token list.

    Returns (flags_set, remaining_value_tokens). `--` stops option parsing and
    is itself consumed. `+i` is treated like the case toggle -i for our purposes
    (we only track a single case flag for the whole ACL line here). Long
    options such as ssl::server_name's `--client-requested` are kept as flags.
    """
    flags = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if getattr(tok, "quoted", False):
            break
        if tok == "--":
            i += 1  # consume and stop
            break
        # -m can appear as -m or -m=<delims>; treat the prefix as the flag.
        if tok in _ACL_OPTIONS or tok.startswith("-m="):
            flags.add("-m" if tok.startswith("-m=") else str(tok))
            i += 1
            continue
        if tok.startswith("--") and len(tok) > 2:
            flags.add(str(tok))
            i += 1
            continue
        break
    return flags, tokens[i:]


def _parse_access(tokens: List[_Tok], line_no: int,
                  directive: str) -> Optional[HttpAccess]:
    # <directive> allow|deny [!]acl [[!]acl ...]
    if len(tokens) < 3:
        return None
    action = tokens[1].lower()
    if action not in ("allow", "deny"):
        return None
    refs: List[AclRef] = []
    for tok in tokens[2:]:
        tok = str(tok)
        negated = tok.startswith("!")
        name = tok[1:] if negated else tok
        refs.append(AclRef(name=name, negated=negated))
    return HttpAccess(action=action, refs=refs, line_no=line_no, directive=directive)


def parse(text: str, base_dir: Optional[str] = None) -> ParsedConfig:
    """Parse squid.conf text into a ParsedConfig.

    base_dir: folder of the squid.conf. Value files and `include` files are
    read only from this folder and its subfolders (see files.FileResolver);
    with base_dir=None no file is read.
    """
    p = _Parser(base_dir)
    p.run_text(text, None)
    return p.cfg
