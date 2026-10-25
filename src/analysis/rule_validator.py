"""
Shared Rule Validator (UI-free)

Single detection core for rule-keyword validation, shared by the Advanced
Editor, the main editor (per-rule save and paste), disk save, and
export/deploy. This module performs DETECTION only: it emits Finding objects
carrying a stable ``code`` and ``params``. Display wording is owned by the
consumers via ``src/analysis/rule_validation_messages.py``.

This module must not import wx or tkinter. It imports only the standard
library, ``src.core.aws_rule_constraints``, and ``src.core.category_protocols``.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
from dataclasses import dataclass, field

from src.core.aws_rule_constraints import is_reject_allowed
from src.core.category_protocols import is_category_protocol_allowed
from src.core.rule_options import (split_options_lossless, has_quoted_semicolon,
                                   quoted_regions, in_quoted_region)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding severity
# ---------------------------------------------------------------------------
ERROR = "error"
WARNING = "warning"
INFO = "info"

# ---------------------------------------------------------------------------
# Finding scope (requirements R12)
# ---------------------------------------------------------------------------
RULE_LOCAL = "rule_local"   # decidable from one rule's text + static keyword data
GROUP = "group"             # needs the variable/reference table or other rules


# ---------------------------------------------------------------------------
# Rule length constants (requirements R13.9)
# ---------------------------------------------------------------------------
RULE_MAX_BYTES = 8191               # AWS fails at >= 8192
RULE_WARN_BYTES = 7691              # editor-save "approaching the limit" warning
GID_ALLOWANCE_BYTES = 16            # "; gid:1234567890" injected by AWS
IP_REFERENCE_EXPANSION_BYTES = 19   # per @ header field ("any" + iprep option)


# ---------------------------------------------------------------------------
# CODE_SCOPE: every catalog code mapped to RULE_LOCAL or GROUP
# (design.md "Catalog code attributes"). A code missing from CODE_SCOPE is a
# programming error and must fail a unit test, not default silently.
# ---------------------------------------------------------------------------
CODE_SCOPE = {
    # rule-local
    "AWS_UNSUPPORTED_KEYWORD": RULE_LOCAL,
    "SYNTAX_MODE_DIRECT_AS_STICKY": RULE_LOCAL,
    "SYNTAX_MODE_STICKY_AS_DIRECT": RULE_LOCAL,
    "SSL_VERSION_NEGATION": RULE_LOCAL,
    "SSL_VERSION_DUPLICATE": RULE_LOCAL,
    "XBITS_TRACK_TX": RULE_LOCAL,
    "FORBIDDEN_MODIFIER": RULE_LOCAL,
    "HTTP_HOST_UPPERCASE": RULE_LOCAL,
    "JA3_HASH_LENGTH": RULE_LOCAL,
    "MD5_BUFFER_NOT_HEX": RULE_LOCAL,
    "MD5_BUFFER_NOCASE": RULE_LOCAL,
    "PACKET_APP_LAYER_MIXING": RULE_LOCAL,
    "PCRE_COMPANION": RULE_LOCAL,
    "IP_PROTO_PROTOCOL": RULE_LOCAL,
    "FLOW_DIRECTION_RESPONSE_ON_TO_SERVER": RULE_LOCAL,
    "FLOW_DIRECTION_REQUEST_ON_TO_CLIENT": RULE_LOCAL,
    "MIXED_DIRECTION_BUFFERS": RULE_LOCAL,
    "GEOIP_INVALID_COUNTRY_CODE": RULE_LOCAL,
    "GEOIP_MISSING_COUNTRY_CODE": RULE_LOCAL,
    "INVALID_ENUM_VALUE": RULE_LOCAL,
    "AWS_URL_CATEGORY_PROTOCOL": RULE_LOCAL,
    "AWS_DOMAIN_CATEGORY_PROTOCOL": RULE_LOCAL,
    "CATEGORY_DUPLICATE_VALUE": RULE_LOCAL,
    "CATEGORY_EMPTY": RULE_LOCAL,
    "CATEGORY_KEYWORD_CONFLICT": RULE_LOCAL,
    "R53_DOMAIN_UNQUOTED": RULE_LOCAL,
    "R53_DOMAIN_MULTIPLE": RULE_LOCAL,
    "R53_DOMAIN_ASTERISK": RULE_LOCAL,
    "R53_DOMAIN_EMPTY": RULE_LOCAL,
    "R53_DOMAIN_INVALID": RULE_LOCAL,
    "REJECT_UNSUPPORTED_PROTOCOL": RULE_LOCAL,
    "IP_REFERENCE_IN_GROUP": RULE_LOCAL,
    "GID_NOT_ALLOWED": RULE_LOCAL,
    "APP_LAYER_PROTOCOL_REDUNDANT": RULE_LOCAL,
    "APP_LAYER_PROTOCOL_CONFLICT": RULE_LOCAL,
    # Special case: needs variable values, so errors_for_rule excludes it (R12.4)
    "RULE_TOO_LONG": RULE_LOCAL,
    # Non-blocking (WARNING in validate_line)
    "UNKNOWN_KEYWORD": RULE_LOCAL,
    # group
    "FLOWBITS_ISSET_NOT_SET": GROUP,
    "UNDEFINED_VARIABLE": GROUP,
    "DUPLICATE_SID": GROUP,
}


@dataclass
class Finding:
    """One validation finding. Carries a code + params; never display text."""
    start: int            # char offset within the line (-1 or None if not positional)
    end: int
    code: str             # stable machine-readable code (see Message Catalog)
    severity: str         # ERROR / WARNING / INFO
    keyword: str = ""     # the keyword this finding is about, when applicable
    params: dict = field(default_factory=dict)  # values needed to render a message
    scope: str = RULE_LOCAL   # looked up from CODE_SCOPE[code]; never set ad hoc
    line_num: int = 0     # 1-based line in the file; set by errors_for_rule_group


@dataclass
class RuleValidationContext:
    """Context built during rule parsing for cross-keyword validation checks."""
    protocol: str = ""
    flow_direction: str | None = None
    keywords_found: list = field(default_factory=list)
    active_sticky_buffer: str | None = None
    content_matches: list = field(default_factory=list)


# Category keywords whose values AWS matches exact-case (R13.7)
CATEGORY_KEYWORDS = frozenset({"aws_url_category", "aws_domain_category"})

# Rule-header protocols that do NOT set the rule's application protocol.
# Every other header protocol (http, tls, dns, ssh, smb, ...) sets it, and AWS
# Network Firewall then rejects any later app-layer-protocol keyword, negated
# or not (CreateRuleGroup DryRun, Oct 25 2026).
NON_APP_HEADER_PROTOCOLS = frozenset({"tcp", "udp", "ip", "icmp"})


def keyword_sets_app_layer_protocol(keyword_def):
    """True if a known keyword sets the rule's application protocol.

    Data-driven from content_keywords.json: an explicit
    ``sets_app_layer_protocol`` flag wins; otherwise keywords with
    ``keyword_level: app_layer`` set it (ja3.hash / ja3s.hash / ja4.hash carry
    ``sets_app_layer_protocol: false`` -- AWS DryRun, Oct 25 2026).
    """
    if not keyword_def:
        return False
    flag = keyword_def.get('sets_app_layer_protocol')
    if flag is not None:
        return bool(flag)
    return keyword_def.get('keyword_level') == 'app_layer'


# aws_route_53_resolved_domain item grammar (R13.8.2). These patterns match
# AWS Network Firewall's domain validation for this keyword: an FQDN or a
# leading-dot wildcard. Each item must match in full -> use fullmatch().
# Length bounds are in the lookaheads: 4-253, wildcard (incl. dot) 3-253.
R53_FQDN_RE = re.compile(
    r"(?=^.{4,253}$)((((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])\.)+([a-zA-Z0-9]{2,63}$))")
R53_WILDCARD_RE = re.compile(
    r"(?=^.{3,253}$)(\.((((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])\.)*)([a-zA-Z0-9]{2,63}$))")


def is_valid_r53_domain(item):
    """True when ``item`` (already trimmed) is a valid FQDN or leading-dot
    wildcard per AWS Network Firewall's domain validation. An empty item is invalid."""
    return bool(R53_FQDN_RE.fullmatch(item) or R53_WILDCARD_RE.fullmatch(item))


# Common country code mistakes with suggestions
COUNTRY_CODE_SUGGESTIONS = {
    "UK": "GB (United Kingdom)",
    "EN": "GB (England is part of United Kingdom)",
    "ENG": "GB (use ISO 3166-1 alpha-2 code)",
    "SC": "GB (Scotland is part of United Kingdom)",
    "WAL": "GB (Wales is part of United Kingdom)",
}


# ---------------------------------------------------------------------------
# Keyword data loading
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_KEYWORDS_PATH = os.path.join(_PROJECT_ROOT, 'data', 'content_keywords.json')

# Cache keyed by absolute path -> parsed dict (or None for a failed load)
_KEYWORDS_CACHE = {}


def _split_top_level(text):
    """Split ``text`` on commas that are not inside nested ``[...]``."""
    items, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
        elif ch == ',' and depth == 0:
            items.append(text[start:i])
            start = i + 1
    items.append(text[start:])
    return items


def _field_variable_names(value, names):
    """Collect $NAME / @NAME items of one header field (or group item)."""
    item = (value or "").strip()
    if item.startswith('!'):
        item = item[1:].strip()
    if item.startswith('[') and item.endswith(']'):
        for part in _split_top_level(item[1:-1]):
            _field_variable_names(part, names)
        return
    if item.startswith('$') or item.startswith('@'):
        names.add(item)


def header_variable_names(src_net, src_port, dst_net, dst_port):
    """Every $NAME / @NAME in the four header fields, including negated
    (!$X, !@REF) and grouped ([$A,10.0.0.0/8], ![$A], [80,$PORTS]) forms.
    Nested brackets are handled recursively."""
    names = set()
    for value in (src_net, src_port, dst_net, dst_port):
        _field_variable_names(value, names)
    return names


_HEADER_VAR_TOKEN_RE = re.compile(r'\$[A-Za-z0-9_]+')


def _variable_definition(variables, name):
    """Non-empty definition of ``name`` in ``variables`` (string or
    ``{"definition": ...}``), else None."""
    if not variables or name not in variables:
        return None
    data = variables[name]
    if isinstance(data, dict):
        data = data.get("definition", "")
    if not isinstance(data, str) or not data.strip():
        return None
    return data


def measure_rule_bytes(rule, variables):
    """AWS-style rule length (requirements R13.9) of a SuricataRule: UTF-8
    bytes of the re-serialized rule after expanding HEADER variables only,
    + IP_REFERENCE_EXPANSION_BYTES per @REF/!@REF header field,
    + GID_ALLOWANCE_BYTES. Undefined variables stay unexpanded. Works on a
    copy; never mutates ``rule``."""
    measured = copy.copy(rule)
    reference_bytes = 0
    for attr in ("src_net", "src_port", "dst_net", "dst_port"):
        value = getattr(measured, attr, "") or ""
        whole = value.strip()
        if whole.startswith('!'):
            whole = whole[1:].strip()
        if whole.startswith('@'):
            # Whole-field IP set reference: AWS rewrites it to "any" and adds
            # an internal iprep option (R13.9).
            setattr(measured, attr, "any")
            reference_bytes += IP_REFERENCE_EXPANSION_BYTES
            continue
        names = header_variable_names(value, "", "", "")
        if not names:
            continue

        def _expand(match, _names=names):
            token = match.group(0)
            if token not in _names:
                return token
            definition = _variable_definition(variables, token)
            return definition if definition is not None else token

        # Token-wise: the regex captures the whole name, so $HOME never
        # rewrites part of $HOME_NET.
        setattr(measured, attr, _HEADER_VAR_TOKEN_RE.sub(_expand, value))
    return (len(measured.to_string().encode("utf-8"))
            + GID_ALLOWANCE_BYTES + reference_bytes)


def load_keywords_data(path=None):
    """Load and cache data/content_keywords.json.

    Args:
        path: Optional path to the JSON file. A relative path is resolved
            against the project root. Defaults to data/content_keywords.json,
            the same file AdvancedEditorWx.load_content_keywords() reads.

    Returns:
        The parsed dict, or None if the file is missing or invalid (logged
        at WARNING).
    """
    if path is None:
        resolved = _DEFAULT_KEYWORDS_PATH
    elif os.path.isabs(path):
        resolved = path
    else:
        resolved = os.path.join(_PROJECT_ROOT, path)
    resolved = os.path.abspath(resolved)

    if resolved in _KEYWORDS_CACHE:
        return _KEYWORDS_CACHE[resolved]

    data = None
    try:
        if not os.path.exists(resolved):
            logger.warning("Content keywords file not found: %s", resolved)
        else:
            with open(resolved, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data = loaded
            else:
                logger.warning("Content keywords file is not a JSON object: %s", resolved)
    except (ValueError, OSError) as exc:
        # json.JSONDecodeError is a subclass of ValueError
        logger.warning("Could not load content keywords file %s: %s", resolved, exc)
        data = None

    _KEYWORDS_CACHE[resolved] = data
    return data


def _derive_valid_country_codes(keywords_data):
    """Build the valid country code frozenset from the geoip definition,
    exactly as AdvancedEditorWx.load_content_keywords() does."""
    if keywords_data:
        geoip_def = next((kw for kw in keywords_data['keywords'] if kw['name'] == 'geoip'), None)
        return frozenset(
            code.upper() for code in geoip_def.get('country_codes', [])
        ) if geoip_def else frozenset()
    return frozenset()


# ---------------------------------------------------------------------------
# Finding construction helpers
# ---------------------------------------------------------------------------
# Codes that are WARNINGs inside validate_line; every other code is an ERROR.
_WARNING_CODES = frozenset({"UNKNOWN_KEYWORD", "UNDEFINED_VARIABLE"})

# Content modifiers that may follow a sticky buffer's content match
# (same tuple the Advanced Editor uses in validate_line).
_CONTENT_MODIFIERS = ('nocase', 'endswith', 'startswith', 'bsize',
                      'depth', 'offset', 'distance', 'within',
                      'fast_pattern', 'dotprefix')

# md5 sticky buffers checked by MD5_BUFFER_NOT_HEX / MD5_BUFFER_NOCASE (R13.6).
# ssh.hassh / ssh.hassh.server are not in content_keywords.json (R13.6.3).
MD5_BUFFER_KEYWORDS = ("ja3.hash", "ja3s.hash")

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def code_scope(code):
    """Return CODE_SCOPE[code]; raises KeyError on an unknown code."""
    return CODE_SCOPE[code]


def make_finding(code, start=-1, end=-1, keyword="", params=None, line_num=0):
    """Build a Finding with severity and scope derived from ``code``.

    Raises:
        KeyError: if ``code`` is not in CODE_SCOPE.
    """
    scope = code_scope(code)
    severity = WARNING if code in _WARNING_CODES else ERROR
    return Finding(
        start=start,
        end=end,
        code=code,
        severity=severity,
        keyword=keyword,
        params=dict(params) if params else {},
        scope=scope,
        line_num=line_num,
    )


def _at(finding, start, end):
    """Set a finding's position and return it."""
    finding.start = start
    finding.end = end
    return finding


def parse_rule_tokens(line_stripped):
    """Parse a rule into tokens, treating bracketed groups, parenthesized
    option blocks, and quoted strings as single tokens.

    Verbatim port of AdvancedEditorWx._parse_rule_tokens so header positions
    match the Advanced Editor exactly.
    """
    tokens = []
    current_token = ""
    bracket_depth = 0
    paren_depth = 0
    in_quotes = False

    for char in line_stripped:
        if char == '"' and bracket_depth == 0 and paren_depth == 0:
            in_quotes = not in_quotes
            current_token += char
        elif in_quotes:
            current_token += char
        elif char == '[':
            bracket_depth += 1
            current_token += char
        elif char == ']':
            bracket_depth -= 1
            current_token += char
        elif char == '(':
            paren_depth += 1
            current_token += char
        elif char == ')':
            paren_depth -= 1
            current_token += char
        elif char == ' ' and bracket_depth == 0 and paren_depth == 0:
            if current_token:
                tokens.append(current_token)
                current_token = ""
        else:
            current_token += char

    # Add final token even if brackets/parens are unclosed
    if current_token:
        tokens.append(current_token)

    return tokens


def _token_positions(line, line_stripped):
    """Locate each header token in the raw line (same arithmetic as the
    Advanced Editor's validate_line)."""
    tokens = parse_rule_tokens(line_stripped)
    current_pos = 0
    token_positions = []
    for token in tokens:
        start = line.find(token, current_pos)
        if start != -1:
            end = start + len(token)
            token_positions.append((start, end, token))
            current_pos = end
    return token_positions


# ---------------------------------------------------------------------------
# flowbits collector (R13.10, group check FLOWBITS_ISSET_NOT_SET)
# ---------------------------------------------------------------------------
FLOWBITS_SET_OPS = frozenset({"set", "toggle"})
FLOWBITS_CHECK_OPS = frozenset({"isset", "isnotset"})


def _option_statements(line):
    """Yield ``(start, end)`` spans (offsets in ``line``) of each ``;``-separated
    option statement in the rule's options block, ignoring ``;`` inside
    double quotes (backslash escapes honoured)."""
    paren_start = line.find('(')
    paren_end = line.rfind(')')
    if paren_start == -1 or paren_end <= paren_start:
        return
    stmt_start = paren_start + 1
    in_quotes = False
    i = stmt_start
    while i < paren_end:
        ch = line[i]
        if ch == '\\' and in_quotes:
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == ';' and not in_quotes:
            yield stmt_start, i
            stmt_start = i + 1
        i += 1
    if stmt_start < paren_end:
        yield stmt_start, paren_end


def flowbits_operations(line):
    """Return the flowbits operations of one rule line.

    Returns a list of ``(op, name, start, end)`` with ``op`` lowercased and
    ``start``/``end`` the span of ``name`` in ``line``. A ``a|b`` name list
    yields one entry per name. Comment and blank lines yield nothing.
    Operations without a name (``noalert``) are skipped.
    """
    ops = []
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return ops
    for s_start, s_end in _option_statements(line):
        statement = line[s_start:s_end]
        colon = statement.find(':')
        if colon == -1 or statement[:colon].strip().lower() != 'flowbits':
            continue
        value_start = s_start + colon + 1
        value = line[value_start:s_end]
        parts = value.split(',')
        if len(parts) < 2:
            continue
        op = parts[0].strip().lower()
        names_offset = value_start + len(parts[0]) + 1
        names_text = parts[1]
        pos = names_offset
        for raw in names_text.split('|'):
            name = raw.strip()
            if name:
                n_start = pos + (len(raw) - len(raw.lstrip()))
                ops.append((op, name, n_start, n_start + len(name)))
            pos += len(raw) + 1
    return ops


def find_unset_flowbits(numbered_lines):
    """Document-wide flowbits pass shared by errors_for_rule_group and the
    Advanced Editor (R13.10).

    Args:
        numbered_lines: iterable of ``(line_num, line_text)`` for the rows to
            consider. Comment and blank rows are ignored even if passed.

    Returns:
        list of FLOWBITS_ISSET_NOT_SET Findings, one per checked name with no
        ``set``/``toggle`` anywhere in ``numbered_lines``, in line order.
        Each has ``line_num`` of the checking rule, the name's span in that
        line, and params ``{"name", "op"}``. Names are compared exactly.
    """
    set_names = set()
    checks = []
    for line_num, line in numbered_lines:
        for op, name, start, end in flowbits_operations(line):
            if op in FLOWBITS_SET_OPS:
                set_names.add(name)
            elif op in FLOWBITS_CHECK_OPS:
                checks.append((line_num, op, name, start, end))
    return [
        make_finding("FLOWBITS_ISSET_NOT_SET", start, end, keyword="flowbits",
                     params={"name": name, "op": op}, line_num=line_num)
        for line_num, op, name, start, end in checks
        if name not in set_names
    ]


class RuleValidator:
    """UI-free rule validator: detection only (codes + params, no display text)."""

    HANDLED_OPTIONS = frozenset({"gid"})   # phase 2 (R13.3)

    def __init__(self, keywords_data, variables, valid_country_codes=None):
        """
        Args:
            keywords_data: parsed content_keywords.json dict, or None (then the
                keyword-level checks are skipped exactly as the Advanced Editor
                skips them today; category/R53/header checks and
                undefined-variable warnings still run).
            variables: any container supporting ``name in variables`` (the
                app's dict, or a set of names).
            valid_country_codes: derived from the geoip keyword definition in
                keywords_data when None.
        """
        self.keywords_data = keywords_data
        self.variables = variables
        if valid_country_codes is None:
            valid_country_codes = _derive_valid_country_codes(keywords_data)
        self.valid_country_codes = valid_country_codes

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def validate_line(self, line, line_num=0):
        """Keyword-level validation of one rule line.

        Runs the Advanced Editor's checks (5)-(7) in the same order (see
        design.md "Current State"), then the header checks
        REJECT_UNSUPPORTED_PROTOCOL and IP_REFERENCE_IN_GROUP. Positions are computed on the raw,
        unstripped ``line``. The generic syntax checks (1)-(4) are NOT run
        here; they stay in the Advanced Editor.

        Returns:
            list of Finding (ERROR and WARNING), in order.
        """
        findings = []

        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            return findings

        token_positions = _token_positions(line, line_stripped)

        # (5) + (6): only when the line has an options block
        if '(' in line and ')' in line:
            paren_start = line.find('(')
            paren_end = line.rfind(')')
            content_section = line[paren_start + 1:paren_end]

            # (5) per-statement keyword loop + cross-keyword checks
            if self.keywords_data:
                self._validate_keywords(line, content_section, paren_start,
                                        token_positions, findings)
            else:
                # GID_NOT_ALLOWED needs no keyword data (R13.3)
                self._check_gid_without_keyword_data(line, content_section,
                                                     paren_start, findings)

            # (6) inline category protocol checks + R53 checks
            self._check_category_protocols(content_section, paren_start,
                                           token_positions, findings)
            self._check_route53_domain(content_section, paren_start, findings)

        # (7) undefined-variable scan (any non-comment line)
        self._check_undefined_variables(line, findings)

        # Header check: reject on a non-allowlisted protocol (after step 7 so
        # the existing finding order is untouched)
        if len(token_positions) > 1:
            a_start, a_end, action = token_positions[0]
            protocol = token_positions[1][2]
            if not is_reject_allowed(action, protocol):
                findings.append(make_finding(
                    "REJECT_UNSUPPORTED_PROTOCOL", a_start, a_end,
                    keyword="", params={"protocol": protocol},
                    line_num=line_num,
                ))

        # Header check: IP set reference inside a network group (R13.2),
        # alongside (after) the reject check
        findings.extend(self._check_ip_reference_in_group(token_positions))

        if line_num:
            for f in findings:
                f.line_num = line_num
        return findings

    def errors_for_rule(self, line):
        """ERROR findings with scope RULE_LOCAL for one rule line.

        Never returns a GROUP code and never RULE_TOO_LONG. Used by the
        per-rule editor save and paste.
        """
        return [
            f for f in self.validate_line(line)
            if f.severity == ERROR and f.scope == RULE_LOCAL and f.code != "RULE_TOO_LONG"
        ]

    def errors_for_rule_group(self, rules, variables, references=None):
        """ERROR findings for a whole rule list (disk save, export/deploy).

        ``rules`` is a list of SuricataRule objects in file order. Only ACTIVE
        rules are considered: comment rows (``is_comment``) and blank rows
        (``is_blank``) are skipped both as offenders and as context (R10.5).
        Every returned Finding has ``line_num`` set to the 1-based index of its
        rule in ``rules``. Findings are returned in rule order, and within a
        rule in the order ``errors_for_rule`` returns them.

        ``variables`` (the app's variables dict) and ``references`` are part of
        the group API contract (R12.3). ``variables`` feeds the per-rule
        ``RULE_TOO_LONG`` measurement (``measure_rule_bytes``).
        """
        findings = []
        active = []  # (line_num, rule) of active rules, for the group pass
        for idx, rule in enumerate(rules):
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            line_num = idx + 1
            active.append((line_num, rule))
            for f in self.errors_for_rule(rule.to_string()):
                f.line_num = line_num
                findings.append(f)
            # RULE_TOO_LONG (R12.4, R13.9): re-checked with the current
            # variable definitions, after the rule's rule-local findings.
            length = measure_rule_bytes(rule, variables)
            if length > RULE_MAX_BYTES:
                findings.append(make_finding(
                    "RULE_TOO_LONG", params={
                        "length": length, "max": RULE_MAX_BYTES},
                    line_num=line_num))

        # Group pass (R13.10, R12.5): flowbits checked but never set by any
        # active rule, listed against the checking rule's line. A stable sort
        # keeps rule order and puts group findings after the rule's own.
        findings.extend(find_unset_flowbits(
            (line_num, rule.to_string()) for line_num, rule in active))
        findings.sort(key=lambda f: f.line_num)
        return findings

    # ------------------------------------------------------------------
    # Step (5): per-statement keyword loop + cross-keyword checks
    # ------------------------------------------------------------------
    def _find_keyword_def(self, name):
        return next((kw for kw in self.keywords_data.get('keywords', [])
                     if kw.get('name', '').lower() == name.lower()), None)

    def _validate_keywords(self, line, content_section, paren_start,
                           token_positions, findings):
        known_keywords = [kw.get('name', '') for kw in self.keywords_data.get('keywords', [])]
        known_lower = [k.lower() for k in known_keywords]
        # Quote-aware: a ';' inside a quoted value does not split. Equals
        # content_section.split(';') when no quoted value contains a ';'.
        statements = split_options_lossless(content_section)
        current_pos = 0

        rule_protocol = token_positions[1][2].lower() if len(token_positions) > 1 else ""
        ctx = RuleValidationContext(protocol=rule_protocol)

        for stmt_idx, statement in enumerate(statements):
            statement = statement.strip()
            if not statement:
                current_pos += 1
                continue

            if ':' in statement:
                keyword = statement.split(':', 1)[0].strip()
                value_part = statement.split(':', 1)[1].strip() if len(statement.split(':', 1)) > 1 else ''
            else:
                keyword = statement.strip()
                value_part = ''

            if keyword and keyword.lower() in self.HANDLED_OPTIONS:
                # Validator-handled options (R13.3): reported by their own
                # check, never as an unknown keyword.
                f = self._check_gid(line, keyword, value_part, paren_start + current_pos)
                if f:
                    findings.append(f)
            elif keyword and keyword.lower() not in known_lower:
                search_start = paren_start + current_pos
                keyword_pos = line.find(keyword, search_start)
                if keyword_pos != -1:
                    findings.append(make_finding(
                        "UNKNOWN_KEYWORD", keyword_pos, keyword_pos + len(keyword),
                        keyword=keyword, params={"keyword": keyword}))
            elif keyword and keyword.lower() in known_lower:
                keyword_def = self._find_keyword_def(keyword)

                search_start = paren_start + current_pos
                keyword_pos = line.find(keyword, search_start)
                if keyword_pos == -1:
                    keyword_pos = paren_start + current_pos + 1
                keyword_end_pos = keyword_pos + len(keyword)

                if keyword_def:
                    ctx.keywords_found.append({
                        'name': keyword,
                        'keyword_def': keyword_def,
                        'position': keyword_pos,
                        'value': value_part if value_part else None
                    })

                    # Extract flow direction from flow: keyword
                    if keyword == 'flow' and value_part:
                        flow_parts = [p.strip() for p in value_part.split(',')]
                        for part in flow_parts:
                            if part in ('to_server', 'from_client'):
                                ctx.flow_direction = 'to_server'
                                break
                            elif part in ('to_client', 'from_server'):
                                ctx.flow_direction = 'to_client'
                                break

                    # Track active sticky buffer
                    syntax_mode = keyword_def.get('syntax_mode')
                    if syntax_mode == 'sticky_buffer' and not value_part:
                        ctx.active_sticky_buffer = keyword
                    elif keyword == 'content' and ctx.active_sticky_buffer:
                        ctx.content_matches.append({
                            'buffer': ctx.active_sticky_buffer,
                            'value': value_part
                        })
                    elif keyword not in _CONTENT_MODIFIERS:
                        if keyword != 'content':
                            ctx.active_sticky_buffer = None

                    # Unsupported keyword
                    f = self._check_unsupported_keyword(keyword_def, keyword)
                    if f:
                        findings.append(_at(f, keyword_pos, keyword_end_pos))

                    # Syntax mode mismatch
                    following_statements = [s.strip() for s in statements[stmt_idx + 1:] if s.strip()]
                    f = self._check_syntax_mode(keyword_def, keyword, value_part, following_statements)
                    if f:
                        findings.append(_at(f, keyword_pos, keyword_end_pos))

                    # Forbidden modifiers after a sticky buffer's content match
                    if keyword == 'content' and ctx.active_sticky_buffer:
                        modifiers_used = []
                        for following_stmt in following_statements:
                            following_kw = following_stmt.split(':', 1)[0].strip() if ':' in following_stmt else following_stmt.strip()
                            if following_kw in _CONTENT_MODIFIERS:
                                modifiers_used.append(following_kw)
                            else:
                                break

                        buffer_def = self._find_keyword_def(ctx.active_sticky_buffer)
                        if buffer_def and modifiers_used:
                            f = self._check_forbidden_modifiers(buffer_def, ctx.active_sticky_buffer, modifiers_used)
                            if f:
                                # Position: first used modifier that is forbidden
                                for mod in modifiers_used:
                                    if mod in buffer_def.get('forbidden_modifiers', []):
                                        mod_pos = line.find(mod, keyword_pos)
                                        if mod_pos != -1:
                                            findings.append(_at(f, mod_pos, mod_pos + len(mod)))
                                        break

                        # Uppercase http.host content (R13.5); independent
                        # of FORBIDDEN_MODIFIER (nocase).
                        if ctx.active_sticky_buffer.lower() == 'http.host':
                            f = self._check_http_host_uppercase(ctx, value_part)
                            if f:
                                findings.append(_at(f, keyword_pos, keyword_pos + len(statement)))

                    # ssl_version negation placement / duplicates
                    if keyword == 'ssl_version' and value_part:
                        f = self._check_ssl_version_negation(keyword, value_part)
                        if f:
                            findings.append(self._at_value(f, line, value_part, keyword_pos, keyword_end_pos))

                    # xbits track tx
                    if keyword == 'xbits' and value_part:
                        f = self._check_xbits_track(value_part)
                        if f:
                            findings.append(self._at_value(f, line, value_part, keyword_pos, keyword_end_pos))

                    # GeoIP country codes
                    if keyword == 'geoip' and value_part:
                        f = self._check_geoip_country_codes(value_part)
                        if f:
                            findings.append(self._at_value(f, line, value_part, keyword_pos, keyword_end_pos))

                    # JA3/JA3S hash length (sticky buffer: check following content:)
                    if keyword in ('ja3.hash', 'ja3s.hash') and not value_part:
                        for follow_idx, following_stmt in enumerate(following_statements):
                            following_kw = following_stmt.split(':', 1)[0].strip() if ':' in following_stmt else following_stmt.strip()
                            if following_kw == 'content':
                                content_val = following_stmt.split(':', 1)[1].strip() if ':' in following_stmt else ''
                                content_pos = line.find(following_stmt.strip(), keyword_pos)
                                f = self._check_ja3_hash_length(keyword, content_val)
                                if f:
                                    if content_pos != -1:
                                        findings.append(_at(f, content_pos, content_pos + len(following_stmt.strip())))
                                    else:
                                        findings.append(_at(f, keyword_pos, keyword_end_pos))
                                else:
                                    # Same modifier run the forbidden-modifier
                                    # scan collects (R13.6.2)
                                    md5_modifiers = []
                                    for mod_stmt in following_statements[follow_idx + 1:]:
                                        mod_kw = mod_stmt.split(':', 1)[0].strip() if ':' in mod_stmt else mod_stmt.strip()
                                        if mod_kw in _CONTENT_MODIFIERS:
                                            md5_modifiers.append(mod_kw)
                                        else:
                                            break
                                    for f in self._check_md5_buffer(keyword, content_val, md5_modifiers):
                                        if f.code == "MD5_BUFFER_NOCASE":
                                            # Search after the content statement so a
                                            # "nocase" inside the value is not matched
                                            search_from = (content_pos + len(following_stmt.strip())
                                                           if content_pos != -1 else keyword_pos)
                                            mod_pos = line.find('nocase', search_from)
                                            if mod_pos != -1:
                                                findings.append(_at(f, mod_pos, mod_pos + len('nocase')))
                                            else:
                                                findings.append(_at(f, keyword_pos, keyword_end_pos))
                                        elif content_pos != -1:
                                            findings.append(_at(f, content_pos, content_pos + len(following_stmt.strip())))
                                        else:
                                            findings.append(_at(f, keyword_pos, keyword_end_pos))
                                break
                            elif following_kw not in _CONTENT_MODIFIERS:
                                break

                # Enumerated value validation
                if keyword_def and keyword_def.get('values') and value_part:
                    self._check_enum_values(line, keyword, keyword_def, value_part,
                                            paren_start + current_pos, findings)

            current_pos += len(statement) + 1

        # --- Cross-keyword checks (after all keywords are collected) ---

        # 1. Packet-level vs app-layer mixing
        f = self._check_packet_app_layer_mixing(ctx.keywords_found)
        if f:
            self._append_at_keyword(f, f.keyword, ctx.keywords_found, findings)

        # 2. Flow direction conflicts
        for f in self._check_flow_direction_conflict(ctx.keywords_found, ctx.flow_direction):
            self._append_at_keyword(f, f.keyword, ctx.keywords_found, findings)

        # 2b. Request + response buffers with no flow direction (R13.1)
        f = self._check_mixed_direction_buffers(ctx)
        if f:
            findings.append(f)

        # 3. pcre companion
        f = self._check_pcre_companion(ctx.keywords_found)
        if f:
            self._append_at_keyword(f, 'pcre', ctx.keywords_found, findings)

        # 4. ip_proto protocol
        f = self._check_ip_proto_protocol(ctx.protocol, ctx.keywords_found)
        if f:
            self._append_at_keyword(f, 'ip_proto', ctx.keywords_found, findings)

        # 5. app-layer-protocol redundancy / conflict (positioned on the
        # offending app-layer-protocol statement)
        f = self._check_app_layer_protocol(ctx.protocol, ctx.keywords_found)
        if f:
            findings.append(f)

        # 6. more than one category keyword (R13.7.4)
        f = self._check_category_keyword_conflict(ctx.keywords_found)
        if f:
            findings.append(f)

    @staticmethod
    def _at_value(finding, line, value_part, keyword_pos, keyword_end_pos):
        """Position a finding on the keyword's value, falling back to the
        keyword name (same arithmetic as the Advanced Editor)."""
        value_pos = line.find(value_part, keyword_pos)
        if value_pos != -1:
            return _at(finding, value_pos, value_pos + len(value_part))
        return _at(finding, keyword_pos, keyword_end_pos)

    @staticmethod
    def _append_at_keyword(finding, kw_name, keywords_found, findings):
        """Append ``finding`` positioned on the first collected keyword named
        ``kw_name``; dropped if not found (as in the Advanced Editor)."""
        for kw_entry in keywords_found:
            if kw_entry['name'] == kw_name:
                start_col = kw_entry['position']
                findings.append(_at(finding, start_col, start_col + len(kw_name)))
                break

    def _check_enum_values(self, line, keyword, keyword_def, value_part,
                           search_start, findings):
        valid_values = [v.lower() for v in keyword_def.get('values', [])]
        # aws_url_category / aws_domain_category: AWS matches category names
        # case-sensitively after trimming (R13.7.1), so compare exact-case and
        # offer the correctly-cased name as a suggestion.
        is_category = keyword.lower() in CATEGORY_KEYWORDS
        exact_values = set(keyword_def.get('values', [])) if is_category else None
        cased_by_lower = {}
        if is_category:
            for v in keyword_def.get('values', []):
                cased_by_lower.setdefault(v.lower(), v)

        syntax = keyword_def.get('syntax', '')
        validate_first_part_only = False
        if ',' in syntax and '<' in syntax.split(',', 1)[1]:
            validate_first_part_only = True

        if keyword_def.get('multi_value'):
            if ',' in value_part:
                user_values = [v.strip() for v in value_part.split(',')]
            elif '|' in value_part:
                user_values = [v.strip() for v in value_part.split('|')]
            else:
                user_values = [value_part]
        elif validate_first_part_only and ',' in value_part:
            first_part = value_part.split(',', 1)[0].strip()
            user_values = [first_part]
        else:
            user_values = [value_part]

        if is_category:
            self._check_category_values(line, keyword, value_part, user_values,
                                        exact_values, cased_by_lower,
                                        search_start, findings)
            return

        for user_value in user_values:
            check_value = user_value
            negated = user_value.startswith('!')
            if negated:
                check_value = user_value[1:].strip()

            # AWS rejects a negated 'unknown' on app-layer-protocol ("can't
            # use negation with protocol 'unknown'"); only the plain form is valid.
            negation_invalid = (negated and keyword.lower() == 'app-layer-protocol'
                                and check_value.lower() == 'unknown')
            if check_value and (negation_invalid
                                or check_value.lower() not in valid_values):
                numeric_range = keyword_def.get('numeric_range')
                if numeric_range and check_value.isdigit():
                    num_val = int(check_value)
                    if numeric_range[0] <= num_val <= numeric_range[1]:
                        continue

                value_pos = line.find(user_value, search_start)
                if value_pos != -1:
                    params = {"value": user_value, "keyword": keyword}
                    if numeric_range:
                        params["min"] = numeric_range[0]
                        params["max"] = numeric_range[1]
                    findings.append(make_finding(
                        "INVALID_ENUM_VALUE", value_pos, value_pos + len(user_value),
                        keyword=keyword, params=params))

    def _check_category_values(self, line, keyword, value_part, user_values,
                               exact_values, cased_by_lower, search_start, findings):
        """Category value checks for aws_url_category / aws_domain_category
        (R13.7.1-R13.7.3), in this order: CATEGORY_EMPTY (and nothing else),
        else INVALID_ENUM_VALUE per value (exact-case, with a case suggestion),
        then the first CATEGORY_DUPLICATE_VALUE. ``user_values`` is the
        existing multi_value split; the existing quote and ``!`` handling is
        unchanged."""
        checked = []  # (user_value, check_value) of non-empty items
        for user_value in user_values:
            check_value = user_value
            if user_value.startswith('!'):
                check_value = user_value[1:].strip()
            if check_value:
                checked.append((user_value, check_value))

        if not checked:
            # Value present but no category after splitting and trimming
            value_pos = line.find(value_part, search_start)
            if value_pos == -1:
                value_pos = search_start
            findings.append(make_finding(
                "CATEGORY_EMPTY", value_pos, value_pos + len(value_part),
                keyword=keyword, params={"keyword": keyword}))
            return

        # (1) exact-case membership (same position arithmetic as the generic check)
        for user_value, check_value in checked:
            if check_value in exact_values:
                continue
            value_pos = line.find(user_value, search_start)
            if value_pos != -1:
                params = {"value": user_value, "keyword": keyword}
                suggestion = cased_by_lower.get(check_value.lower())
                if suggestion:
                    params["suggestion"] = suggestion
                findings.append(make_finding(
                    "INVALID_ENUM_VALUE", value_pos, value_pos + len(user_value),
                    keyword=keyword, params=params))

        # (2) first duplicate (exact match after trim), positioned on the
        # repeated occurrence
        seen = set()
        cursor = search_start
        for user_value, _check_value in checked:
            pos = line.find(user_value, cursor)
            if pos != -1:
                cursor = pos + len(user_value)
            if user_value in seen:
                if pos == -1:
                    pos = line.find(user_value, search_start)
                if pos != -1:
                    findings.append(make_finding(
                        "CATEGORY_DUPLICATE_VALUE", pos, pos + len(user_value),
                        keyword=keyword, params={"keyword": keyword, "value": user_value}))
                break
            seen.add(user_value)

    def _check_category_keyword_conflict(self, keywords_found):
        """CATEGORY_KEYWORD_CONFLICT (R13.7.4): more than one category keyword
        (url + domain, or either one twice). Reported once, positioned on the
        second category keyword."""
        cats = [kw for kw in keywords_found if kw['name'].lower() in CATEGORY_KEYWORDS]
        if len(cats) < 2:
            return None
        second = cats[1]
        start = second['position']
        return make_finding(
            "CATEGORY_KEYWORD_CONFLICT", start, start + len(second['name']),
            keyword=second['name'], params={"keyword": second['name']})

    # ------------------------------------------------------------------
    # Per-keyword helpers (return an unpositioned Finding or None)
    # ------------------------------------------------------------------
    def _check_unsupported_keyword(self, keyword_def, keyword):
        if not keyword_def.get('supported', True):
            reason = keyword_def.get('unsupported_reason', 'not supported in AWS Network Firewall')
            return make_finding("AWS_UNSUPPORTED_KEYWORD", keyword=keyword,
                                params={"keyword": keyword, "reason": reason})
        return None

    def _check_syntax_mode(self, keyword_def, keyword, value_part, following_statements):
        syntax_mode = keyword_def.get('syntax_mode')
        if syntax_mode is None:
            return None

        if syntax_mode == "direct_value":
            if not value_part:
                for stmt in following_statements:
                    if stmt.strip().startswith('content:'):
                        return make_finding("SYNTAX_MODE_DIRECT_AS_STICKY", keyword=keyword,
                                            params={"keyword": keyword})
        elif syntax_mode == "sticky_buffer":
            if value_part:
                return make_finding("SYNTAX_MODE_STICKY_AS_DIRECT", keyword=keyword,
                                    params={"keyword": keyword, "value": value_part})
        return None

    def _check_ssl_version_negation(self, keyword, value_part):
        if keyword != "ssl_version":
            return None

        values = [val.strip() for val in value_part.split(',')]

        bang_count = value_part.count('!')
        if bang_count > 1 or (bang_count == 1 and not values[0].startswith('!')):
            return make_finding("SSL_VERSION_NEGATION", keyword=keyword,
                                params={"keyword": keyword, "value": value_part})

        seen = set()
        for val in values:
            name = val.lstrip('!').strip().lower()
            if not name:
                continue
            if name in seen:
                return make_finding("SSL_VERSION_DUPLICATE", keyword=keyword,
                                    params={"keyword": keyword, "name": name})
            seen.add(name)
        return None

    def _check_xbits_track(self, value_part):
        for part in value_part.split(','):
            tokens = part.strip().lower().split()
            if len(tokens) >= 2 and tokens[0] == 'track' and tokens[1] == 'tx':
                return make_finding("XBITS_TRACK_TX", keyword="xbits",
                                    params={"keyword": "xbits", "value": value_part})
        return None

    def _check_forbidden_modifiers(self, keyword_def, keyword, modifiers_used):
        forbidden_modifiers = keyword_def.get('forbidden_modifiers', [])
        if not forbidden_modifiers:
            return None

        for modifier in modifiers_used:
            if modifier in forbidden_modifiers:
                reason = keyword_def.get('forbidden_modifier_reasons', {}).get(modifier, "")
                return make_finding("FORBIDDEN_MODIFIER", keyword=keyword,
                                    params={"modifier": modifier, "keyword": keyword,
                                            "reason": reason})
        return None

    def _check_geoip_country_codes(self, value_part):
        if not value_part or not self.valid_country_codes:
            return None

        parts = value_part.split(',')
        if len(parts) < 2:
            return make_finding("GEOIP_MISSING_COUNTRY_CODE", keyword="geoip",
                                params={"keyword": "geoip", "value": value_part})

        country_codes = parts[1:]
        non_empty_codes = [c.strip().lstrip('!') for c in country_codes if c.strip() and c.strip() != '!']
        if not non_empty_codes:
            return make_finding("GEOIP_MISSING_COUNTRY_CODE", keyword="geoip",
                                params={"keyword": "geoip", "value": value_part})

        for code in country_codes:
            code = code.strip()
            if not code:
                continue
            if code.startswith('!'):
                code = code[1:]
            if not code:
                continue
            if code.upper() not in self.valid_country_codes:
                suggestion = COUNTRY_CODE_SUGGESTIONS.get(code.upper())
                return make_finding("GEOIP_INVALID_COUNTRY_CODE", keyword="geoip",
                                    params={"keyword": "geoip", "code": code,
                                            "suggestion": suggestion})
        return None

    def _check_ja3_hash_length(self, keyword, content_value):
        if keyword not in ("ja3.hash", "ja3s.hash"):
            return None
        if not content_value:
            return None

        value = content_value.strip()
        if not value:
            return None
        if value.startswith('!'):
            value = value[1:]
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        else:
            return None
        if '|' in value:
            return None
        if len(value) != 32:
            return make_finding("JA3_HASH_LENGTH", keyword=keyword,
                                params={"keyword": keyword, "value": value,
                                        "actual_len": len(value)})
        return None

    def _check_md5_buffer(self, keyword, content_value, modifiers_used):
        """MD5_BUFFER_NOT_HEX / MD5_BUFFER_NOCASE (R13.6). Called only after
        _check_ja3_hash_length returned None. Returns a (possibly empty) list
        of unpositioned findings: NOT_HEX first, then NOCASE."""
        results = []
        if keyword.lower() not in MD5_BUFFER_KEYWORDS:
            return results

        value = (content_value or '').strip()
        if value.startswith('!'):
            value = value[1:]
        # Hex test only on a quoted, 32-character value without |..| patterns
        # (the same values JA3_HASH_LENGTH accepts as length-checked).
        if (len(value) >= 2 and value.startswith('"') and value.endswith('"')):
            inner = value[1:-1]
            if ('|' not in inner and len(inner) == 32
                    and inner.lower() != 'x' * 32
                    and any(ch not in _HEX_DIGITS for ch in inner)):
                results.append(make_finding(
                    "MD5_BUFFER_NOT_HEX", keyword=keyword,
                    params={"keyword": keyword, "value": inner}))

        if 'nocase' in modifiers_used:
            results.append(make_finding(
                "MD5_BUFFER_NOCASE", keyword=keyword,
                params={"keyword": keyword, "modifier": "nocase"}))
        return results

    def _check_http_host_uppercase(self, ctx, content_value):
        """HTTP_HOST_UPPERCASE (R13.5): a content match on the http.host buffer
        whose literal text (outside |..| hex segments) has an uppercase ASCII
        letter. Independent of FORBIDDEN_MODIFIER."""
        if not ctx.active_sticky_buffer or ctx.active_sticky_buffer.lower() != 'http.host':
            return None
        value = (content_value or '').strip()
        if value.startswith('!'):
            value = value[1:]
        if not (len(value) >= 2 and value.startswith('"') and value.endswith('"')):
            return None
        inner = value[1:-1]

        # Even-indexed segments are literal text; odd-indexed are |..| hex.
        segments = inner.split('|')
        has_upper = False
        suggestion_parts = []
        for idx, seg in enumerate(segments):
            if idx % 2 == 0:
                if any('A' <= ch <= 'Z' for ch in seg):
                    has_upper = True
                suggestion_parts.append(seg.lower())
            else:
                suggestion_parts.append(seg)
        if not has_upper:
            return None
        return make_finding(
            "HTTP_HOST_UPPERCASE", keyword="http.host",
            params={"keyword": "http.host", "value": inner,
                    "suggestion": "|".join(suggestion_parts)})

    # ------------------------------------------------------------------
    # Cross-keyword helpers
    # ------------------------------------------------------------------
    def _check_packet_app_layer_mixing(self, keywords_found):
        """Finding.keyword is the first packet-level keyword (the caller
        positions the finding on it)."""
        packet_keywords = []
        app_layer_keywords = []
        for kw in keywords_found:
            keyword_level = kw['keyword_def'].get('keyword_level')
            if keyword_level == 'packet':
                packet_keywords.append(kw)
            elif keyword_level == 'app_layer':
                app_layer_keywords.append(kw)

        if packet_keywords and app_layer_keywords:
            first_packet = packet_keywords[0]
            app_layer_names = [kw['name'] for kw in app_layer_keywords[:3]]
            return make_finding("PACKET_APP_LAYER_MIXING", keyword=first_packet['name'],
                                params={"packet_keyword": first_packet['name'],
                                        "app_layer_list": ", ".join(app_layer_names)})
        return None

    def _check_pcre_companion(self, keywords_found):
        companion_keywords = {"content", "tls.sni", "http.host", "http.uri", "dns.query"}
        if not any(kw['name'] == 'pcre' for kw in keywords_found):
            return None
        if any(kw['name'] in companion_keywords for kw in keywords_found):
            return None
        return make_finding("PCRE_COMPANION", keyword="pcre", params={"keyword": "pcre"})

    def _check_ip_proto_protocol(self, protocol, keywords_found):
        if not any(kw['name'] == 'ip_proto' for kw in keywords_found):
            return None
        if protocol.lower() != 'ip':
            return make_finding("IP_PROTO_PROTOCOL", keyword="ip_proto",
                                params={"keyword": "ip_proto", "protocol": protocol})
        return None

    def _check_flow_direction_conflict(self, keywords_found, flow_value):
        """Return a list of findings (Finding.keyword = conflicting keyword)."""
        if flow_value is None:
            return []

        flow_parts = [part.strip() for part in flow_value.split(',')]
        rule_direction = None
        for part in flow_parts:
            if part in ('to_server', 'from_client'):
                rule_direction = 'to_server'
                break
            elif part in ('to_client', 'from_server'):
                rule_direction = 'to_client'
                break
        if rule_direction is None:
            return []

        conflicts = []
        for kw in keywords_found:
            kw_flow_direction = kw['keyword_def'].get('flow_direction')
            if kw_flow_direction is None or kw_flow_direction == 'both':
                continue
            if kw_flow_direction == 'to_client' and rule_direction == 'to_server':
                conflicts.append(make_finding(
                    "FLOW_DIRECTION_RESPONSE_ON_TO_SERVER", keyword=kw['name'],
                    params={"keyword": kw['name']}))
            elif kw_flow_direction == 'to_server' and rule_direction == 'to_client':
                conflicts.append(make_finding(
                    "FLOW_DIRECTION_REQUEST_ON_TO_CLIENT", keyword=kw['name'],
                    params={"keyword": kw['name']}))
        return conflicts

    def _check_mixed_direction_buffers(self, ctx):
        """MIXED_DIRECTION_BUFFERS (R13.1): a request-only (flow_direction
        to_server) and a response-only (to_client) keyword in a rule with no
        flow: direction. Skipped when a flow direction is set, so it never
        fires together with FLOW_DIRECTION_*. Positioned on whichever of the
        two keywords appears later in the rule."""
        if ctx.flow_direction is not None:
            return None
        req = None
        resp = None
        for kw in ctx.keywords_found:
            direction = kw['keyword_def'].get('flow_direction')
            if direction == 'to_server' and req is None:
                req = kw
            elif direction == 'to_client' and resp is None:
                resp = kw
        if req is None or resp is None:
            return None
        later = req if req['position'] > resp['position'] else resp
        start = later['position']
        return make_finding(
            "MIXED_DIRECTION_BUFFERS", start, start + len(later['name']),
            keyword=later['name'],
            params={"req_kw": req['name'], "resp_kw": resp['name']})

    def _check_gid(self, line, keyword, value_part, search_start):
        """GID_NOT_ALLOWED (R13.3): a customer-supplied gid option. Positioned
        on the option name."""
        if keyword.lower() != 'gid':
            return None
        keyword_pos = line.find(keyword, search_start)
        if keyword_pos == -1:
            keyword_pos = search_start + 1
        return make_finding(
            "GID_NOT_ALLOWED", keyword_pos, keyword_pos + len(keyword),
            keyword=keyword, params={"keyword": keyword, "value": value_part})

    def _check_gid_without_keyword_data(self, line, content_section, paren_start, findings):
        """Run the gid check when keyword data is unavailable (the per-statement
        keyword loop does not run then). Same statement/position arithmetic."""
        current_pos = 0
        for statement in split_options_lossless(content_section):
            statement = statement.strip()
            if not statement:
                current_pos += 1
                continue
            if ':' in statement:
                keyword, value_part = statement.split(':', 1)
                keyword, value_part = keyword.strip(), value_part.strip()
            else:
                keyword, value_part = statement, ''
            if keyword.lower() in self.HANDLED_OPTIONS:
                f = self._check_gid(line, keyword, value_part, paren_start + current_pos)
                if f:
                    findings.append(f)
            current_pos += len(statement) + 1

    _IP_REF_WHOLE_FIELD = re.compile(r'^!?@[A-Za-z0-9_]+$')
    _IP_REF_NAME = re.compile(r'@[A-Za-z0-9_]+')

    def _check_ip_reference_in_group(self, token_positions):
        """IP_REFERENCE_IN_GROUP (R13.2): an @NAME IP set reference used
        anywhere but as the whole source/destination network field. Header
        finding (empty keyword), positioned on the network-field token.
        Returns a list (source first, then destination)."""
        results = []
        for idx, field_name in ((2, "Source Network"), (5, "Destination Network")):
            if len(token_positions) <= idx:
                continue
            start, end, token = token_positions[idx]
            value = token.strip()
            if '@' not in value or self._IP_REF_WHOLE_FIELD.match(value):
                continue
            match = self._IP_REF_NAME.search(value)
            if not match:
                continue  # malformed; generic syntax checks report it
            results.append(make_finding(
                "IP_REFERENCE_IN_GROUP", start, end, keyword="",
                params={"field": field_name, "value": value,
                        "reference": match.group(0)}))
        return results

    def _check_app_layer_protocol(self, protocol, keywords_found):
        """APP_LAYER_PROTOCOL_REDUNDANT / APP_LAYER_PROTOCOL_CONFLICT.

        Matches AWS Network Firewall CreateRuleGroup DryRun (Oct 25 2026):
        - An app-layer-protocol statement (negated or not, any value) is
          rejected when the header protocol is not tcp/udp/ip/icmp, or when an
          EARLIER known keyword sets the app protocol
          (``keyword_sets_app_layer_protocol``). Keywords after it never count.
        - More than one non-negated value, or a non-negated value mixed with a
          negated one, is rejected ("conflicting app-layer-protocol rules").
          Several negated values only are accepted.
        At most one finding per rule; REDUNDANT wins over CONFLICT. Positioned
        on the offending app-layer-protocol statement.
        """
        header = (protocol or '').lower()
        header_sets = bool(header) and header not in NON_APP_HEADER_PROTOCOLS
        setter = None          # first earlier keyword that sets the protocol
        seen_positive = None   # first non-negated value seen
        seen_negated = None    # first negated value seen
        conflict = None
        for kw in keywords_found:
            name = kw['name']
            if name != 'app-layer-protocol':
                if setter is None and keyword_sets_app_layer_protocol(kw.get('keyword_def')):
                    setter = name
                continue
            alp_value = (kw.get('value') or '').strip()
            if not alp_value:
                continue
            start = kw['position']
            end = start + len(name)
            if header_sets or setter is not None:
                source = 'header' if header_sets else 'keyword'
                source_name = protocol if header_sets else setter
                return _at(make_finding(
                    "APP_LAYER_PROTOCOL_REDUNDANT", keyword="app-layer-protocol",
                    params={"keyword": "app-layer-protocol", "protocol": alp_value,
                            "source": source, "source_name": source_name}),
                    start, end)
            negated = alp_value.startswith('!')
            if conflict is None:
                prior = seen_negated if not negated else None
                if seen_positive is not None:
                    prior = seen_positive
                if prior is not None:
                    conflict = _at(make_finding(
                        "APP_LAYER_PROTOCOL_CONFLICT", keyword="app-layer-protocol",
                        params={"keyword": "app-layer-protocol", "protocol": alp_value,
                                "first": prior}),
                        start, end)
            if negated:
                if seen_negated is None:
                    seen_negated = alp_value
            elif seen_positive is None:
                seen_positive = alp_value
        return conflict

    # ------------------------------------------------------------------
    # Step (6): category protocol checks + aws_route_53_resolved_domain
    # ------------------------------------------------------------------
    def _check_category_protocols(self, content_section, paren_start,
                                  token_positions, findings):
        lowered = content_section.lower()
        # Only for rules with a ';' inside a quoted value: ignore keyword text
        # inside quoted values. Regions are computed on `lowered` so they share
        # the index base of the lowered.find() offsets below.
        regions = quoted_regions(lowered) if has_quoted_semicolon(content_section) else None
        for kw_name, code in (("aws_url_category", "AWS_URL_CATEGORY_PROTOCOL"),
                              ("aws_domain_category", "AWS_DOMAIN_CATEGORY_PROTOCOL")):
            if (kw_name + ':') in lowered and len(token_positions) > 1:
                protocol = token_positions[1][2]
                if not is_category_protocol_allowed(kw_name, protocol):
                    start_pos = lowered.find(kw_name + ':')
                    if regions is not None:
                        while start_pos != -1 and in_quoted_region(regions, start_pos):
                            start_pos = lowered.find(kw_name + ':', start_pos + 1)
                        if start_pos == -1:
                            continue
                    end_pos = start_pos + len(kw_name)
                    findings.append(make_finding(
                        code, paren_start + 1 + start_pos, paren_start + 1 + end_pos,
                        keyword=kw_name, params={"keyword": kw_name, "protocol": protocol}))

    _R53_OCC_PATTERN = re.compile(
        r'aws_route_53_resolved_domain\s*:\s*("[^"]*"|[^;]*)',
        re.IGNORECASE
    )

    def _check_route53_domain(self, content_section, paren_start, findings):
        kw_name = 'aws_route_53_resolved_domain'
        if (kw_name + ':') not in content_section.lower():
            return
        occurrences = list(self._R53_OCC_PATTERN.finditer(content_section))
        if has_quoted_semicolon(content_section):
            # Only for rules with a ';' inside a quoted value: ignore matches
            # that start inside a quoted value.
            regions = quoted_regions(content_section)
            occurrences = [m for m in occurrences
                           if not in_quoted_region(regions, m.start())]
        for occ_idx, match in enumerate(occurrences):
            kw_start = paren_start + 1 + match.start()
            kw_end = kw_start + len(kw_name)
            raw_value = match.group(1).strip()
            val_start = paren_start + 1 + match.start(1)
            val_end = val_start + len(match.group(1))

            # (1) more than one occurrence per rule: flag the 2nd+
            if occ_idx > 0:
                findings.append(make_finding(
                    "R53_DOMAIN_MULTIPLE", kw_start, kw_end,
                    keyword=kw_name, params={"keyword": kw_name}))

            # (2) value must be double-quoted
            if not (len(raw_value) >= 2 and raw_value.startswith('"') and raw_value.endswith('"')):
                findings.append(make_finding(
                    "R53_DOMAIN_UNQUOTED", val_start, val_end,
                    keyword=kw_name, params={"keyword": kw_name, "value": raw_value}))
            else:
                inner = raw_value[1:-1]
                # (3) empty / whitespace-only quoted value (R13.8.1)
                if not inner.strip():
                    findings.append(make_finding(
                        "R53_DOMAIN_EMPTY", val_start, val_end,
                        keyword=kw_name, params={"keyword": kw_name, "value": inner}))
                # (4) leading-dot wildcards, not asterisks
                elif '*' in inner:
                    findings.append(make_finding(
                        "R53_DOMAIN_ASTERISK", val_start, val_end,
                        keyword=kw_name, params={"keyword": kw_name, "value": inner}))
                else:
                    # (5) first item that is not a valid FQDN / wildcard (R13.8.2)
                    for item in inner.split(','):
                        domain = item.strip()
                        if not is_valid_r53_domain(domain):
                            findings.append(make_finding(
                                "R53_DOMAIN_INVALID", val_start, val_end,
                                keyword=kw_name,
                                params={"keyword": kw_name, "value": inner, "domain": domain}))
                            break

    # ------------------------------------------------------------------
    # Step (7): undefined-variable scan
    # ------------------------------------------------------------------
    _VAR_PATTERN = re.compile(r'([\$@]\w+)')

    def _check_undefined_variables(self, line, findings):
        for match in self._VAR_PATTERN.finditer(line):
            var_name = match.group(1)
            var_pos = match.start()

            # Don't flag variables inside quoted strings
            in_quotes = False
            for char in line[:var_pos]:
                if char == '"':
                    in_quotes = not in_quotes

            if not in_quotes and var_name not in self.variables:
                findings.append(make_finding(
                    "UNDEFINED_VARIABLE", match.start(), match.end(),
                    params={"variable": var_name}))
