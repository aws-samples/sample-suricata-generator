"""
Suricata rule emitter.

Turns a ParsedConfig (acls + http_access + http_reply_access) into Suricata rules.

Verdict mapping (Squid action -> Suricata action):
    allow -> pass   (with `alert;` when alert_on_pass is on)
    deny  -> <deny_action> : reject (default) or drop
             (monitoring first is done with the Generator's export test mode)

The output is always for AWS Network Firewall's explicit proxy (a capability of
Network Firewall, not a separate deployment mode): a DNS pass rule for the
proxy's own name lookups is always the first rule.

Every rule of a line is checked, in its final form, with the caller's
rule_check (the Generator's shared rule validator). Any error makes the whole
line not convertible, so a condition is never silently dropped.

How one Squid access line is converted:
  1. annotate_transaction / annotate_client ACLs are no-ops for matching
     (they always match). Their `rule=<tag>` value is added to the rule msg.
  2. Group ACLs are expanded: all-of members are ANDed into the line, any-of
     becomes OR branches (one set of rules per branch), a negated any-of
     becomes the AND of its negated members. A negated all-of is not converted.
  3. If ANY condition has no Suricata equivalent (time, proxy_auth, maxconn,
     an undefined ACL, ...), NOTHING is emitted for the line and the line is
     reported. Dropping a condition would silently widen or narrow the policy.
  4. Header ACLs (src/dst/port) fill the rule header. Per field at most one
     non-negated ACL plus any number of negated ones: [$A,![x,y]].
  5. App-layer ACLs: values inside one ACL are ORed (one rule per value, cross
     product across ACLs); a negated ACL adds all its values as negated
     matches to every rule of the line.
  6. Each line is emitted for HTTP and for TLS. A condition the other protocol
     cannot see (e.g. a URL path on TLS, an SNI on HTTP) makes that variant
     impossible when non-negated, or is omitted when negated. `method CONNECT`
     is treated as satisfied on TLS (HTTPS through Squid is a CONNECT tunnel).
  7. Lines with only header conditions become an `http` + `tls` pair (never a
     `tcp` rule, which would also cover non-web protocols).
  8. http_reply_access lines are not converted (only `allow all`, which needs
     no rule). A response check only applies to requests Squid allowed, and
     those are `pass` rules here; once a `pass` rule matches, AWS Network
     Firewall stops inspecting the whole connection, so a response rule never
     sees the reply (verified on a live firewall, including a flowbit set
     before the pass).

Rules are emitted in Squid's first-match order; load them into an AWS Network
Firewall stateful rule group with STRICT_ORDER so that order is preserved.
"""

import hashlib
import ipaddress
import itertools
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from src.core.aws_rule_constraints import is_reject_allowed

from . import sslbump
from .mapping import lookup, FULL, PARTIAL, NONE, AclMapping
from .nfw_literal import required_literal
from .parser import ParsedConfig, HttpAccess, Acl, AclRef, where

# AWS Network Firewall rejects a rule using `pcre` unless it also carries one
# of these options. Verified against the service with CreateRuleGroup DryRun.
# On any other buffer the pcre needs a `content:` prefilter to be deployable.
_PCRE_SELF_SUFFICIENT = {"tls.sni", "http.host", "dns.query", "http.uri"}

# Per-access-line outcomes, for the total-accounting invariant.
EMITTED = "emitted"
NOT_CONVERTIBLE = "not_convertible"
NOTE_ONLY = "note_only"


# How a Squid `deny` is converted.
DENY_ACTIONS = ("reject", "drop")

# A Rule_Check takes one complete rule line and returns error messages
# (empty list = acceptable). Supplied by the caller.
RuleCheck = Callable[[str], List[str]]

# Proxy deployment: the firewall resolves each destination name itself by
# querying the Amazon Route 53 Resolver (169.254.169.253), and that DNS lookup
# is evaluated by the stateful engine as DNS from the client's address. Under
# an application-layer default drop it is dropped, so every proxied request
# fails - even to explicitly allowed domains - unless DNS is passed first
# (observed on a live proxy-mode firewall). The rule is scoped to the
# Resolver address so clients cannot use it to reach external DNS servers.
PROXY_DNS_RESOLVER = "169.254.169.253"
# Port 53 only: the proxy's queries to port 5353 are classified as mdns, not
# dns, so a dns rule never matched them, and name resolution works without
# them (observed on a live proxy-mode firewall).
_PROXY_DNS_RULE_HEAD = "pass dns any any -> %s 53" % PROXY_DNS_RESOLVER
PROXY_DNS_MSG = "Squid import: proxy DNS"

# A SID in the valid range used while checking a rule before its real SID is
# assigned.
_PLACEHOLDER_SID = 1000000

# Longest rule msg, in characters.
_MSG_MAX = 120

_MAX_RULES_PER_LINE = 200


@dataclass
class EmitResult:
    rules: List[str]
    notes: List[str]          # informational (partial conversions, defaults)
    not_convertible: List[str]  # lines/ACLs that had no Suricata equivalent
    # Address and port variables used by the rules, in first-use order:
    #   VAR_NAME -> {"acl": <squid acl name>, "acl_type": "src"|"port",
    #                "values": [cidr/port, ...]}
    # `acl_type` is "src" for an IP set variable, "port" for a port set.
    variables: "OrderedDict[str, dict]" = field(default_factory=OrderedDict)
    # Access-control directives that are not converted (icp_access, ssl_bump, ...)
    unhandled: List[str] = field(default_factory=list)
    # Problems reading the config (missing include, unevaluable `if`, ...)
    problems: List[str] = field(default_factory=list)
    # (line_no, source, directive) -> EMITTED | NOT_CONVERTIBLE | NOTE_ONLY
    line_outcomes: Dict[Tuple[int, Optional[str], str], str] = field(default_factory=dict)
    # Places the converted policy knowingly differs from the source Squid.
    # Reported, never silent (requirement (c)).
    divergences: List[str] = field(default_factory=list)
    # SslBump posture of the source config (sslbump.Posture).
    posture: object = None
    # Where each SslBump-related ACL type has to be handled on the AWS side.
    sslbump_classification: List[str] = field(default_factory=list)
    # Whether --route53-resolved-domains was used.
    resolved_domains: bool = False
    # Options the rules were built with.
    deny_action: str = "reject"
    alert_on_pass: bool = True
    # One _RuleSpec per entry of `rules` (same order) and its content SID.
    specs: List["_RuleSpec"] = field(default_factory=list)
    sids: List[int] = field(default_factory=list)
    # (line_no, source, directive) -> (short_reason, [indexes into rules])
    line_info: Dict[Tuple[int, Optional[str], str], Tuple[str, List[int]]] = \
        field(default_factory=dict)
    # Set when a converted `http` rule carries an HTTP-only condition
    # (URL, path, method, header, MIME type).
    http_only_used: bool = False
    # Set when a rule uses aws_route_53_resolved_domain.
    r53_used: bool = False
    # Problems with the rules the converter generates itself (not from a
    # Squid line), for example the proxy DNS rule failing the rule check.
    generated_problems: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SID allocation
#
# SIDs anchor alert history and rule suppressions in AWS Network Firewall, so
# they must be STABLE: editing one part of a squid.conf must not renumber
# unrelated rules. Sequential allocation fails this - adding one domain to an
# allowlist shifted every following SID by one.
#
# Instead each SID is derived from the rule's own semantic content (action,
# protocol, addresses, ports, match options and rule tag) and deliberately NOT
# from its position or source line number. Adding, removing or reordering rules
# therefore leaves every other rule's SID untouched.
# ---------------------------------------------------------------------------
SID_BASE = 1000000
SID_SPAN = 1000000          # SIDs land in [1000000, 1999999]


@dataclass
class _RuleSpec:
    """A rule with everything decided except its SID."""
    head: str
    opts: str
    label: str            # "<squid action> <protocol>", e.g. "allow tls"
    loc: str              # "line 244" or "conf.d/rules.conf line 4"
    tag: str              # " rule=<tags>" or ""
    action: str = ""      # rule action: pass | reject | drop
    protocol: str = ""    # rule protocol: http | tls | ftp | dns
    line_no: Optional[int] = None
    source: Optional[str] = None
    origin: str = "squid"          # "squid" | "generated"
    alert: bool = False            # add `alert;` (alert on pass)
    msg_override: Optional[str] = None

    def semantic_key(self) -> str:
        """Identity used to derive the SID: what the rule MATCHES and DOES.

        Excludes the source line number so that editing the squid.conf above a
        rule does not change that rule's SID. Also excludes the msg and the
        `alert;` keyword, which do not change what the rule matches.
        """
        return "|".join((self.head, self.opts, self.label, self.tag))

    def msg(self) -> str:
        """Short trace to the source line: `Squid line 244 allow tls
        (app_allow)` or `Squid conf.d/rules.conf line 4 deny http`."""
        if self.msg_override is not None:
            return self.msg_override
        tags = self.tag[len(" rule="):] if self.tag else ""
        tail = " line %d %s%s" % (self.line_no or 0, self.label,
                                  (" (%s)" % tags) if tags else "")
        if not self.source:
            return _msg_safe("Squid" + tail)[:_MSG_MAX]
        label = self.source
        room = _MSG_MAX - len("Squid " + tail)
        if room < 4:
            return _msg_safe("Squid" + tail)[:_MSG_MAX]
        if len(label) > room:
            label = "..." + label[-(room - 3):]
        return _msg_safe("Squid " + label + tail)

    def render(self, sid: int) -> str:
        return '%s (%s%ssid:%d; rev:1; msg:"%s";)' % (
            self.head, self.opts, "alert; " if self.alert else "", sid,
            self.msg())


class ContentSidAllocator:
    """Assigns stable, content-derived SIDs.

    Identical rules that genuinely repeat get distinct SIDs via an occurrence
    counter; hash collisions between different rules are resolved by probing
    upward. Both are deterministic, so output is reproducible.
    """

    def __init__(self, base: int = SID_BASE, span: int = SID_SPAN):
        self.base, self.span = base, span
        self._taken: Dict[int, str] = {}
        self._seen_keys: Dict[str, int] = {}
        self.collisions = 0

    def assign(self, key: str) -> int:
        n = self._seen_keys.get(key, 0)
        self._seen_keys[key] = n + 1
        unique = key if n == 0 else "%s#%d" % (key, n)
        digest = hashlib.sha256(unique.encode("utf-8")).digest()
        offset = int.from_bytes(digest[:8], "big") % self.span
        sid = self.base + offset
        while sid in self._taken and self._taken[sid] != unique:
            self.collisions += 1
            offset = (offset + 1) % self.span
            sid = self.base + offset
        self._taken[sid] = unique
        return sid


# ---------------------------------------------------------------------------
# src ACL -> address variable
#
# AWS Network Firewall RuleVariables.IPSets keys must be 1-32 chars and match
# ^[A-Za-z][A-Za-z0-9_]*$ (same rules work for Suricata address-groups).
# ---------------------------------------------------------------------------
_VAR_MAX_LEN = 32
_RESERVED_VARS = {"HOME_NET", "EXTERNAL_NET"}


# ---------------------------------------------------------------------------
# Squid address ranges -> CIDR
#
# Squid `src` / `dst` ACLs accept `addr1-addr2` ranges. Suricata rule headers
# and AWS Network Firewall IP set variables accept CIDR blocks only, so each
# range is rewritten as the exact set of CIDR blocks covering it (no more and
# no fewer addresses). The masked form `addr1-addr2/mask` has Squid-specific
# matching semantics and is reported instead of guessed at.
# ---------------------------------------------------------------------------
_RANGE_RE = re.compile(r"^([0-9a-fA-F:.]+)-([0-9a-fA-F:.]+)(/\S+)?$")


def _range_to_cidrs(value: str) -> Optional[List[str]]:
    """CIDR blocks for a Squid `addr1-addr2` range, or None if not a range.

    Raises ValueError (with a reason fit for a report) for a range that
    cannot be converted exactly.
    """
    m = _RANGE_RE.match(value)
    if m is None:
        return None
    if m.group(3):
        raise ValueError(
            "address range `%s` has a netmask; Squid's masked-range matching "
            "has no exact CIDR equivalent, so rewrite it as CIDR blocks by "
            "hand" % value)
    try:
        lo = ipaddress.ip_address(m.group(1))
        hi = ipaddress.ip_address(m.group(2))
    except ValueError:
        raise ValueError("address range `%s` does not contain two valid IP "
                         "addresses" % value)
    if lo.version != hi.version:
        raise ValueError("address range `%s` mixes IPv4 and IPv6" % value)
    if lo > hi:
        raise ValueError("address range `%s` ends before it starts" % value)
    return [str(n) for n in ipaddress.summarize_address_range(lo, hi)]


# Squid's "everything" spellings; left as they are (the default-policy logic
# recognises them).
_SPECIAL_ADDRESSES = {"all", "0/0"}

# A DNS host name as Squid accepts it in src/dst ACLs (it resolves the name
# when it loads the config). At least one letter, so a malformed IP is not
# taken for a name.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?=.*[A-Za-z])"
    r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*\.?$")


def _as_network(value: str) -> Optional[str]:
    """CIDR form of an IP, CIDR or dotted-netmask value, or None.

    10.0.0.5 -> 10.0.0.5/32, 10.0.0.0/255.255.255.0 -> 10.0.0.0/24, and an
    address with host bits set (10.0.0.5/24) -> its network, which is how
    Squid applies the mask.
    """
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def _is_hostname(value: str) -> bool:
    return (_RANGE_RE.match(value) is None and value not in _SPECIAL_ADDRESSES
            and _as_network(value) is None and bool(_HOSTNAME_RE.match(value)))


def _check_address_values(acl: Acl) -> None:
    """Raise _Unconvertible for an address value that cannot become CIDR."""
    for value in acl.values:
        try:
            if _range_to_cidrs(value) is not None:
                continue
        except ValueError as e:
            raise _Unconvertible(acl.name, acl.acl_type, str(e))
        if value in _SPECIAL_ADDRESSES or _as_network(value) is not None:
            continue
        if _is_hostname(value) and acl.acl_type == "src":
            raise _Unconvertible(
                acl.name, acl.acl_type,
                "`%s` is a host name. Squid resolves it when it loads the "
                "config, but NFW rules and IP set variables need IP addresses, "
                "and resolving it here would freeze addresses that can change. "
                "Replace it with the client's IP or CIDR" % value)
        if value.startswith((".", "*")):
            raise _Unconvertible(
                acl.name, acl.acl_type,
                "`%s` looks like a wildcard domain, but a %s ACL has no "
                "wildcard form (Squid resolves each host name to IPs). Use a "
                "dstdomain ACL for a domain and its subdomains" % (value, acl.acl_type))
        raise _Unconvertible(acl.name, acl.acl_type,
                             "`%s` is not an IP address, CIDR block, netmask "
                             "or address range" % value)


def _cidr_values(values: List[str]) -> Tuple[List[str], List[str]]:
    """(values as CIDR blocks, change notes).

    Ranges become the CIDR blocks that cover them; bare IPs and dotted
    netmasks become CIDR notation (NFW IP sets accept CIDR only). Call only
    after _check_address_values has accepted the values.
    """
    out: List[str] = []
    changes: List[str] = []
    for value in values:
        cidrs = _range_to_cidrs(value)
        if cidrs is not None:
            changes.append("%s -> %s" % (value, ", ".join(cidrs)))
            out.extend(cidrs)
            continue
        net = None if value in _SPECIAL_ADDRESSES else _as_network(value)
        if net is None or net == value:
            out.append(value)
            continue
        changes.append("%s -> %s" % (value, net))
        out.append(net)
    return out, changes


def _var_name(acl_name: str) -> str:
    """Sanitize a Squid ACL name into a valid NFW/Suricata variable name.

    Uppercase; non-alphanumerics -> '_'; leading non-letter -> 'ACL_' prefix;
    truncate to 32 chars. Collisions/reserved names are handled by VarRegistry.
    """
    name = re.sub(r"[^A-Za-z0-9_]", "_", acl_name).upper()
    if not name or not name[0].isalpha():
        name = "ACL_" + name
    return name[:_VAR_MAX_LEN]


class VarRegistry:
    """Maps Squid src ACL names to unique variable names and tracks their CIDRs."""

    def __init__(self):
        self._by_acl: Dict[str, str] = {}
        self.variables: "OrderedDict[str, dict]" = OrderedDict()
        self.notes: List[str] = []

    def snapshot(self):
        """State to restore when a line's rules are refused."""
        return (dict(self._by_acl), OrderedDict(self.variables),
                list(self.notes))

    def restore(self, state) -> None:
        by_acl, variables, notes = state
        self._by_acl = dict(by_acl)
        self.variables = OrderedDict(variables)
        self.notes = list(notes)

    @staticmethod
    def _with_suffix(base: str, suffix: str) -> str:
        return base[:_VAR_MAX_LEN - len(suffix)] + suffix

    def _allocate(self, acl: Acl, kind: str) -> str:
        """Reserve a unique variable name for `acl`, or return the existing one.
        `kind` ("src" or "port") only shapes the reserved-name note."""
        if acl.name in self._by_acl:
            return self._by_acl[acl.name]
        base = _var_name(acl.name)
        if base in _RESERVED_VARS:
            renamed = self._with_suffix(base, "_ACL")
            self.notes.append(
                "%s ACL `%s` would map to reserved Suricata variable $%s; "
                "renamed to $%s." % (kind, acl.name, base, renamed)
            )
            base = renamed
        name, n = base, 2
        while name in self.variables:
            name = self._with_suffix(base, "_%d" % n)
            n += 1
        self._by_acl[acl.name] = name
        return name

    def register(self, acl: Acl) -> str:
        """Register a `src` ACL as an NFW IP set variable."""
        if acl.name in self._by_acl:
            return self._by_acl[acl.name]
        name = self._allocate(acl, "src")
        values, changes = _cidr_values(acl.values)
        self.variables[name] = {"acl": acl.name, "acl_type": "src",
                                "values": values}
        if changes:
            self.notes.append(
                "Variable $%s (acl %s): Squid addresses converted to CIDR "
                "notation (address ranges, bare IPs and netmasks), because NFW "
                "IP sets accept CIDR only: %s."
                % (name, acl.name, "; ".join(changes))
            )
        return name

    def register_port(self, acl: Acl) -> str:
        """Register a `port` ACL as an NFW port set variable. Squid port ranges
        (`1025-65535`) become Suricata/NFW range syntax (`1025:65535`)."""
        if acl.name in self._by_acl:
            return self._by_acl[acl.name]
        name = self._allocate(acl, "port")
        values = [v.replace("-", ":") for v in acl.values]
        self.variables[name] = {"acl": acl.name, "acl_type": "port",
                                "values": values}
        return name


# ---------------------------------------------------------------------------
# Squid built-in ACLs
# ---------------------------------------------------------------------------
# Built-ins that have no explicit `acl` line but are understood by Squid out of
# the box (or ship in the default config). We synthesize an equivalent Acl.
#   name -> (acl_type, [values])
_PREDEFINED_ACLS = {
    "CONNECT": ("method", ["CONNECT"]),          # predefined method ACL
    "all": ("src", ["0.0.0.0/0"]),               # matches everything
    # Written in CIDR form, as NFW expects, so no conversion note is needed.
    # The converter targets IPv4, so the IPv6 parts of Squid's built-ins
    # (::1, ::/128, fe80::/10) are not included.
    "localhost": ("src", ["127.0.0.1/32"]),
    # Squid's built-in to_localhost also covers 0.0.0.0, which on Linux reaches
    # local services.
    "to_localhost": ("dst", ["127.0.0.0/8", "0.0.0.0/32"]),
    # link-local / APIPA range Squid protects by default
    "to_linklocal": ("dst", ["169.254.0.0/16"]),
}

# Built-ins that are proxy-internal and have no traffic-rule analog.
_PREDEFINED_NONE = {
    "manager": "Squid cache-manager interface ACL; proxy-internal, no Suricata analog.",
}
for _cert in ("certHasExpired", "certNotYetValid", "certUntrusted",
              "certSelfSigned", "certDomainMismatch"):
    for _n in (_cert, "ssl::" + _cert):
        _PREDEFINED_NONE[_n] = "SslBump certificate-validation ACL; proxy-internal."

_ANNOTATION_TYPES = {"annotate_transaction", "annotate_client"}
_GROUP_TYPES = {"any-of", "all-of"}

# Squid `proto` values -> Suricata rule protocols. Squid is an HTTP/HTTPS/FTP
# proxy, so these are the only schemes with a wire-protocol equivalent; the
# rest (CACHE_OBJECT, URN, WHOIS, ICP, ...) are proxy-internal.
# `ftp` and `ftp-data` were verified accepted by NFW via DryRun.
_PROTO_TO_WIRE = {
    "HTTP": ("http",),
    "HTTPS": ("tls",),
    "FTP": ("ftp",),
}
# Every wire protocol a line can be emitted for, in output order.
_ALL_WIRE = ("http", "tls", "ftp")
# Wire protocols that carry no HTTP app-layer buffers, so an http.* condition
# cannot be expressed on them.
_NO_HTTP_BUFFERS = {"ftp"}
# Header-based http-only types Squid can also evaluate on a CONNECT request.
_CONNECT_VISIBLE_HTTP = {"browser", "referer_regex", "req_header", "req_mime_type"}


class _Unconvertible(Exception):
    def __init__(self, acl_name: str, acl_type: str, reason: str):
        super().__init__(reason)
        self.acl_name, self.acl_type, self.reason = acl_name, acl_type, reason


def _short_reason(u: "_Unconvertible") -> str:
    """One short phrase for a comment row: `external ACL ExtEng`."""
    if u.acl_type == "line":
        return "too many rules"
    if u.acl_type == "undefined":
        return "undefined ACL %s" % u.acl_name
    return "%s ACL %s" % (u.acl_type, u.acl_name)


@dataclass
class _Item:
    acl: Acl
    negated: bool
    mapping: AclMapping


def _resolve_acl(name: str, cfg: ParsedConfig) -> Optional[Acl]:
    """Return the Acl for a name, synthesizing Squid built-ins when the config
    has no explicit `acl` line for it."""
    acl = cfg.acls.get(name)
    if acl is not None:
        return acl
    spec = _PREDEFINED_ACLS.get(name)
    if spec is not None:
        acl_type, values = spec
        return Acl(name=name, acl_type=acl_type, values=list(values),
                   value_lines=[list(values)])
    return None


def _verdict_action(squid_action: str, deny_action: str) -> str:
    if squid_action == "allow":
        return "pass"
    return deny_action  # "reject" or "drop"


def _only_connect(acl: Acl) -> bool:
    """True when a method ACL matches nothing but CONNECT."""
    return bool(acl.values) and all(v.upper() == "CONNECT" for v in acl.values)


# Loopback / unspecified addresses. Through the explicit proxy the rules never
# see a source in these ranges (they see the client's VPC address), and the
# proxy refuses destinations in them before any rule is evaluated: bare IPs
# with HTTP 400, host names resolving to loopback with HTTP 403 (observed on a
# live proxy-mode firewall).
_LOOPBACK_NETS = [ipaddress.ip_network(n) for n in
                  ("127.0.0.0/8", "0.0.0.0/32", "::1/128", "::/128")]
# IPv4 link-local (instance metadata, the Route 53 Resolver address, ...).
# The proxy refuses these destinations too: bare IPs with HTTP 400, host names
# resolving into the range with HTTP 403, including 169.254.169.254, on every
# listener (observed on a live proxy-mode firewall). Private (RFC 1918)
# destinations are NOT refused: the proxy connects and the rules see them.
_LINKLOCAL_NETS = [ipaddress.ip_network("169.254.0.0/16")]
# Destinations the proxy refuses before any rule runs.
_PROXY_BLOCKED_DST_NETS = _LOOPBACK_NETS + _LINKLOCAL_NETS


def _loopback_only(acl: Optional[Acl]) -> bool:
    """True for a src/dst ACL whose every value is a loopback or unspecified
    address (Squid's `localhost` / `to_localhost`, built in or user-defined)."""
    return _all_in(acl, _LOOPBACK_NETS)


def _proxy_blocked_dst(acl: Optional[Acl]) -> bool:
    """True for a dst ACL whose every value is an address the proxy refuses
    (loopback or link-local: Squid's `to_localhost`, `to_linklocal`, or a
    user-defined ACL with only such addresses)."""
    return (acl is not None and acl.acl_type == "dst"
            and _all_in(acl, _PROXY_BLOCKED_DST_NETS))


def _all_in(acl: Optional[Acl], ranges) -> bool:
    """True for a src/dst ACL whose every value lies inside `ranges`."""
    if acl is None or acl.acl_type not in ("src", "dst") or not acl.values:
        return False
    for value in acl.values:
        try:
            cidrs = _range_to_cidrs(value)
        except ValueError:
            return False
        nets = cidrs if cidrs is not None else [_as_network(value)]
        for net in nets:
            if net is None:
                return False
            n = ipaddress.ip_network(net)
            if not any(n.version == r.version and n.subnet_of(r)
                       for r in ranges):
                return False
    return True


def _in_any(acl: Acl, ranges) -> bool:
    """True when at least one value of `acl` lies inside `ranges` (call only
    for an ACL that _all_in has accepted)."""
    for value in acl.values:
        cidrs = _range_to_cidrs(value)
        for net in (cidrs if cidrs is not None else [_as_network(value)]):
            n = ipaddress.ip_network(net)
            if any(n.version == r.version and n.subnet_of(r) for r in ranges):
                return True
    return False


def _is_all_acl(acl: Optional[Acl]) -> bool:
    return bool(acl) and acl.acl_type == "src" and any(
        v in ("all", "0.0.0.0/0", "0/0", "::/0") for v in acl.values)


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------
def _pcre_escape(regex: str) -> str:
    """Make a Squid regex safe inside pcre:"/.../": escape the `/` delimiter,
    and write `"` and `;` (special in Suricata rule options) as hex escapes."""
    out, i = [], 0
    while i < len(regex):
        c = regex[i]
        if c == "\\" and i + 1 < len(regex):
            nxt = regex[i + 1]
            out.append({'"': "\\x22", ";": "\\x3b"}.get(nxt, c + nxt))
            i += 2
            continue
        out.append({"/": "\\/", '"': "\\x22", ";": "\\x3b"}.get(c, c))
        i += 1
    return "".join(out)


def _content_escape(value: str) -> str:
    """Escape a literal for content:"...": `"`, `;`, `\\` and `|` as hex bytes."""
    special = {'"': "|22|", ";": "|3B|", "\\": "|5C|", "|": "|7C|"}
    return "".join(special.get(c, c) for c in value)


# ---------------------------------------------------------------------------
# Match clauses
# ---------------------------------------------------------------------------
class _NeedsCompanion(str):
    """A bare `pcre` clause that NFW only accepts if the finished rule has a
    companion option somewhere else (a content match or one of the
    self-sufficient sticky buffers). The caller's rule_check decides; the
    ACL and reason are kept for diagnostics.
    """
    acl_name = "?"
    acl_type = "?"
    reason = ""


def _needs_companion(clause: str, acl: Optional[Acl], reason: str) -> str:
    tagged = _NeedsCompanion(clause)
    tagged.acl_name = acl.name if acl is not None else "?"
    tagged.acl_type = acl.acl_type if acl is not None else "?"
    tagged.reason = reason
    return tagged


def _pcre(keyword: str, body: str, negated: bool, flags: str = "",
          acl: Optional[Acl] = None) -> str:
    """Build a pcre match, adding the `content:` prefilter NFW requires.

    On buffers other than tls.sni / http.host / dns.query / http.uri, Network
    Firewall refuses a `pcre` unless the RULE also has a companion option. A
    positive pcre gets a `content` prefilter when the regex guarantees a
    literal, so `content AND pcre` selects exactly what `pcre` alone did.

    A NEGATED pcre can take no prefilter (requiring the literal would wrongly
    narrow a "does not match" condition), and some regexes guarantee no
    literal. Those are returned bare and tagged; the rule they end up in is
    checked as a whole once it is assembled, and only refused if nothing else
    in it satisfies NFW.
    """
    clause = '%s; pcre:"%s/%s/%s";' % (keyword, "!" if negated else "",
                                       body, flags)
    if keyword in _PCRE_SELF_SUFFICIENT:
        return clause

    if negated:
        return _needs_companion(
            clause, acl,
            "a negated regex on the Suricata `%s` buffer cannot be deployed to "
            "AWS Network Firewall on its own: NFW requires a `content:` option "
            "(or tls.sni / http.host / dns.query / http.uri) in the rule "
            "alongside `pcre`, no content prefilter is valid for a negated "
            "match (it would narrow the condition), and nothing else on this "
            "line provides one" % keyword)

    literal = required_literal(body)
    if literal is None:
        return _needs_companion(
            clause, acl,
            "AWS Network Firewall requires a `content:` option (or tls.sni / "
            "http.host / dns.query / http.uri) in the rule alongside `pcre` "
            "on the `%s` buffer, no literal is guaranteed by the regex `%s` "
            "so no prefilter can be added without changing the policy, and "
            "nothing else on this line provides one" % (keyword, body))
    return '%s; content:"%s"; nocase; pcre:"/%s/%s";' % (
        keyword, _content_escape(literal), body, flags)


class _DomainClause(str):
    """A dstdomain / ssl::server_name match on http.host or tls.sni.

    The string value is the stand-alone form. Squid matches domain names
    case-insensitively, so the value is lowercased; `nocase` is added on
    tls.sni (the server name is not normalised) but not on http.host, which
    Suricata already lowercases (and where NFW-oriented validators reject
    `nocase`).

    Stand-alone forms:
      .example.com -> <buf>; dotprefix; content:".example.com"; endswith;
                      dotprefix prepends "." to the buffer, so this matches
                      example.com and any subdomain but not evilexample.com:
                      exactly Squid's leading-dot meaning.
      a.example.com -> <buf>; content:"a.example.com"; startswith; endswith;

    When several clauses share one buffer, _merge_buffers renders them
    together under a single `dotprefix` (see under_dotprefix).
    """
    keyword = ""
    domain = ""          # lowercased, without the leading dot
    dotted = False
    negated = False

    @property
    def _mods(self) -> str:
        return " nocase;" if self.keyword == "tls.sni" else ""

    @property
    def _neg(self) -> str:
        return "!" if self.negated else ""

    def under_dotprefix(self) -> str:
        """Content match against a buffer that already has `dotprefix`."""
        value = _content_escape("." + self.domain)
        if self.dotted:
            return 'content:%s"%s"; endswith;%s' % (self._neg, value, self._mods)
        return 'content:%s"%s"; startswith; endswith;%s' % (self._neg, value,
                                                            self._mods)

    def pcre_form(self) -> str:
        """Equivalent match without a transform, for buffers that also carry
        a regex (a transform would change what that regex sees)."""
        if not self.dotted:
            return str(self)
        body = "(^|\\.)" + _pcre_escape(re.escape(self.domain)) + "$"
        flags = "i" if self.keyword == "tls.sni" else ""
        return '%s; pcre:"%s/%s/%s";' % (self.keyword, self._neg, body, flags)


def _domain_clause(keyword: str, value: str, negated: bool) -> _DomainClause:
    dotted = value.startswith(".")
    domain = (value[1:] if dotted else value).lower()
    neg = "!" if negated else ""
    mods = " nocase;" if keyword == "tls.sni" else ""
    if dotted:
        text = '%s; dotprefix; content:%s"%s"; endswith;%s' % (
            keyword, neg, _content_escape("." + domain), mods)
    else:
        text = '%s; content:%s"%s"; startswith; endswith;%s' % (
            keyword, neg, _content_escape(domain), mods)
    clause = _DomainClause(text)
    clause.keyword, clause.domain = keyword, domain
    clause.dotted, clause.negated = dotted, negated
    return clause


# Squid ACL types whose values are domain names (matched case-insensitively).
_DOMAIN_TYPES = {"dstdomain", "ssl::server_name"}


def _content(keyword: str, value: str, negated: bool, mods: str = "") -> str:
    return '%s; content:%s"%s";%s' % (keyword, "!" if negated else "",
                                     _content_escape(value), mods)


def _content_match(keyword: str, value: str, negated: bool, nocase: bool,
                   is_regex: bool, acl: Optional[Acl] = None) -> str:
    """Build a match for a domain/string/regex value on a sticky buffer.

    Squid DOTTED ".google.com" means the domain AND its subdomains. A plain
    `content; endswith` would also match "evilgoogle.com", so it becomes a
    label-anchored pcre /(^|\\.)google\\.com$/. An UNDOTTED value is an exact
    match (startswith + endswith). A regex value becomes pcre.
    """
    if is_regex:
        return _pcre(keyword, _pcre_escape(value), negated,
                     "i" if nocase else "", acl)
    if value.startswith("."):
        body = "(^|\\.)" + _pcre_escape(re.escape(value[1:])) + "$"
        return _pcre(keyword, body, negated, "i" if nocase else "", acl)
    return _content(keyword, value, negated,
                    " startswith; endswith;" + (" nocase;" if nocase else ""))


def _header_regex_clause(header: str, regex: str, negated: bool, nocase: bool,
                         acl: Optional[Acl] = None) -> str:
    """Squid applies a header ACL regex to the VALUE of one named header.
    Emit a pcre on http.header anchored to that header's line."""
    lead = "[^\\r\\n]*"
    if regex.startswith("^"):
        regex, lead = regex[1:], "[ \\t]*"
    if regex.endswith("$") and not regex.endswith("\\$"):
        regex = regex[:-1] + "\\r?$"
    body = "^(?i:%s):%s%s" % (re.escape(header), lead, _pcre_escape(regex))
    return _pcre("http.header", body, negated,
                 "m" + ("i" if nocase else ""), acl)


def _merge_buffers(clauses: List[str]) -> str:
    """Join match clauses, selecting each sticky buffer once:
    ['http.uri; pcre:"!/a/";', 'http.uri; pcre:"!/b/";'] ->
    'http.uri; pcre:"!/a/"; pcre:"!/b/";'  (Suricata warns on duplicates).

    Domain clauses need care because `dotprefix` transforms the whole buffer
    and may appear only once, directly after it:
      * one clause on the buffer: its stand-alone form;
      * several clauses, all domains, any of them dotted: one `dotprefix`,
        and every domain matched against the dot-prefixed buffer
        (an exact host a.com becomes content:".a.com"; startswith; endswith);
      * domains mixed with any other match (a regex) on the same buffer:
        the dotted domains use their pcre form, so the transform cannot
        change what the regex sees.
    """
    groups: "OrderedDict[str, List[str]]" = OrderedDict()
    for c in clauses:
        kw, _, _rest = c.partition("; ")
        groups.setdefault(kw, []).append(c)
    rendered = []
    for kw, parts in groups.items():
        domains = [p for p in parts if isinstance(p, _DomainClause)]
        if len(parts) > 1 and any(d.dotted for d in domains):
            if len(domains) == len(parts):
                rendered.append("%s; dotprefix; %s" % (
                    kw, " ".join(d.under_dotprefix() for d in domains)))
                continue
            parts = [p.pcre_form() if isinstance(p, _DomainClause) else p
                     for p in parts]
        rendered.append("%s; %s" % (kw, " ".join(p.partition("; ")[2]
                                                 for p in parts)))
    return " ".join(rendered)


def _acl_values(item: _Item) -> List[str]:
    """Values to generate clauses from."""
    return list(item.acl.values)


def _value_clause(item: _Item, value: str, proto: str) -> str:
    acl, m, neg = item.acl, item.mapping, item.negated
    t = acl.acl_type
    if t == "req_header" or m.fixed_header:
        return _header_regex_clause(acl.header_name or m.fixed_header, value,
                                    neg, acl.case_insensitive, acl)
    if t == "server_cert_fingerprint":
        return _content("tls.cert_fingerprint", value.lower(), neg)
    keyword = "tls.sni" if proto == "tls" and m.keyword == "http.host" else m.keyword
    if t in _DOMAIN_TYPES and keyword in ("http.host", "tls.sni"):
        return _domain_clause(keyword, value, neg)
    return _content_match(keyword, value, neg, acl.case_insensitive,
                          m.is_regex, acl)


# ---------------------------------------------------------------------------
# Line expansion
# ---------------------------------------------------------------------------
def _strip_annotations(refs: List[AclRef], cfg: ParsedConfig):
    """Remove always-true annotation ACLs; return (remaining refs, rule tags)."""
    kept, tags = [], []
    for ref in refs:
        acl = cfg.acls.get(ref.name)
        if acl is not None and acl.acl_type in _ANNOTATION_TYPES:
            for v in acl.values:
                key, sep, val = v.partition("=")
                if sep and key.rstrip("+") == "rule" and val:
                    tags.append(val)
            continue
        kept.append(ref)
    return kept, tags


def _expand(name: str, negated: bool, cfg: ParsedConfig,
            stack: Tuple[str, ...]) -> List[List[_Item]]:
    """Expand one ACL reference into OR-branches, each an AND-list of items."""
    acl = _resolve_acl(name, cfg)
    if acl is None:
        if name in _PREDEFINED_NONE:
            raise _Unconvertible(name, "predefined", _PREDEFINED_NONE[name])
        raise _Unconvertible(name, "undefined", "ACL is not defined in the config")
    if acl.conflict:
        raise _Unconvertible(name, acl.acl_type, acl.conflict)
    if acl.acl_type in _GROUP_TYPES and name in stack:
        raise _Unconvertible(name, acl.acl_type, "group ACL refers to itself (cycle)")
    inner = stack + (name,)

    if acl.acl_type == "all-of":
        if negated:
            raise _Unconvertible(name, "all-of", "negated all-of is an OR of "
                                 "negations; not converted")
        branches: List[List[_Item]] = []
        for line in acl.value_lines:          # same-name all-of lines are ORed
            acc: List[List[_Item]] = [[]]
            for member in line:
                sub = _expand(member, False, cfg, inner)
                acc = [a + b for a in acc for b in sub]
                _check_cap(len(acc), name, acl.acl_type)
            branches.extend(acc)
        return branches

    if acl.acl_type == "any-of":
        if negated:                           # NOT(a OR b) = !a AND !b
            acc = [[]]
            for member in acl.values:
                sub = _expand(member, True, cfg, inner)
                acc = [a + b for a in acc for b in sub]
            return acc
        out: List[List[_Item]] = []
        for member in acl.values:
            out.extend(_expand(member, False, cfg, inner))
            _check_cap(len(out), name, acl.acl_type)
        return out

    m = lookup(acl.acl_type)
    if m is None:
        raise _Unconvertible(name, acl.acl_type, "unknown ACL type")
    if acl.acl_type == "dst":
        hosts = [v for v in acl.values if _is_hostname(v)]
        if hosts:
            return _expand_dst_hostnames(acl, hosts, negated, m)
    return [[_Item(acl, negated, m)]]


# A dst ACL's host names become an aws_route_53_resolved_domain condition
# instead of rule-header addresses (see _expand_dst_hostnames).
_R53_DST = AclMapping(
    "dst", FULL, layers=["r53"],
    note="Destination host name -> aws_route_53_resolved_domain (matches when "
         "the Route 53 Resolver resolved the destination IP for that name).")


def _expand_dst_hostnames(acl: Acl, hosts: List[str], negated: bool,
                          m: AclMapping) -> List[List[_Item]]:
    """Split a dst ACL that names hosts into OR branches.

    Squid resolves dst host names when it loads the config and matches the
    destination IP against the result. AWS Network Firewall's
    aws_route_53_resolved_domain keyword matches when the Route 53 Resolver
    resolved the connection's destination IP for the name, which follows DNS
    changes instead of freezing a startup lookup. Values inside one ACL are
    ORed, so the IPs (rule header) and the names (keyword) become separate
    branches: either one matching is a match.
    """
    if negated:
        raise _Unconvertible(
            acl.name, acl.acl_type,
            "a negated dst ACL with host names (%s) is not converted: it "
            "would need a negated aws_route_53_resolved_domain match, which "
            "the AWS documentation does not describe" % ", ".join(hosts))
    branches: List[List[_Item]] = []
    ips = [v for v in acl.values if v not in hosts]
    if ips:
        branches.append([_Item(Acl(name=acl.name, acl_type="dst", values=ips,
                                   value_lines=[ips]), False, m)])
    names = []
    for host in hosts:
        h = host.rstrip(".").lower()
        if h not in names:
            names.append(h)
    branches.append([_Item(Acl(name=acl.name, acl_type="dst", values=names,
                               value_lines=[names]), False, _R53_DST)])
    return branches


def _r53_clause(branch: List["_Item"]) -> str:
    """The aws_route_53_resolved_domain option for one branch, or ''."""
    hosts = [h for i in branch if "r53" in i.mapping.layers for h in i.acl.values]
    if not hosts:
        return ""
    return 'aws_route_53_resolved_domain:"%s";' % ",".join(hosts)


def _check_cap(count: int, name: str, acl_type: str) -> None:
    if count > _MAX_RULES_PER_LINE:
        raise _Unconvertible(name, acl_type, "expands to more than %d rules"
                             % _MAX_RULES_PER_LINE)


def _validate(item: _Item, directive: str) -> None:
    acl, m = item.acl, item.mapping
    missing = [v for v in acl.values if v.startswith("__MISSING_INCLUDE__:")]
    if missing:
        # The parser's sentinel carries the reason, naming the file.
        raise _Unconvertible(acl.name, acl.acl_type,
                             "ACL value " + missing[0].split(":", 1)[1])
    if m.reply_only and directive == "http_access":
        raise _Unconvertible(acl.name, acl.acl_type,
                             "reply-only ACL used in http_access (Squid only "
                             "evaluates it in http_reply_access)")
    if m.convertibility == NONE or not m.layers:
        raise _Unconvertible(acl.name, acl.acl_type, m.note or "no Suricata analog")
    if "header" in m.layers and not acl.values:
        raise _Unconvertible(acl.name, acl.acl_type, "ACL has no values")
    if m.header_field == "port" and "0" in acl.values:
        raise _Unconvertible(
            acl.name, acl.acl_type,
            "`port 0` matches Squid requests that have no port at all (for "
            "example URN targets); network traffic always has a port, so a "
            "firewall rule on port 0 would never match")
    if m.header_field in ("src_ip", "dst_ip"):
        _check_address_values(acl)


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------
class _LineEmitter:
    def __init__(self, cfg, deny_action, alert_on_pass, rule_check,
                 resolved_domains=False):
        self.cfg, self.deny_action = cfg, deny_action
        self.alert_on_pass = alert_on_pass
        self.rule_check = rule_check
        # (line_no, source, directive) -> (short_reason, [spec indexes])
        self.line_info: Dict[Tuple[int, Optional[str], str],
                             Tuple[str, List[int]]] = {}
        self._short_reason = ""
        # Locations of converted `allow` lines with a destination-address
        # condition (see the bare-IP note in _proxy_deployment_notes).
        self.dst_address_lines: List[str] = []
        # Set when a line's `proto FTP` produced ftp rules (see the FTP note
        # in _proxy_deployment_notes).
        self.ftp_used = False
        # --route53-resolved-domains: domain matches also require the
        # destination IP to be one the Route 53 Resolver returned for the name.
        self.resolved_domains = resolved_domains
        # Set when (with resolved_domains) a regex domain rule could not carry
        # the keyword (see emit()).
        self.regex_domain_without_r53 = False
        self.specs: List[_RuleSpec] = []
        self.notes: List[str] = []
        self.not_convertible: List[str] = []
        self.registry = VarRegistry()
        self.line_outcomes: Dict[Tuple[int, Optional[str], str], str] = {}
        # Set when a rule carries an HTTP-only condition (see emit()).
        self.http_only_used = False
        # Set when a rule uses aws_route_53_resolved_domain (see emit()).
        self.r53_used = False

    def _note(self, line_notes: List[str], text: str) -> None:
        if text not in line_notes:
            line_notes.append(text)

    def _allowed_wire(self, items: List[_Item], ha: HttpAccess) -> Optional[set]:
        """Wire protocols a `proto` ACL restricts this line to, or None.

        Squid's `proto` is the URL scheme, so it selects the Suricata rule
        protocol rather than adding a match condition. A non-negated value
        narrows the line to that protocol; a negated one excludes it.
        """
        proto_items = [i for i in items if "proto" in i.mapping.layers]
        if not proto_items:
            return None
        allowed = set(_ALL_WIRE)
        for item in proto_items:
            wires: set = set()
            for value in item.acl.values:
                key = value.upper()
                if key not in _PROTO_TO_WIRE:
                    raise _Unconvertible(
                        item.acl.name, item.acl.acl_type,
                        "`proto %s` is a proxy-internal scheme with no wire "
                        "protocol a firewall rule can select (only HTTP, "
                        "HTTPS and FTP have one)" % value)
                wires.update(_PROTO_TO_WIRE[key])
            # Values inside one ACL are ORed; separate ACLs on a line are ANDed.
            allowed &= (set(_ALL_WIRE) - wires) if item.negated else wires
        if not allowed:
            raise _Unconvertible(
                proto_items[0].acl.name, "proto",
                "the `proto` conditions on this line cannot all be true at "
                "once, so no rule protocol satisfies them")
        return allowed

    # -- header ---------------------------------------------------------------
    def _render_one(self, acl: Acl) -> str:
        if acl.acl_type == "src" and acl.name in self.cfg.acls:
            return "$" + self.registry.register(acl)
        header_field = lookup(acl.acl_type).header_field
        # User-defined `port` ACLs become NFW port set variables (the Generator
        # auto-detects the port-set type from the port position in the header),
        # mirroring how `src` ACLs become IP set variables.
        if header_field == "port" and acl.name in self.cfg.acls:
            return "$" + self.registry.register_port(acl)
        values = acl.values
        if header_field == "port":
            # Squid writes port ranges as 1025-65535; Suricata uses 1025:65535.
            values = [v.replace("-", ":") for v in values]
        elif header_field in ("src_ip", "dst_ip"):
            # Literal addresses in the rule header (dst ACLs, built-ins):
            # address ranges become CIDR blocks, as for variables.
            values, changes = _cidr_values(values)
            if changes:
                note = ("acl %s: Squid addresses converted to CIDR notation "
                        "in the rule header (address ranges, bare IPs and "
                        "netmasks): %s."
                        % (acl.name, "; ".join(changes)))
                if note not in self.notes:
                    self.notes.append(note)
        return values[0] if len(values) == 1 else "[" + ",".join(values) + "]"

    def _render_field(self, items: List[_Item]) -> str:
        pos = [self._render_one(i.acl) for i in items if not i.negated]
        neg = [self._render_one(i.acl) for i in items if i.negated]
        if not pos and not neg:
            return "any"
        neg_group = (neg[0] if len(neg) == 1 else "[" + ",".join(neg) + "]") if neg else ""
        if pos and not neg:
            return pos[0]
        if not pos:
            return "!" + neg_group
        return "[%s,!%s]" % (pos[0], neg_group)

    # -- app layer ------------------------------------------------------------
    def _variant(self, app_items: List[_Item], proto: str, ha: HttpAccess,
                 line_notes: List[str]) -> Optional[List[str]]:
        """Return the list of match strings for one protocol variant, or None
        when the variant can never match."""
        options: List[List[str]] = []
        negs: List[str] = []
        other = "TLS" if proto == "tls" else "HTTP"
        for it in app_items:
            acl, m = it.acl, it.mapping
            if (acl.acl_type == "method" and proto == "http"
                    and not it.negated and _only_connect(acl)):
                # An http.method CONNECT rule never matches in AWS Network
                # Firewall. In the transparent (source-preservation)
                # deployment there is no CONNECT on the wire; in the proxy
                # (no-source-preservation) deployment the proxy answers the
                # CONNECT itself and does not pass it to the rules - the
                # tunnel is judged by tls.sni instead (observed on a live
                # proxy-mode firewall). So the rule is suppressed and
                # reported; the companion tls rule carries the policy.
                self._note(line_notes,
                           "Squid %s: `%s` [method CONNECT] produces no HTTP "
                           "rule - AWS Network Firewall rules never see a "
                           "CONNECT request (in the proxy deployment the "
                           "proxy answers CONNECT itself and the tunnel is "
                           "matched by tls.sni). The TLS rule for this line "
                           "carries the policy instead."
                           % (_loc(ha), acl.name))
                return None
            if acl.acl_type == "server_cert_fingerprint":
                self._note(line_notes,
                           "Squid %s: `%s` [server_cert_fingerprint] maps to "
                           "tls.cert_fingerprint, which STOPS matching inside "
                           "an AWS Network Firewall TLS inspection scope - "
                           "after decryption only tls.sni still matches. This "
                           "rule will not fire for traffic the firewall "
                           "decrypts." % (_loc(ha), acl.name))
            if acl.acl_type == "method" and proto == "tls":
                # HTTPS through Squid is a CONNECT tunnel.
                has_connect = "CONNECT" in acl.values
                if has_connect != it.negated:
                    continue                      # satisfied: drop on TLS
                self._note(line_notes, "Squid %s: `%s%s` [method] cannot match "
                           "TLS traffic; no TLS rule." % (_loc(ha),
                                                         "!" if it.negated else "", acl.name))
                return None
            if proto not in m.layers:
                where = "HTTP-only" if proto == "tls" else "TLS-only"
                if it.negated:
                    self._note(line_notes, "Squid %s: `!%s` [%s] is %s; omitted "
                               "from the %s rule (always true there)."
                               % (_loc(ha), acl.name, acl.acl_type, where, other))
                    continue
                extra = ""
                if proto == "tls" and acl.acl_type in _CONNECT_VISIBLE_HTTP:
                    extra = (" Squid also checks it on the CONNECT request "
                             "headers, which AWS Network Firewall rules cannot "
                             "see: they are inside TLS in the transparent "
                             "deployment, and the proxy deployment does not "
                             "pass the CONNECT request to the rules.")
                self._note(line_notes, "Squid %s: `%s` [%s] is %s; no %s rule.%s"
                           % (_loc(ha), acl.name, acl.acl_type, where, other, extra))
                return None
            values = _acl_values(it)
            if acl.acl_type == "method" and proto == "http":
                # NFW rules never see a CONNECT request, so CONNECT is dropped
                # from a mixed method list (PUT CONNECT -> PUT). A negated
                # list that becomes empty (!CONNECT) is always true here.
                values = [v for v in values if v.upper() != "CONNECT"]
                if not values:
                    continue
            clauses = [_value_clause(it, v, proto) for v in values]
            if it.negated:
                negs.extend(clauses)
            else:
                options.append(clauses)
        matches: List[str] = []
        for combo in itertools.product(*options):
            parts = list(combo) + negs
            match = _merge_buffers(parts)
            # Whether a bare pcre (no content prefilter could be added) is
            # deployable is decided by the caller's rule_check on the whole
            # rule (the shared validator's pcre-companion check), which then
            # refuses the whole line.
            match += self._resolved_domain_option(parts, ha)
            matches.append(match)
        return matches

    def _resolved_domain_option(self, parts: List[str], ha: HttpAccess) -> str:
        """With --route53-resolved-domains: the aws_route_53_resolved_domain
        option for one rule's positive dstdomain / ssl::server_name values.

        Negated domains are left to their content:! match (a negated keyword
        isn't documented). Several positive domains on one rule (DomA AND
        DomB) are listed together: the name matches already require all of
        them, so "resolved for any of them" is sound.
        """
        if not self.resolved_domains:
            return ""
        names = []
        for p in parts:
            if isinstance(p, _DomainClause) and not p.negated:
                name = ("." if p.dotted else "") + p.domain
                if name not in names:
                    names.append(name)
        if not names:
            return ""
        return ' aws_route_53_resolved_domain:"%s";' % ",".join(names)

    # -- one access line --------------------------------------------------------
    def convert(self, ha: HttpAccess) -> None:
        """Convert one access line and record its outcome for the ledger."""
        start = len(self.specs)
        self._short_reason = ""
        outcome = self._convert(ha)
        key = (ha.line_no, ha.source, ha.directive)
        self.line_outcomes[key] = outcome
        self.line_info[key] = (self._short_reason,
                               list(range(start, len(self.specs))))

    def _convert_reply(self, ha: HttpAccess, refs: List[AclRef]) -> str:
        """http_reply_access: only `allow all` (no rule needed) is handled.

        Squid checks a response only for a request it already allowed. The
        converted allow is a `pass` rule, and once a `pass` rule matches,
        AWS Network Firewall stops inspecting the whole connection, so no
        rule - whatever its position or a flowbit set before the pass - ever
        sees the response. Observed on a live firewall.
        """
        if len(refs) == 1 and not refs[0].negated and (
                refs[0].name == "all" or _is_all_acl(self.cfg.acls.get(refs[0].name))):
            if ha.action == "allow":
                self.notes.append(
                    "Squid %s: `http_reply_access allow all` is the default "
                    "permit for responses; no Suricata rule is needed." % _loc(ha))
                self._short_reason = "allow all = no rule needed"
                return NOTE_ONLY
        elif any(r.name == "all" and r.negated for r in refs):
            self.notes.append("Squid %s: contains `!all`, which never matches; "
                              "no rule." % _loc(ha))
            self._short_reason = "!all never matches"
            return NOTE_ONLY
        self._short_reason = "reply rule"
        self.not_convertible.append(
            "Squid %s not converted: http_reply_access %s - AWS Network "
            "Firewall can't enforce response checks on allowed traffic. Squid "
            "checks a response only after allowing the request, and the "
            "converted allow is a `pass` rule; once a `pass` rule matches, the "
            "firewall stops inspecting the whole connection, so a rule on the "
            "response never sees it (rule order and flowbits don't change "
            "this). Responses are let through." % (_loc(ha), ha.action))
        return NOT_CONVERTIBLE

    def _convert(self, ha: HttpAccess) -> str:
        refs, tags = _strip_annotations(ha.refs, self.cfg)
        tag = (" rule=" + ",".join(tags)) if tags else ""

        if ha.directive == "http_reply_access":
            return self._convert_reply(ha, refs)

        # Default policy lines: `deny all` / `allow all` (after annotations).
        if len(refs) == 1 and not refs[0].negated and (
                refs[0].name == "all" or _is_all_acl(self.cfg.acls.get(refs[0].name))):
            if ha.action == "deny":
                self.notes.append(
                    "Squid %s: `%s deny all` is the fail-closed DEFAULT%s. In "
                    "Suricata this is the default policy (drop/reject anything not "
                    "matched by a `pass` rule) rather than a single rule. Configure "
                    "your Suricata/NFW default policy accordingly."
                    % (_loc(ha), ha.directive, tag.replace(" rule=", " (rule=") + (")" if tag else "")))
                self._short_reason = "deny all = firewall default action"
                return NOTE_ONLY
        if any(r.name == "all" and r.negated for r in refs):
            self.notes.append("Squid %s: contains `!all`, which never matches; "
                              "no rule." % _loc(ha))
            self._short_reason = "!all never matches"
            return NOTE_ONLY

        # A non-negated condition that can never be true through the explicit
        # proxy - a loopback-only src (`localhost`), or a dst made only of
        # addresses the proxy refuses (`to_localhost`, `to_linklocal`) - means
        # the whole line (an AND) never matches and needs no rule. Removing a
        # line that never matches cannot change the policy.
        for ref in refs:
            acl = _resolve_acl(ref.name, self.cfg)
            if ref.negated or acl is None:
                continue
            if acl.acl_type == "src" and not _loopback_only(acl):
                continue
            if acl.acl_type == "dst" and not _proxy_blocked_dst(acl):
                continue
            if acl.acl_type not in ("src", "dst"):
                continue
            if acl.acl_type == "dst" and _in_any(acl, _LINKLOCAL_NETS):
                kinds = ("loopback and link-local" if _in_any(acl, _LOOPBACK_NETS)
                         else "link-local")
                ranges = ("127.0.0.0/8, 0.0.0.0, 169.254.0.0/16"
                          if kinds != "link-local" else "169.254.0.0/16, "
                          "including the instance metadata address 169.254.169.254")
                self.notes.append(
                    "Squid %s: `%s` [dst] matches %s destinations (%s). The "
                    "Network Firewall proxy refuses those targets itself "
                    "before any rule is evaluated (a bare IP address gets "
                    "HTTP 400, a host name that resolves into the range gets "
                    "HTTP 403), so this line can never match; no rule is "
                    "needed." % (_loc(ha), ref.name, kinds, ranges))
                self._short_reason = "proxy refuses %s targets" % kinds
                return NOTE_ONLY
            if acl.acl_type == "src":
                self.notes.append(
                    "Squid %s: `%s` [src] matches only requests from the Squid "
                    "server itself (a loopback address). Through AWS Network "
                    "Firewall the rules always see the client's own VPC "
                    "address, so this line can never match; no rule is needed."
                    % (_loc(ha), ref.name))
                self._short_reason = "%s = Squid server itself" % ref.name
            else:
                self.notes.append(
                    "Squid %s: `%s` [dst] matches loopback destinations "
                    "(127.0.0.0/8, 0.0.0.0). The Network Firewall proxy "
                    "refuses those targets itself before any rule is "
                    "evaluated (a bare IP address gets HTTP 400, a host name "
                    "that resolves to loopback gets HTTP 403), so this line "
                    "can never match; no rule is needed." % (_loc(ha), ref.name))
                self._short_reason = "proxy refuses loopback targets"
            return NOTE_ONLY

        # Expand groups into OR branches and validate every condition.
        try:
            branches: List[List[_Item]] = [[]]
            for ref in refs:
                if ref.name == "all" and ref.name not in self.cfg.acls:
                    continue                           # `all` adds no constraint
                sub = _expand(ref.name, ref.negated, self.cfg, ())
                branches = [a + b for a in branches for b in sub]
                _check_cap(len(branches), ref.name, "line")
            branches = [[i for i in b if i.acl.acl_type not in _ANNOTATION_TYPES]
                        for b in branches]
            for b in branches:
                for it in b:
                    _validate(it, ha.directive)
                for fld in ("src_ip", "dst_ip", "port"):
                    pos = [i for i in b if i.mapping.header_field == fld and not i.negated]
                    if len(pos) > 1:
                        raise _Unconvertible(pos[1].acl.name, pos[1].acl.acl_type,
                                             "two non-negated %s ACLs on one line "
                                             "(%s AND %s) are not converted"
                                             % (fld, pos[0].acl.name, pos[1].acl.name))
                if self.resolved_domains and any(
                        i.acl.acl_type in ("dstdom_regex", "ssl::server_name_regex")
                        and not i.negated for i in b):
                    self.regex_domain_without_r53 = True
                r53 = [i for i in b if "r53" in i.mapping.layers]
                if r53:
                    if not self.resolved_domains:
                        raise _Unconvertible(
                            r53[0].acl.name, "dst",
                            "dst host names (%s) are converted only with the "
                            "\"Use Route 53 resolved domains\" option "
                            "(--route53-resolved-domains), which uses AWS "
                            "Network Firewall's aws_route_53_resolved_domain "
                            "keyword and requires Route 53 resolved IP "
                            "validation on the firewall policy"
                            % ", ".join(r53[0].acl.values))
                    pos_domain = [i for i in b if i.acl.acl_type in _DOMAIN_TYPES
                                  and not i.negated]
                    if pos_domain:
                        raise _Unconvertible(
                            r53[0].acl.name, "dst",
                            "a dst host name and a %s condition (%s) on one line "
                            "would need two aws_route_53_resolved_domain keywords "
                            "(one per rule is allowed), and combining them would "
                            "turn AND into OR; not converted"
                            % (pos_domain[0].acl.acl_type, pos_domain[0].acl.name))
                    pos_dst = [i for i in b if i.mapping.header_field == "dst_ip"
                               and not i.negated]
                    if len(r53) > 1 or pos_dst:
                        other = (r53[1] if len(r53) > 1 else pos_dst[0]).acl.name
                        raise _Unconvertible(
                            r53[0].acl.name, "dst",
                            "two non-negated dst ACLs on one line (%s AND %s) "
                            "are not converted" % (r53[0].acl.name, other))
        except _Unconvertible as u:
            self.not_convertible.append(
                "Squid %s not converted: contains %s [%s] - %s"
                % (_loc(ha), u.acl_name, u.acl_type, u.reason))
            self._short_reason = _short_reason(u)
            return NOT_CONVERTIBLE

        # Plan every rule first (no side effects), then emit. Clause building
        # can also find a condition that cannot be deployed (for example a
        # regex NFW will not accept), so it is guarded the same way.
        line_notes: List[str] = []
        planned: List[Tuple[List[_Item], Optional[str], List[str]]] = []
        try:
            for b in branches:
                allowed = self._allowed_wire(b, ha)
                app = [i for i in b if "header" not in i.mapping.layers
                       and "proto" not in i.mapping.layers
                       and "r53" not in i.mapping.layers]
                for it in app:
                    if it.mapping.convertibility == PARTIAL:
                        self._note(line_notes, "Squid %s: `%s` [%s] converted "
                                   "APPROXIMATELY - %s"
                                   % (_loc(ha), it.acl.name, it.acl.acl_type,
                                      it.mapping.note))
                if not app:
                    planned.append((b, None, [""], allowed))
                    continue
                if allowed is not None and allowed & _NO_HTTP_BUFFERS:
                    bad = sorted(allowed & _NO_HTTP_BUFFERS)
                    if not allowed - _NO_HTTP_BUFFERS:
                        # Nothing expressible at all for this line.
                        raise _Unconvertible(
                            app[0].acl.name, app[0].acl.acl_type,
                            "the line selects protocol %s via `proto`, which "
                            "carries no HTTP buffers, so this condition cannot "
                            "be expressed there" % ", ".join(bad))
                    self._note(line_notes,
                               "Squid %s: the line's `proto` condition also "
                               "covers %s, but `%s` [%s] has no %s equivalent, "
                               "so %s requests matching this line are NOT "
                               "covered by the generated rules."
                               % (_loc(ha), ", ".join(bad), app[0].acl.name,
                                  app[0].acl.acl_type, ", ".join(bad),
                                  ", ".join(bad)))
                variants = []
                for proto in ("http", "tls"):
                    matches = self._variant(app, proto, ha, line_notes)
                    if matches:
                        variants.append((proto, matches))
                # Pair the rules: the http and tls rule for the same value
                # (e.g. one domain) are emitted next to each other instead of
                # all http rules followed by all tls rules. Both variants are
                # built from the same ACL values in the same order, so index
                # i is the same value in each. Every rule of one Squid line
                # has the same action, so this order can't change the policy.
                longest = max((len(m) for _p, m in variants), default=0)
                for i in range(longest):
                    for proto, matches in variants:
                        if i < len(matches):
                            planned.append((b, proto, [matches[i]], allowed))
        except _Unconvertible as u:
            self.not_convertible.append(
                "Squid %s not converted: contains %s [%s] - %s"
                % (_loc(ha), u.acl_name, u.acl_type, u.reason))
            self._short_reason = _short_reason(u)
            return NOT_CONVERTIBLE
        total = sum(len(p[2]) for p in planned)
        if total > _MAX_RULES_PER_LINE:
            self.not_convertible.append(
                "Squid %s not converted: expands to %d rules (limit %d)"
                % (_loc(ha), total, _MAX_RULES_PER_LINE))
            self._short_reason = "too many rules"
            return NOT_CONVERTIBLE
        if total == 0:
            self.notes.extend(line_notes)
            self.notes.append("Squid %s: produced no Suricata rule (its "
                              "conditions can only be evaluated by Squid)." % _loc(ha))
            self._short_reason = "only Squid can evaluate it"
            return NOTE_ONLY

        # Build the line's rules with every side effect captured, so a line
        # the rule check rejects leaves no trace (no variable, note or flag).
        saved = (self.registry.snapshot(), list(self.notes),
                 self.http_only_used, self.r53_used)
        line_specs: List[_RuleSpec] = []
        base_action = _verdict_action(ha.action, self.deny_action)
        for b, proto, matches, allowed in planned:
            src = self._render_field([i for i in b if i.mapping.header_field == "src_ip"])
            dst = self._render_field([i for i in b if i.mapping.header_field == "dst_ip"])
            port = self._render_field([i for i in b if i.mapping.header_field == "port"])
            if proto == "http" and any(i.mapping.layers == ["http"] for i in b):
                # An HTTP-only condition (URL, method, header, MIME type,
                # status): see the TLS-inspection / HTTP/2 note in emit().
                self.http_only_used = True
            r53 = _r53_clause(b)
            if r53:
                self.r53_used = True
            r53_opt = r53 + " " if r53 else ""
            for match in matches:
                if "aws_route_53_resolved_domain" in match:
                    self.r53_used = True
                for wire in _wire_protocols(proto, allowed):
                    action = base_action
                    if not is_reject_allowed(action, wire):
                        # NFW accepts reject on a fixed set of protocols only
                        # (e.g. not ftp): block with drop instead.
                        action = "drop"
                        note = ("AWS Network Firewall doesn't support `reject` on "
                                "`%s`, so those rules use `drop`. The traffic is "
                                "still blocked; the client times out instead of "
                                "receiving a reset." % wire)
                        if note not in self.notes:
                            self.notes.append(note)
                    head = "%s %s %s any -> %s %s" % (action, wire, src,
                                                      dst, port)
                    # Request-side buffers (http.host, tls.sni, http.uri,
                    # ...) are client-to-server, and flow:to_server is the
                    # AWS NFW best-practice form. The server certificate is
                    # sent server-to-client, so a tls.cert_fingerprint rule
                    # must not be restricted to to_server.
                    flow = ("" if "tls.cert_fingerprint" in match
                            else "flow:to_server; ")
                    opts = flow + (match + " " if match else "") + r53_opt
                    label = "%s %s" % (ha.action, wire)
                    line_specs.append(_RuleSpec(
                        head=head, opts=opts, label=label, loc=_loc(ha),
                        tag=tag, action=action, protocol=wire,
                        line_no=ha.line_no, source=ha.source,
                        alert=self.alert_on_pass and action == "pass"))

        # Rule_Check: every rule in its final form (alert-on-pass and msg
        # applied, placeholder SID). One error refuses the whole line.
        for spec in line_specs:
            errors = list(self.rule_check(spec.render(_PLACEHOLDER_SID)) or [])
            if errors:
                (registry_state, notes, http_only, r53_used) = saved
                self.registry.restore(registry_state)
                self.notes[:] = notes
                self.http_only_used, self.r53_used = http_only, r53_used
                self.not_convertible.append(
                    "Squid %s not converted: rejected by the rule validator: "
                    "%s (rule: %s)" % (_loc(ha), errors[0],
                                       spec.render(_PLACEHOLDER_SID)))
                self._short_reason = "rejected by validator"
                return NOT_CONVERTIBLE
        # The line's own notes go before the notes its rules produced, as
        # they always have.
        at = len(saved[1])
        self.notes[at:at] = line_notes
        self.specs.extend(line_specs)
        if ha.action == "allow" and any(
                i.mapping.header_field == "dst_ip" and not i.negated
                for b, _p, _m, _a in planned for i in b):
            self.dst_address_lines.append(_loc(ha))
        if any(spec.protocol == "ftp" for spec in line_specs):
            self.ftp_used = True
        return EMITTED


def _wire_protocols(proto: Optional[str],
                    allowed: Optional[set] = None) -> List[str]:
    """Which Suricata rule protocols one planned match is emitted for.

    No `http2` rules are generated. Without TLS inspection, HTTP/2 runs inside
    TLS and is matched by the tls.sni rule; cleartext HTTP/2 (h2c) is rare.
    With TLS inspection, AWS Network Firewall still matches tls.sni on
    decrypted traffic, so domain rules keep working; only HTTP-level
    conditions on decrypted HTTP/2 would need http2 rules, and those use
    different buffers (AWS's example matches the host with http.request_header
    and the :authority pseudo-header, because NFW doesn't support HTTP/2
    keyword overloading). That case is reported, not generated.

    `allowed` is the restriction a `proto` ACL puts on the line (None when the
    line has no `proto` condition).
    """
    if proto is None:
        # Header-only conditions (addresses / ports, optionally a resolved
        # domain). Squid's http_access only ever governs traffic sent through
        # the proxy - HTTP requests and CONNECT tunnels, i.e. web traffic - so
        # these become an http + tls pair rather than a tcp rule, which would
        # also pass (or block) SSH, SMTP and every other TCP protocol Squid
        # never saw. Non-web traffic is left to the firewall policy's default
        # action. A `proto` restriction selects the protocols instead.
        if allowed is not None:
            return [w for w in _ALL_WIRE if w in allowed]
        return ["http", "tls"]
    else:
        wires = [proto]           # http or tls
    if allowed is not None:
        wires = [w for w in wires if w in allowed]
    return wires


def _loc(ha: HttpAccess) -> str:
    return where(ha.line_no, ha.source)


def _msg_safe(text: str) -> str:
    """Keep msg:"..." valid: no quotes, semicolons or backslashes."""
    return re.sub(r'["\\;]', "_", text)


def _is_catch_all(ha: HttpAccess, cfg: ParsedConfig) -> bool:
    """True when an access line matches everything (`all`, after annotations)."""
    refs, _tags = _strip_annotations(ha.refs, cfg)
    return (len(refs) == 1 and not refs[0].negated and (
        refs[0].name == "all" or _is_all_acl(cfg.acls.get(refs[0].name))))


def _implicit_default(cfg: ParsedConfig) -> Tuple[List[str], List[str]]:
    """(notes, divergences) for Squid's implicit default.

    When no access line matches, Squid applies the OPPOSITE of the last line
    (no lines at all: http_access denies, http_reply_access allows). The
    recommended NFW default actions drop unmatched requests and leave
    responses alone, so the two only agree in some cases; the others are
    reported as policy divergences.
    """
    notes: List[str] = []
    divergences: List[str] = []

    req = cfg.http_access
    if not req:
        notes.append(
            "The config has no http_access lines, so Squid denies every "
            "request. That matches an NFW firewall policy whose default action "
            "drops unmatched traffic.")
    else:
        last = req[-1]
        if not _is_catch_all(last, cfg):
            if last.action == "deny":
                divergences.append(
                    "Squid %s: the last http_access line is a `deny` that "
                    "does not match everything, so Squid ALLOWS any request "
                    "that no line matches (the implicit default is the "
                    "opposite of the last line). With the recommended NFW "
                    "default action (drop unmatched traffic) the firewall "
                    "BLOCKS that traffic instead. Add an explicit "
                    "`http_access allow all` at the end of squid.conf if the "
                    "allow is intended (it converts to a catch-all pass "
                    "rule), or `http_access deny all` if it is not."
                    % _loc(last))
            else:
                notes.append(
                    "Squid %s: the last http_access line is an `allow`, so "
                    "Squid denies any request no line matches (the implicit "
                    "default is the opposite of the last line). That matches "
                    "an NFW firewall policy whose default action drops "
                    "unmatched traffic." % _loc(last))
        # A trailing `allow all` is converted to a catch-all pass rule and a
        # trailing `deny all` is the default-action note, so both agree.

    # http_reply_access lines are not convertible (each one is reported), so
    # Squid's implicit reply default needs no separate divergence.
    return notes, divergences


def _proxy_deployment_notes(le: "_LineEmitter") -> List[str]:
    """Notes for AWS Network Firewall's explicit-proxy deployment, which the
    output is always written for (observed behaviour on a live proxy-mode
    firewall)."""
    notes = [
        "Proxy deployment: rules see the client's own IP address as the "
        "source and the real destination address and port (443, 80, ...) - "
        "never the proxy listener ports - so src, dst and port conversions "
        "are unchanged. HTTPS is matched by tls.sni; plain HTTP by "
        "http.host / http.uri, where http.uri is the path only.",
        "Proxy deployment: the proxy connects only to the address it resolves "
        "itself for the requested host name; it does not use an IP the client "
        "supplies. A client cannot send a blocked host to an allowed site's "
        "IP address, and cannot reach an allowed name's SNI or Host header at "
        "a different server. So the SNI/Host spoofing that a transparent "
        "deployment is exposed to does not arise here (verified on a live "
        "proxy-mode firewall).",
        "Proxy deployment: the proxy adds a `Via: 1.1 AWS Network Firewall` "
        "request header. A Squid rule that matched on the `Via` header would "
        "not see the client's original value; rules on other headers, the "
        "user agent and the URL path see the client's values unchanged "
        "(verified on a live proxy-mode firewall).",
        "Proxy deployment: the proxy refuses every request to a bare IP "
        "address target before any rule is evaluated (for example "
        "`http://192.0.2.10/` or `CONNECT 192.0.2.10:443` gets HTTP 400 "
        "\"bare IP address targets are not permitted\"), and a host name "
        "that resolves to a loopback or link-local address (127.0.0.0/8, "
        "169.254.0.0/16) gets HTTP 403. Private (RFC 1918) destinations are "
        "not refused. Clients must "
        "request host names: a request to an IP address that Squid allowed "
        "now fails. Rules with destination addresses (`dst` ACLs) "
        "still work: they match the address the proxy resolved for the "
        "requested host name.",
    ]
    if le.dst_address_lines:
        notes.append(
            "Proxy deployment: %s use destination addresses (`dst` ACLs). "
            "The rules match requests for host names that resolve into those "
            "addresses; requests that name the IP address directly are "
            "refused by the proxy, so that part of the Squid policy is not "
            "reproduced (it can only block more, never allow more)."
            % _join_locations(le.dst_address_lines))
    uses_reject = any(spec.action == "reject" for spec in le.specs)
    if uses_reject:
        notes.append(
            "Proxy deployment: `reject` does not reach the client as a TCP "
            "reset. The proxy answers CONNECT with 200 first, so a rejected "
            "HTTPS connection fails during the TLS handshake, and a rejected "
            "plain-HTTP request gets `502 Bad Gateway` from the proxy. The "
            "traffic is still blocked.")
    if le.ftp_used:
        notes.append(
            "Proxy deployment: this config converts a `proto FTP` line to "
            "`ftp` rules, but the proxy front-ends FTP over HTTP - an "
            "`ftp://` request through the proxy is carried to the origin on "
            "an HTTP connection, which the firewall sees as `http`, not "
            "`ftp` (observed on a live proxy-mode firewall). The `ftp` rules "
            "will therefore not match proxied FTP, and that traffic falls to "
            "the firewall policy's default action. Review FTP handling by "
            "hand.")
    return notes


def _join_locations(locs: List[str]) -> str:
    """'Squid line 3' / 'Squid lines 3, 7 and conf.d/a.conf line 2'."""
    if len(locs) == 1:
        return "Squid " + locs[0]
    return "Squid " + ", ".join(locs[:-1]) + " and " + locs[-1]


def _proxy_dns_spec(alert_on_pass: bool) -> _RuleSpec:
    """The generated DNS pass rule for the proxy's own name lookups."""
    return _RuleSpec(head=_PROXY_DNS_RULE_HEAD, opts="flow:to_server; ",
                     label="allow dns", loc="proxy deployment name resolution",
                     tag="", action="pass", protocol="dns", line_no=None,
                     source=None, origin="generated", alert=alert_on_pass,
                     msg_override=PROXY_DNS_MSG)


def emit(cfg: ParsedConfig, rule_check: RuleCheck,
         deny_action: str = "reject", alert_on_pass: bool = True,
         resolved_domains: bool = False) -> EmitResult:
    """Convert a parsed config.

    rule_check: called with every rule in its final form (placeholder SID);
    any returned error makes the rule's whole Squid line not convertible.
    There is no built-in checker: the caller supplies one (the Generator
    passes its shared rule validator; pure-conversion tests pass
    `lambda line: []`).

    deny_action: "reject" (default) or "drop" for a Squid `deny`.

    alert_on_pass: add `alert;` to every `pass` rule so allowed traffic is
    logged.

    resolved_domains (--route53-resolved-domains): domain rules also carry
    aws_route_53_resolved_domain, so they match only when the Route 53
    Resolver resolved the destination IP for the name, and dst host names are
    converted. Requires Route 53 resolved IP validation on the firewall
    policy. Off: no rule uses the keyword and dst host names are not
    convertible.

    The output is always for the explicit-proxy deployment: the proxy DNS
    pass rule is always the first rule.
    """
    if deny_action not in DENY_ACTIONS:
        raise ValueError("deny_action must be one of %s, not %r"
                         % (", ".join(DENY_ACTIONS), deny_action))
    if rule_check is None:
        raise TypeError("rule_check is required")
    le = _LineEmitter(cfg, deny_action, alert_on_pass, rule_check,
                      resolved_domains=resolved_domains)
    for ha in list(cfg.http_access) + list(cfg.http_reply_access):
        le.convert(ha)

    # First, so no converted deny rule can catch the proxy's own lookups.
    dns_spec = _proxy_dns_spec(alert_on_pass)
    generated_problems: List[str] = []
    dns_errors = list(rule_check(dns_spec.render(_PLACEHOLDER_SID)) or [])
    if dns_errors:
        generated_problems.append(
            "The generated proxy DNS rule was rejected by the rule "
            "validator: %s. This is a converter defect; please report it."
            % dns_errors[0])
    specs = [dns_spec] + list(le.specs)
    deployment_notes = _proxy_deployment_notes(le)
    line_info = {key: (reason, [i + 1 for i in idx])
                 for key, (reason, idx) in le.line_info.items()}

    # SIDs are assigned once every rule body is known, so each one can be
    # derived from its own content instead of its position.
    allocator = ContentSidAllocator()
    sids = [allocator.assign(spec.semantic_key()) for spec in specs]
    rules = [spec.render(sid) for spec, sid in zip(specs, sids)]

    unhandled = [
        "Squid %s: `%s` - not converted (only http_access and "
        "http_reply_access are converted)" % (where(ln, src), d)
        for ln, d, src in cfg.unhandled
    ]
    # One entry per flagged directive, listing every line it appears on
    # (auth_param, for example, usually spans several lines).
    flagged: "OrderedDict[Tuple[str, str], List[str]]" = OrderedDict()
    for ln, d, src, reason in cfg.flagged:
        flagged.setdefault((d, reason), []).append(where(ln, src))
    unhandled.extend(
        "Squid %s: `%s` - not converted: %s." % (", ".join(locs), d, reason)
        for (d, reason), locs in flagged.items())
    default_notes, default_divergences = _implicit_default(cfg)
    posture = sslbump.analyse(cfg)
    r53_notes: List[str] = []
    if le.r53_used:
        r53_notes.append(
            "--route53-resolved-domains: domain rules (dstdomain, "
            "ssl::server_name) and dst host names use "
            "aws_route_53_resolved_domain, which matches only when the Amazon "
            "Route 53 Resolver resolved the connection's destination IP for "
            "that name. This is stricter than Squid, which checks the name "
            "only: a client sending an allowed name to an unrelated IP no "
            "longer matches. PREREQUISITES: enable Route 53 resolved IP "
            "validation on the firewall policy, with a Route 53 Resolver DNS "
            "Firewall rule group (it needs no rules) associated with the VPCs "
            "behind the firewall, and make sure clients resolve DNS through "
            "the Route 53 Resolver. Without the policy setting the policy "
            "reports ROUTE53_RESOLVED_IP_VALIDATION_MISSING and these rules "
            "are inactive. In an Availability Zone that doesn't support the "
            "feature, NFW drops all traffic these rules inspect, even for "
            "`pass` rules, so every allowed domain would be blocked there - "
            "check the DnsAzUnavailableFlows metric is zero first. The policy "
            "setting's own Action applies to ALL traffic that fails "
            "validation (including connections to hard-coded IPs); keeping "
            "it at Alert and relying on these rules is likely workable but "
            "has not been verified.")
    if le.regex_domain_without_r53:
        r53_notes.append(
            "--route53-resolved-domains: regex domain rules (dstdom_regex, "
            "ssl::server_name_regex) carry no aws_route_53_resolved_domain "
            "keyword, because it takes names, not regular expressions. They "
            "check the name only; the policy-level resolved IP validation "
            "check still applies to them if its Action enforces.")
    if resolved_domains:
        r53_notes.append(
            "--route53-resolved-domains with the proxy deployment: the proxy "
            "resolves each name itself and connects to what it resolved, so "
            "the gap this option closes (a client sending an allowed name to "
            "an unrelated IP) does not arise there. Partly verified on a live "
            "proxy-mode firewall: resolved IP validation (with the "
            "169.254.169.253/32 bypass and the proxy's own lookups) did not "
            "break normal traffic in Alert or Drop mode, but because the "
            "proxy only ever connects to addresses it just resolved, the "
            "keyword's extra protection is limited here. Keeping validation "
            "at Alert and relying on these rules is workable.")
    http2_notes: List[str] = []
    http2_divergences: List[str] = []
    if le.http_only_used:
        http2_notes.append(
            "HTTP-level conditions (URL, method, headers, MIME type, status) "
            "are emitted as `http` rules only. They apply to plain HTTP; on "
            "HTTPS they apply only with NFW TLS inspection, and even then not "
            "to HTTP/2, because NFW doesn't support HTTP/2 keyword overloading: "
            "matching decrypted HTTP/2 needs extra `http2` rules on HTTP/2 "
            "buffers (e.g. http.request_header with `authority: <host>`), which "
            "the converter does not generate. Domain rules are unaffected: "
            "tls.sni still matches decrypted traffic.")
        if posture.decrypts:
            http2_divergences.append(
                "The source Squid decrypts HTTPS (`ssl_bump bump`), and some "
                "converted rules use HTTP-only conditions (URL, path, method, "
                "header, MIME type). On HTTPS those rules enforce only after "
                "AWS Network Firewall TLS inspection is configured for the "
                "clients' HTTPS traffic (see Firewall prerequisites); without "
                "it they match plain HTTP only.")
            http2_divergences.append(
                "The source Squid decrypts HTTPS (`ssl_bump bump`), so its "
                "URL/method/header/MIME conditions applied to all decrypted "
                "HTTPS, including HTTP/2. The converted `http` rules do not "
                "cover HTTP/2, even with NFW TLS inspection enabled; those "
                "conditions would need additional `http2` rules.")
    return EmitResult(rules=rules,
                      notes=deployment_notes + list(cfg.notes) + le.notes
                      + le.registry.notes + r53_notes + http2_notes + default_notes
                      + posture.notes,
                      not_convertible=le.not_convertible,
                      variables=le.registry.variables, unhandled=unhandled,
                      problems=list(cfg.problems),
                      line_outcomes=dict(le.line_outcomes),
                      divergences=default_divergences + http2_divergences
                      + list(posture.divergences),
                      posture=posture,
                      sslbump_classification=sslbump.classification_report(
                          acl.acl_type for acl in cfg.acls.values()),
                      resolved_domains=resolved_domains,
                      deny_action=deny_action, alert_on_pass=alert_on_pass,
                      specs=specs, sids=sids, line_info=line_info,
                      http_only_used=le.http_only_used, r53_used=le.r53_used,
                      generated_problems=generated_problems)
