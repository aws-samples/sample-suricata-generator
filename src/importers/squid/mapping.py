"""
ACL type -> Suricata keyword mapping table.

Squid is an HTTP/HTTPS (Layer 7) proxy. Its ACL "types" are MATCH conditions
(what to look at), not verdicts. Suricata rule "actions" (pass/drop/reject/alert)
are the verdicts; Suricata match keywords (http.host, tls.sni, ...) are the
equivalent of Squid ACL types.

This table classifies each Squid ACL type into one of:
  - FULL    : cleanly convertible to a Suricata match
  - PARTIAL : approximate / limited equivalent, emitted with a caveat
  - NONE    : no Suricata rule equivalent (proxy-layer-only or L2/internal)

For FULL/PARTIAL entries we describe how to emit the match. The emitter uses
`layers` to decide whether to produce an http rule, a tls rule, or both.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional


# Convertibility classification
FULL = "FULL"
PARTIAL = "PARTIAL"
NONE = "NONE"


@dataclass
class AclMapping:
    squid_type: str
    convertibility: str
    # Which Suricata app-layer protocols this maps to. Used by the emitter to
    # decide how many rules to produce. "header" means it belongs in the rule
    # header (src/dst IP, ports) rather than as an app-layer keyword.
    layers: List[str] = field(default_factory=list)
    # Human-readable note shown in output (especially important for PARTIAL/NONE).
    note: str = ""
    # For header-type matches: which part of the rule header this fills.
    header_field: Optional[str] = None  # "src_ip" | "dst_ip" | "port"
    # For app-layer matches: the Suricata sticky-buffer keyword to use.
    keyword: Optional[str] = None  # e.g. "http.host", "tls.sni", "http.uri"
    # Whether the values are regex in Squid (=> emit pcre in Suricata).
    is_regex: bool = False
    # Only meaningful on the server response (http_reply_access).
    reply_only: bool = False
    # For header-regex types with a fixed header (referer_regex -> Referer).
    fixed_header: Optional[str] = None


# The core mapping table. Keyed by Squid ACL type.
MAPPINGS = {
    # ---- Header-level matches (network 3/4-tuple) ----
    "src": AclMapping(
        "src", FULL, layers=["header"], header_field="src_ip",
        note="Client IP/CIDR -> Suricata rule header source address.",
    ),
    "dst": AclMapping(
        "dst", FULL, layers=["header"], header_field="dst_ip",
        note="Destination IP/CIDR -> Suricata rule header dest address. "
             "In Squid this may trigger DNS; Suricata matches the literal IP.",
    ),
    "localip": AclMapping(
        "localip", NONE,
        note="Squid listening IP the client connected to; NFW rules never see "
             "a listener address (the transparent deployment has none, and "
             "in the proxy deployment rules see the real destination, not "
             "the proxy endpoint).",
    ),
    "port": AclMapping(
        "port", FULL, layers=["header"], header_field="port",
        note="Destination port(s) -> Suricata rule header dest port.",
    ),
    "localport": AclMapping(
        "localport", NONE,
        note="Squid listening port (e.g. 3128); NFW rules never see a "
             "listener port (the transparent deployment has none, and in the "
             "proxy deployment rules see the real destination port such as "
             "443 or 80, not the 3128/8443 listener).",
    ),

    # ---- HTTP app-layer matches ----
    "method": AclMapping(
        "method", FULL, layers=["http"], keyword="http.method",
        note="HTTP method -> http.method. HTTP only (HTTPS method is hidden "
             "unless SslBump is used). CONNECT is the HTTPS tunnel setup method.",
    ),
    "url_regex": AclMapping(
        "url_regex", PARTIAL, layers=["http"], keyword="http.uri", is_regex=True,
        note="Squid matches the full URL (scheme+host+path); Suricata http.uri "
             "is the path+query only, so patterns anchored on scheme/host will "
             "not match. HTTP only.",
    ),
    "urlpath_regex": AclMapping(
        "urlpath_regex", FULL, layers=["http"], keyword="http.uri", is_regex=True,
        note="Regex on URL path -> pcre on http.uri. HTTP only.",
    ),
    "urllogin": AclMapping(
        "urllogin", NONE,
        note="URL login field (user:pass@host); it is not part of the on-wire "
             "request URI, so there is no Suricata buffer to match.",
    ),
    "req_header": AclMapping(
        "req_header", FULL, layers=["http"], keyword="http.header", is_regex=True,
        note="Regex on a named request header -> header-anchored pcre on "
             "http.header. HTTP only.",
    ),
    "browser": AclMapping(
        "browser", FULL, layers=["http"], keyword="http.user_agent", is_regex=True,
        note="User-Agent regex -> http.user_agent. HTTP only.",
    ),
    "referer_regex": AclMapping(
        "referer_regex", FULL, layers=["http"], keyword="http.header", is_regex=True,
        fixed_header="Referer",
        note="Referer regex -> header-anchored pcre on http.header. HTTP only.",
    ),
    "req_mime_type": AclMapping(
        "req_mime_type", FULL, layers=["http"], keyword="http.content_type",
        is_regex=True,
        note="Request Content-Type regex -> pcre on http.content_type. HTTP only.",
    ),
    # Reply-only types are used in http_reply_access, which is not converted:
    # once a `pass` rule matches, AWS Network Firewall stops inspecting the
    # connection, so a rule on the response never sees allowed traffic.
    "rep_mime_type": AclMapping(
        "rep_mime_type", NONE, reply_only=True,
        note="Reply Content-Type; http_reply_access is not converted (AWS "
             "Network Firewall doesn't inspect responses on allowed traffic).",
    ),
    "http_status": AclMapping(
        "http_status", NONE, reply_only=True,
        note="Reply status code; http_reply_access is not converted (AWS "
             "Network Firewall doesn't inspect responses on allowed traffic).",
    ),
    "rep_header": AclMapping(
        "rep_header", NONE, reply_only=True,
        note="Reply header regex; http_reply_access is not converted (AWS "
             "Network Firewall doesn't inspect responses on allowed traffic).",
    ),

    # ---- Group ACLs (expanded by the emitter) ----
    "any-of": AclMapping(
        "any-of", FULL, layers=["group"],
        note="Group: matches if any member ACL matches (expanded into OR branches).",
    ),
    "all-of": AclMapping(
        "all-of", FULL, layers=["group"],
        note="Group: matches if all member ACLs match (inlined as AND).",
    ),

    # ---- Domain / host matches (work on both HTTP host and TLS SNI) ----
    "dstdomain": AclMapping(
        "dstdomain", FULL, layers=["http", "tls"], keyword="http.host",
        note="Destination domain -> http.host (HTTP) AND tls.sni (HTTPS). "
             "SNI-based, no decryption needed.",
    ),
    "dstdom_regex": AclMapping(
        "dstdom_regex", FULL, layers=["http", "tls"], keyword="http.host",
        is_regex=True,
        note="Destination domain regex -> pcre on http.host AND tls.sni.",
    ),
    "ssl::server_name": AclMapping(
        "ssl::server_name", FULL, layers=["tls"], keyword="tls.sni",
        note="TLS server name (SNI / cert) -> tls.sni. No decryption needed.",
    ),
    "ssl::server_name_regex": AclMapping(
        "ssl::server_name_regex", FULL, layers=["tls"], keyword="tls.sni",
        is_regex=True,
        note="TLS server name regex -> pcre on tls.sni.",
    ),

    # ---- Weak / no equivalent (source domain relies on reverse DNS) ----
    "srcdomain": AclMapping(
        "srcdomain", PARTIAL, layers=[], note=(
            "Client reverse-DNS name. No native Suricata analog "
            "(Suricata does not reverse-resolve client IPs). Enforce at proxy."),
    ),
    "srcdom_regex": AclMapping(
        "srcdom_regex", PARTIAL, layers=[], note=(
            "Client reverse-DNS regex. No native Suricata analog."),
    ),

    # ---- No Suricata rule equivalent (proxy-layer / internal / L2) ----
    "proxy_auth": AclMapping("proxy_auth", NONE, note="Proxy authentication; proxy-layer only."),
    "proxy_auth_regex": AclMapping("proxy_auth_regex", NONE, note="Proxy authentication; proxy-layer only."),
    "ext_user": AclMapping("ext_user", NONE, note="External-helper username; proxy-layer only."),
    "ext_user_regex": AclMapping("ext_user_regex", NONE, note="External-helper username; proxy-layer only."),
    "external": AclMapping("external", NONE, note="External ACL helper; no Suricata equivalent."),
    "ident": AclMapping("ident", NONE, note="Client identity via ident protocol (RFC 1413); proxy-layer only (in Squid 6, removed in Squid 7)."),
    "ident_regex": AclMapping("ident_regex", NONE, note="Client ident regex (RFC 1413); proxy-layer only (in Squid 6, removed in Squid 7)."),
    "maxconn": AclMapping("maxconn", NONE, note="Per-client connection count; closest is Suricata threshold/detection_filter (not a header match)."),
    "max_user_ip": AclMapping("max_user_ip", NONE, note="User-from-N-IPs; no Suricata analog."),
    "time": AclMapping("time", NONE, note="Time-of-day scheduling; no Suricata rule analog."),
    "random": AclMapping("random", NONE, note="Probabilistic match; no Suricata analog."),
    "note": AclMapping("note", NONE, note="Squid transaction annotation; internal only."),
    "annotate_transaction": AclMapping("annotate_transaction", NONE, note="Squid annotation side-effect; internal only."),
    "annotate_client": AclMapping("annotate_client", NONE, note="Squid annotation side-effect; internal only."),
    "tag": AclMapping("tag", NONE, note="External-helper tag; internal only."),
    "snmp_community": AclMapping("snmp_community", NONE, note="SNMP agent access; not traffic filtering."),
    "peername": AclMapping("peername", NONE, note="cache_peer selection; proxy-internal."),
    "peername_regex": AclMapping("peername_regex", NONE, note="cache_peer selection; proxy-internal."),
    "myportname": AclMapping("myportname", NONE, note="Named *_port; proxy-internal (NFW rules never see which listener a request arrived on)."),
    "proto": AclMapping(
        "proto", FULL, layers=["proto"],
        note="URL scheme of the request. Not a match keyword: it selects which "
             "Suricata rule PROTOCOL the line applies to - HTTP -> http, "
             "HTTPS -> tls, FTP -> ftp. Other schemes (CACHE_OBJECT, URN, "
             "WHOIS, ICP, ...) are proxy-internal and are reported.",
    ),
    "arp": AclMapping("arp", NONE, note="Client MAC (L2); Suricata rules cannot act on ARP/MAC."),
    "eui64": AclMapping("eui64", NONE, note="Client EUI-64 (L2); no Suricata rule analog."),
    "src_as": AclMapping("src_as", NONE, note="Autonomous System number; no Suricata analog."),
    "dst_as": AclMapping("dst_as", NONE, note="Autonomous System number; no Suricata analog."),
    "hier_code": AclMapping("hier_code", NONE, reply_only=True, note="Squid hierarchy code (how Squid fetched the object); internal only."),
    "user_cert": AclMapping("user_cert", PARTIAL, layers=[], note="Client cert attributes; limited Suricata tls cert keyword support."),
    "ca_cert": AclMapping("ca_cert", PARTIAL, layers=[], note="Issuing CA attributes; limited Suricata support."),
    "server_cert_fingerprint": AclMapping("server_cert_fingerprint", PARTIAL, layers=["tls"], keyword="tls.cert_fingerprint", note="Server cert SHA1 fingerprint -> tls.cert_fingerprint (lowercased). Squid needs SslBump to see the cert; Suricata sees it in TLS <=1.2 handshakes only (TLS 1.3 encrypts it)."),
    "at_step": AclMapping("at_step", NONE, note="SslBump processing step; proxy-internal."),
    "ssl_error": AclMapping("ssl_error", NONE, note="SSL validation error; proxy-internal."),
    "connections_encrypted": AclMapping("connections_encrypted", NONE, note="All-messages-over-TLS state; proxy-internal."),
    "clientside_mark": AclMapping("clientside_mark", NONE, note="CONNMARK; proxy/netfilter internal."),
    "client_connection_mark": AclMapping("client_connection_mark", NONE, note="CONNMARK; proxy/netfilter internal."),
    "transaction_initiator": AclMapping("transaction_initiator", NONE, note="Transaction initiator; proxy-internal."),
    "has": AclMapping("has", NONE, note="Transaction component presence; proxy-internal."),
    "adaptation_service": AclMapping("adaptation_service", NONE, note="ICAP/eCAP service used; proxy-internal."),
    "squid_error": AclMapping("squid_error", NONE, note="Squid's own ERR_* error condition for the transaction; proxy-internal, no Suricata analog. (Not listed in the Squid 5-7 acl reference.)"),
}

# Old names Squid used for localip / localport. They are no longer in the
# Squid 6 manual, but old configs still contain them; give them the same
# reason as the current names instead of "unknown ACL type".
for _old, _new in (("myip", "localip"), ("myport", "localport")):
    MAPPINGS[_old] = AclMapping(
        _old, MAPPINGS[_new].convertibility,
        note="Old name for %s. %s" % (_new, MAPPINGS[_new].note))


def lookup(squid_type: str) -> Optional[AclMapping]:
    """Return the mapping for a Squid ACL type, or None if unknown."""
    return MAPPINGS.get(squid_type)
