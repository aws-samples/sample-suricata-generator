"""
SslBump posture analysis.

Whether a Squid config DECRYPTS HTTPS decides what its url/path/method/header/
MIME ACLs actually enforce:

  * `ssl_bump bump`   - Squid sees inside HTTPS, so those ACLs apply to HTTPS.
  * `ssl_bump splice` - the tunnel stays encrypted; only SNI-level ACLs apply.

The converter reads this from the source config rather than from a flag, so
HTTPS coverage is correct out of the box. A bumping config whose converted
output covered only plain HTTP would UNDER-ENFORCE the policy, which is the
silent narrowing this tool exists to prevent.

Where the two sides cannot agree, the difference is REPORTED (requirement (c)):
diverge when necessary, never silently. Two divergences arise in practice:

  1. A source config that does NOT bump, converted for a firewall that will
     decrypt: the converted rules then enforce MORE than Squid did.
  2. `ssl_bump splice <domains>`: Squid exempts domains from decryption by SNI,
     but an AWS Network Firewall TLS inspection scope is 5-tuple only
     (protocol, source, source port, destination, destination port) with no
     domain dimension, so the exemption cannot be expressed as configuration.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .parser import ParsedConfig, SslBumpLine, where

# Postures
BUMPING = "bumping"          # decrypts everything it inspects
NOT_BUMPING = "not-bumping"  # never decrypts
MIXED = "mixed"              # decrypts, with explicit splice exemptions

# ssl_bump actions that mean "decrypt from here on".
_DECRYPTING = {"bump", "stare"}
_ALL_ACLS = {"all", ""}

# Evidence for rejecting destination-CIDR carve-outs as a splice substitute:
# one spliced domain resolved to three different addresses within an hour
# during lab testing.
_CDN_EVIDENCE = ("CDN-fronted domains do not have stable addresses - "
                 "checkip.amazonaws.com resolved to 34.227.92.189, "
                 "100.56.52.64 and 184.197.238.144 within one hour of lab "
                 "testing - so destination-CIDR carve-outs cannot reproduce "
                 "an SNI-based splice reliably")


@dataclass
class Posture:
    posture: str = NOT_BUMPING
    actions: List[SslBumpLine] = field(default_factory=list)
    spliced_domains: List[str] = field(default_factory=list)
    terminated_domains: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    divergences: List[str] = field(default_factory=list)

    @property
    def decrypts(self) -> bool:
        """True when the source Squid sees inside at least some HTTPS."""
        return self.posture in (BUMPING, MIXED)

    def summary_lines(self) -> List[str]:
        out = ["SslBump posture: %s." % self.posture]
        if self.actions:
            out.append("  ssl_bump: " + ", ".join(
                "%s %s" % (a.action, " ".join(a.acls) or "all")
                for a in self.actions))
        if self.spliced_domains:
            out.append("  spliced (not decrypted) by SNI: "
                       + ", ".join(self.spliced_domains))
        if self.decrypts:
            out.append("  HTTPS coverage: url/path/method/header/MIME rules "
                       "apply to decrypted HTTPS (requires NFW TLS inspection).")
        else:
            out.append("  HTTPS coverage: source Squid does not decrypt; only "
                       "domain/SNI rules applied to HTTPS there.")
        for note in self.notes:
            out.append("  " + note)
        return out


def _domains_for(acl_names: List[str], cfg: ParsedConfig,
                 posture: Posture, action: str, line: SslBumpLine) -> List[str]:
    """Resolve the SNI values an ssl_bump line selects on."""
    out: List[str] = []
    for name in acl_names:
        bare = name[1:] if name.startswith("!") else name
        if bare in _ALL_ACLS:
            continue
        acl = cfg.acls.get(bare)
        if acl is None:
            posture.notes.append(
                "Squid %s: `ssl_bump %s %s` refers to ACL `%s`, which is not "
                "defined in the config, so its domains could not be listed."
                % (where(line.line_no, line.source), action, " ".join(acl_names),
                   bare))
            continue
        if acl.acl_type.startswith("ssl::server_name") or \
                acl.acl_type.startswith("dstdom") or acl.acl_type == "dstdomain":
            out.extend(acl.values)
        else:
            posture.notes.append(
                "Squid %s: `ssl_bump %s` selects on ACL `%s` [%s], which is "
                "not a domain/SNI match, so it has no equivalent in an NFW TLS "
                "inspection scope."
                % (where(line.line_no, line.source), action, bare, acl.acl_type))
    return out


def analyse(cfg: ParsedConfig) -> Posture:
    """Determine the SslBump posture of a parsed config and its divergences."""
    p = Posture(actions=list(cfg.ssl_bump))

    decrypting = [l for l in cfg.ssl_bump if l.action in _DECRYPTING]
    splicing = [l for l in cfg.ssl_bump if l.action == "splice"]
    terminating = [l for l in cfg.ssl_bump if l.action == "terminate"]

    for line in splicing:
        p.spliced_domains.extend(
            _domains_for(line.acls, cfg, p, "splice", line))
    for line in terminating:
        p.terminated_domains.extend(
            _domains_for(line.acls, cfg, p, "terminate", line))

    if not decrypting:
        p.posture = NOT_BUMPING
    elif p.spliced_domains:
        p.posture = MIXED
    else:
        p.posture = BUMPING

    # Divergence 1: the source never decrypts, but the converted http.* rules
    # will match decrypted HTTPS once NFW TLS inspection is enabled.
    if not p.decrypts:
        p.divergences.append(
            "The source Squid does NOT decrypt HTTPS (no `ssl_bump bump`), so "
            "its url/path/method/header/MIME ACLs only ever applied to plain "
            "HTTP. The converted rules match those buffers on decrypted HTTPS "
            "too, so with NFW TLS inspection enabled the firewall will enforce "
            "them STRICTER than Squid did. Disable TLS inspection to match the "
            "source exactly, or accept the tighter policy deliberately.")

    # Divergence 2: splice-by-domain has no expression in an NFW scope.
    if p.spliced_domains:
        p.divergences.append(
            "Squid exempts %d domain(s) from decryption by SNI (`ssl_bump "
            "splice`): %s. An AWS Network Firewall TLS inspection scope matches "
            "on 5-tuple only (protocol, source, source port, destination, "
            "destination port) and has no domain dimension, so this exemption "
            "CANNOT be expressed in the firewall - those domains WILL be "
            "decrypted. To preserve the exemption, route that traffic around "
            "the inspection path; %s. Also review any certificate-pinned "
            "applications among them, which break under decryption."
            % (len(p.spliced_domains), ", ".join(p.spliced_domains),
               _CDN_EVIDENCE))

    if p.terminated_domains:
        p.divergences.append(
            "Squid terminates connections to %s (`ssl_bump terminate`). NFW has "
            "no terminate-at-handshake action; the closest equivalent is a drop "
            "or reject rule on tls.sni, which the converter emits only if an "
            "http_access line also denies those domains."
            % ", ".join(p.terminated_domains))
    return p


# ---------------------------------------------------------------------------
# SslBump ACL type classification (Task 10)
#
# Squid's SslBump-related ACL types do not all map to Suricata rules. Sorting
# them into four buckets makes the reporting honest about WHERE each one has to
# be handled on the AWS side - a rule, the TLS inspection scope, firewall
# configuration, or nowhere at all.
# ---------------------------------------------------------------------------
BECOMES_RULE = "becomes-rule"
BECOMES_SCOPE = "becomes-scope"
BECOMES_FIREWALL_CONFIG = "becomes-firewall-config"
NO_ANALOG = "no-analog"

_CERT_ACLS = ("certHasExpired", "certNotYetValid", "certUntrusted",
              "certSelfSigned", "certDomainMismatch")

_CLASSIFICATION = {
    # Becomes a Suricata rule: tls.sni survives inside a TLS inspection scope,
    # because the SSL proxy passes the SNI through as metadata.
    "ssl::server_name": (BECOMES_RULE,
                         "matches tls.sni, which keeps working inside an NFW "
                         "TLS inspection scope"),
    "ssl::server_name_regex": (BECOMES_RULE,
                               "matches tls.sni via pcre, which keeps working "
                               "inside an NFW TLS inspection scope"),
    # Becomes part of the TLS inspection scope rather than a rule.
    "at_step": (BECOMES_SCOPE,
                "SslBump processing step; on the AWS side the equivalent "
                "decision is whether traffic is in the TLS inspection scope at "
                "all, not a rule condition"),
    # Becomes firewall configuration: NFW does this itself, no rule needed.
    "ssl_error": (BECOMES_FIREWALL_CONFIG,
                  "NFW performs certificate revocation checking (OCSP/CRL) on "
                  "behalf of clients when outbound TLS inspection is enabled, "
                  "so certificate errors are handled by firewall "
                  "configuration instead of a rule"),
    "connections_encrypted": (BECOMES_FIREWALL_CONFIG,
                              "whether a flow is encrypted is decided by the "
                              "TLS inspection scope, not by a rule condition"),
    # No analog at all.
    "user_cert": (NO_ANALOG,
                  "client-certificate attributes; NFW has no client-"
                  "certificate inspection"),
    "ca_cert": (NO_ANALOG,
                "issuing-CA attributes of a CLIENT certificate; NFW has no "
                "client-certificate inspection"),
    "server_cert_fingerprint": (BECOMES_RULE,
                                "maps to tls.cert_fingerprint, but that "
                                "keyword STOPS matching inside a TLS "
                                "inspection scope - only tls.sni survives "
                                "decryption"),
}
for _name in _CERT_ACLS:
    for _spelled in (_name, "ssl::" + _name):
        _CLASSIFICATION[_spelled] = (
            BECOMES_FIREWALL_CONFIG,
            "Squid's built-in certificate-validation ACL; NFW validates the "
            "SNI against the server certificate automatically and can check "
            "revocation, so this is firewall configuration, not a rule")


def classify(acl_type: str) -> Optional[str]:
    """Which bucket an SslBump-related ACL type falls into, or None."""
    entry = _CLASSIFICATION.get(acl_type)
    return entry[0] if entry else None


def explain(acl_type: str) -> Optional[str]:
    """Why an SslBump-related ACL type is classified the way it is."""
    entry = _CLASSIFICATION.get(acl_type)
    return entry[1] if entry else None


def classification_report(acl_types) -> List[str]:
    """One report line per SslBump ACL type present in the config."""
    out: List[str] = []
    for acl_type in sorted(set(acl_types)):
        bucket = classify(acl_type)
        if bucket is None:
            continue
        out.append("SslBump ACL `%s` -> %s: %s"
                   % (acl_type, bucket, explain(acl_type)))
    return out
