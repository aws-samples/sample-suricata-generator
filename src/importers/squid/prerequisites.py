"""
Firewall prerequisites for converted Squid rules.

The converted rules only behave like the source Squid policy when the AWS
Network Firewall policy is set up to match. `build()` returns those settings as
structured items, so the import dialog, the report, the command line summary
and the documentation all show the same text.

Keys:
  strict_order          always
  default_actions       always
  proxy_dns             always (the output is always for the explicit proxy)
  tls_inspection        the source decrypts HTTPS and an HTTP-only rule was made
  route53               the "Use Route 53 resolved domains" option is on
  route53_proxy_bypass  the "Use Route 53 resolved domains" option is on
  reply_rules           the config has http_reply_access lines
"""

from dataclasses import dataclass, field
from typing import List

# Amazon Route 53 Resolver address the explicit proxy sends its DNS queries to.
RESOLVER_ADDRESS = "169.254.169.253"
RESOLVER_IPV6_ADDRESS = "fd00:ec2::253"


@dataclass
class Prerequisite:
    """One firewall setting the converted rules depend on.

    key: stable identifier (see the module docstring).
    title: short heading.
    lines: the explanation, one paragraph or bullet per entry.
    """
    key: str
    title: str
    lines: List[str] = field(default_factory=list)


def strict_order() -> Prerequisite:
    return Prerequisite("strict_order", "Rule order: STRICT_ORDER", [
        "Load the rules into a stateful rule group whose rule order is "
        "STRICT_ORDER, in a firewall policy that also uses strict order.",
        "Squid uses the first http_access line that matches, and the rules "
        "keep that order. With the default action order instead, every "
        "`pass` rule would be evaluated before the `reject`/`drop` rules and "
        "could allow traffic Squid denied.",
    ])


def default_actions() -> Prerequisite:
    return Prerequisite("default_actions", "Firewall policy default actions", [
        "Set the policy's stateful default actions to \"Application drop "
        "established\" and \"Application alert established\" (both "
        "server-directed only).",
        "Squid denies a request no line allows. These default actions do the "
        "same for web requests without breaking the connection set-up "
        "(the TCP handshake and TLS ClientHello) that the rules need to see "
        "before they can match a domain or URL.",
        "\"Drop all\" or \"Drop established\" would drop that set-up traffic "
        "before any rule can match, so they would block traffic the source "
        "Squid allowed.",
        "Non-web traffic (SSH, SMTP, ...) is never matched by the converted "
        "rules, because Squid only ever handled web traffic. It falls to "
        "these default actions.",
        "To monitor before enforcing, export the rules with the Generator's "
        "test mode, which turns every rule into `alert` at export without "
        "changing the rules in the editor.",
    ])


def proxy_dns() -> Prerequisite:
    return Prerequisite("proxy_dns", "Proxy DNS rule (first rule)", [
        "The output is for AWS Network Firewall's explicit proxy, where "
        "clients use the firewall as their HTTP/HTTPS proxy, as they did "
        "with Squid. (The explicit proxy is a capability of Network Firewall; "
        "the same firewall can also do transparent filtering for other "
        "traffic.)",
        "The first rule passes DNS to the Amazon Route 53 Resolver (%s, "
        "port 53). The proxy resolves each destination name itself "
        "by querying the Resolver, and that lookup is checked by the "
        "firewall rules. Without this rule the recommended default action "
        "blocks the lookups and every proxied request fails. Keep it first. "
        "Clients' own DNS does not pass through the proxy, and the rule is "
        "limited to the Resolver address, so clients cannot use it to reach "
        "other DNS servers." % RESOLVER_ADDRESS,
        "Dual-stack VPCs: if the proxy resolves names over IPv6, add the "
        "Resolver's IPv6 address %s to the rule's destination."
        % RESOLVER_IPV6_ADDRESS,
        "VPCs that use a custom DNS resolver: change the rule's destination "
        "to that resolver's address. (Not yet verified on a live firewall.)",
    ])


def tls_inspection() -> Prerequisite:
    return Prerequisite("tls_inspection", "TLS inspection (the source Squid decrypts HTTPS)", [
        "The source Squid decrypts HTTPS (`ssl_bump bump`), so its URL, "
        "path, method, header and MIME type conditions applied to HTTPS. The "
        "converted rules with those conditions enforce on HTTPS only after "
        "AWS Network Firewall TLS inspection is set up:",
        "- a TLS inspection configuration you create (by whatever method you "
        "choose), covering the clients' HTTPS traffic (TCP 443);",
        "- a CA certificate imported into AWS Certificate Manager for it;",
        "- clients that trust that CA;",
        "- the configuration added to a NEW firewall policy (AWS does not "
        "allow adding one to an existing policy);",
        "- QUIC (UDP 443) blocked, because TLS inspection cannot decrypt it "
        "and a TCP-only scope lets it bypass inspection.",
        "Not yet verified on a live firewall: TLS inspection in the explicit "
        "proxy deployment, and whether a request on a reused connection is "
        "still evaluated after an earlier request on it was passed (this "
        "affects path or header denies placed before a domain allow).",
    ])


def route53() -> Prerequisite:
    return Prerequisite("route53", "Route 53 resolved domains", [
        "Enable Route 53 resolved IP validation on the firewall policy.",
        "Associate a Route 53 Resolver DNS Firewall rule group (it needs no "
        "rules) with the VPCs behind the firewall.",
        "Make sure clients resolve DNS through the Route 53 Resolver.",
        "Check that the DnsAzUnavailableFlows metric is zero: in an "
        "Availability Zone that does not support the feature, the firewall "
        "drops all traffic these rules inspect, even for `pass` rules.",
        "The policy setting's own action applies to ALL traffic that fails "
        "validation, including clients connecting to hard-coded IP "
        "addresses.",
        "The rules are stricter than Squid, which checks the name only: a "
        "rule now matches only when the Route 53 Resolver resolved the "
        "connection's destination IP for that name.",
        "With the explicit proxy the proxy resolves each name itself and "
        "connects only to what it resolved, so the spoofing gap this closes "
        "(a client sending an allowed name to an unrelated IP) does not arise "
        "there; the keyword's extra protection is therefore limited. Verified "
        "on a live firewall: validation with the 169.254.169.253/32 bypass "
        "and the proxy's own lookups did not break normal traffic in Alert or "
        "Drop mode.",
    ])


def route53_proxy_bypass() -> Prerequisite:
    return Prerequisite("route53_proxy_bypass", "Required: bypass the Resolver address", [
        "Add %s/32 (the Amazon Route 53 Resolver address) to the firewall "
        "policy's \"Bypass destination validation IP ranges\"."
        % RESOLVER_ADDRESS,
        "Why: the proxy resolves each destination name itself by querying "
        "that address, and resolved IP validation checks that query like any "
        "other connection. The Resolver's own address never appears in a DNS "
        "answer, so with a policy action of Drop or Reject the query is "
        "blocked, the proxy can resolve no names, and all proxied traffic "
        "fails.",
        "The DNS pass rule the converter adds does not cover this: the "
        "policy-level check applies independently of the rules. Validation "
        "still applies to the real destinations.",
        "AWS's public resolved IP validation documentation does not cover "
        "the explicit proxy deployment.",
    ])


def reply_rules() -> Prerequisite:
    return Prerequisite("reply_rules", "http_reply_access lines are not enforced", [
        "Squid's http_reply_access lines check responses. AWS Network "
        "Firewall can't enforce them on allowed traffic: once a `pass` rule "
        "matches, the firewall stops inspecting the whole connection. They "
        "are reported, not converted, and responses are let through.",
    ])


def build(cfg, emit_result, route53_option: bool) -> List[Prerequisite]:
    """Prerequisites for one conversion, in display order."""
    items = [strict_order(), default_actions(), proxy_dns()]
    posture = getattr(emit_result, "posture", None)
    if posture is not None and posture.decrypts and emit_result.http_only_used:
        items.append(tls_inspection())
    if route53_option:
        items.append(route53())
        items.append(route53_proxy_bypass())
    if getattr(cfg, "http_reply_access", None):
        items.append(reply_rules())
    return items
