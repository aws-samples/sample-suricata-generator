# Rule Analysis Categories

This is the reference for every finding the Rule Group Analysis can produce. The
analyzer describes each finding on two independent axes:

- **Category** — *what kind* of problem it is (for example, Rule Shadowing or
  Protocol Layering). The Category is the grouping axis: it never changes based
  on how urgent a particular instance is.
- **Severity** — *how much it matters* for this specific instance:
  - 🚨 **Critical** — the rule (or rule pair) will not behave as written; fix
    before deploying.
  - ⚠️ **Warning** — likely a mistake or a correctness/security gap; review it.
  - ℹ️ **Informational** — not an error, but worth knowing; often a redundancy or
    a no-op.

One Category can emit more than one Severity. "Rule Shadowing," for example,
reports Critical, Warning, or Informational depending on how completely one rule
hides another. The table below lists, for each Category, the Severities it can
produce and what it detects, with a small generic example.

The labels in the **Category** column match exactly what you see in the report
window's *Category* column.

## Categories

| Category | Possible severities | What it detects |
|---|---|---|
| **Rule Shadowing** | 🚨 Critical · ⚠️ Warning · ℹ️ Informational | An earlier rule fully or partially hides a later one, so the later rule never (or rarely) matches. Critical when the earlier rule makes the later one completely unreachable; Warning/Informational for partial overlap. Example: a broad `pass tls any -> any any` above a specific `pass tls ... ($HOME_NET)` for `example.com` — the specific rule never runs. |
| **Protocol Layering** | ⚠️ Warning · ℹ️ Informational | Rules of different Suricata processing tiers (IP-only → packet → application-layer) interact in a way file order does not reflect, because Suricata processes by tier, not by line position. Warning when the interaction changes the outcome; Informational when it is only a note about evaluation order. Example: an IP-only `pass` for a CIDR and an application-layer `drop dns` for `sub.example.com` whose networks overlap. |
| **Sticky Buffer Ordering** | ⚠️ Warning | A content keyword appears before the sticky buffer it depends on (for example `content` before `tls.sni`), so the content has no buffer context and may not match as intended. Example: `content:"example.com"; tls.sni;` — the `tls.sni` must come first. |
| **UDP flow:established** | ⚠️ Warning | A UDP or ICMP rule uses `flow:established` with a `drop`/`reject` action. These flows are only "established" after bidirectional traffic, so the first packet (such as a DNS query or echo request) is never blocked — a security gap. Example: `drop udp any any -> any 53 (flow:established; ...)`. |
| **Protocol/Keyword Mismatch** | ⚠️ Warning · ℹ️ Informational | A rule's protocol is incompatible with (Warning) or less specific than (Informational) an application-layer keyword it uses. Example (Warning): a `udp` rule using `http.host`; (Informational): a `tcp` rule using `tls.sni` where protocol `tls` would be clearer. |
| **Port/Protocol Mismatch** | ℹ️ Informational | A protocol appears on an unusual or unexpected port, which may indicate a configuration slip. Example: `tls` traffic scoped to port `80` instead of `443`. |
| **Port on Portless Protocol** | ℹ️ Informational | An `ip` or `icmp` rule carries a concrete port. These protocols match at the network layer and have no port concept, so Suricata ignores the port — the rule matches all traffic to/from the networks regardless of port. Example: `pass ip $HOME_NET any -> any 443` actually matches every port. |
| **Contradictory Flow** | ⚠️ Warning | A single rule combines mutually exclusive flow keywords. Example: `flow:to_server,to_client` (can't be both directions) or `flow:established,not_established`. |
| **Packet/Flow Action** | ⚠️ Warning | A packet-scope `drop`/`reject` conflicts with a flow-scope `pass`. Behavior was ambiguous before Suricata 8.0 (deconfliction was added there). Example: a packet rule `drop tcp ...` alongside a flow `pass` on the same session. |
| **Asymmetric Flow** | 🚨 Critical · ⚠️ Warning | Rules allow one direction of a conversation but block the return direction, breaking bidirectional communication. Critical when the return path is fully blocked; Warning for a narrower mismatch. Example: `pass ... flow:to_server` for `sub.example.com` with a `drop ... flow:to_client` on the same pair. |
| **Reject-on-IP** | 🚨 Critical | A `reject` action is used on an `ip` protocol rule, which AWS Network Firewall does not support. Example: `reject ip $HOME_NET any -> any any`. |
| **Reject-on-QUIC** | 🚨 Critical | A `reject` action is used on a `quic` protocol rule, which AWS Network Firewall does not support. Example: `reject quic any any -> any any`. |
| **Unsupported Keywords** | 🚨 Critical | The rule uses a keyword AWS Network Firewall does not support (for example `dataset`/`datarep`, `iprep`). Example: `... (dataset:isset,my-set; ...)`. |
| **PCRE Restrictions** | 🚨 Critical | A `pcre` keyword is used without one of the companion keywords AWS Network Firewall requires (such as `content`, `tls.sni`). Example: a bare `pcre:"/pattern/"` with no anchoring keyword. |
| **Threshold** | ⚠️ Warning | The `threshold` keyword is used; AWS Network Firewall supports it only in a limited capacity. Not an error, but worth confirming the behavior you expect. Example: `... (threshold:type limit, track by_src, count 5, seconds 60; ...)`. |
| **Priority-strict-order** | ⚠️ Warning | A `priority` keyword is used while AWS Network Firewall is in strict evaluation order (its default), where `priority` is not honored — rules run in file order within their tier. Example: `... (priority:1; ...)` has no effect. |

## Notes

- Categories marked as AWS-specific (Reject-on-IP, Reject-on-QUIC, Unsupported
  Keywords, PCRE Restrictions, Threshold, Priority-strict-order) reflect
  [AWS Network Firewall Suricata limitations](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html).
- You can ignore findings individually, or ignore an entire Category at once
  from the report's right-click menu. Ignoring the Rule Shadowing category hides
  all three of its severities together.
