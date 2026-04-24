# AWS Network Firewall Best Practices

Source: [AWS Security Services Best Practices Guide](https://aws.github.io/aws-security-services-best-practices/guides/network-firewall/)
Content was rephrased for compliance with licensing restrictions.

## Deployment Models

Three main architecture patterns:
1. **Distributed** — Network Firewall deployed into each individual VPC
2. **Centralized** — Deployed into a centralized inspection VPC attached to AWS Transit Gateway for East-West or North-South traffic
3. **Combined** — Centralized for East-West + subset of North-South, with internet ingress distributed to VPCs needing dedicated inbound access

## Key Best Practices

### Use Strict Rule Ordering with Drop Established Default Action

- "Strict" ordering processes rules in defined order (recommended over "Action Order")
- "Drop established (application layer)" is the recommended default action — it allows Suricata to fully reassemble application layer data (TLS Client Hello, HTTP headers) before making drop decisions, which prevents issues with fragmented TLS handshakes from modern clients using post-quantum cryptography
- "Drop established" is an alternative that drops at the TCP established level — this can cause issues with clients that fragment the TLS Client Hello across multiple TCP segments (common with post-quantum key exchange like X25519Kyber768)
- "Drop all" is the most aggressive option but prevents L7 inspection entirely
- Always pair with the corresponding "Alert" action to log dropped traffic (e.g., "Alert established (application layer)" with "Drop established (application layer)")

### Use Stateful Rules Over Stateless Rules

- Stateless rules should be used very sparingly — they cause asymmetric flow forwarding issues
- Set stateless engine default to "Forward to stateful rule groups"
- Stateful rules provide deep packet inspection, automatic return traffic handling, logging, and the reject action

### Use Custom Suricata Rules Instead of UI-Generated Rules

Benefits of custom Suricata rules:
- Allows adding the critical `flow:to_server` keyword easily
- Maximum flexibility and control over alerting/logging
- Custom SIDs for easier troubleshooting and log analysis
- Easy to copy, edit, share, backup, and move between rule groups

### Use "flow:to_server" Keyword in Stateful Rules

This is critical to prevent rule conflicts. Without `flow:to_server`, a TCP pass rule can take precedence over an HTTP reject rule because they operate at different OSI layers.

**Bad example (DO NOT USE):**
```
reject http $HOME_NET any -> any 80 (http.host; content:"baddomain.com"; sid:1;)
pass tcp $HOME_NET any -> any 80 (sid:2;)
```

**Good example:**
```
reject http $HOME_NET any -> any 80 (http.host; content:"baddomain.com"; sid:1;)
pass tcp $HOME_NET any -> any 80 (flow:to_server; sid:2;)
```

### Ensure $HOME_NET Variable Is Set Correctly

- Default is VPC CIDR where Network Firewall is deployed — may not cover spoke VPCs
- Most customers should set to all RFC 1918 ranges: `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16`
- Can be set at firewall policy level (global) or per rule group (rule group wins)
- If set at rule group level, also set $EXTERNAL_NET at rule group level

### Use Alert Rule Before Pass Rule to Log Allowed Traffic

Pass rules don't generate logs. To log allowed traffic, add an alert rule before the pass rule:
```
alert tls $HOME_NET any -> any any (tls.sni; content:".amazonaws.com"; nocase; endswith; msg:"*.amazonaws.com allowed"; flow:to_server; sid:021420241;)
pass tls $HOME_NET any -> any any (tls.sni; content:".amazonaws.com"; nocase; endswith; flow:to_server; sid:021420242;)
```

Alternative: Use `alert;` keyword in pass rules (shows verdict as "alert" instead of "pass"):
```
pass tls $HOME_NET any -> any any (alert; msg:"www.example.com allowed"; tls.sni; content:"www.example.com"; startswith; nocase; endswith; flow:to_server; sid:202506131;)
```

### Use as Few Custom Rule Groups as Possible

- Capacity cannot be modified after creation — fewer groups = easier capacity management
- Single view of all rules makes conflict/shadow detection easier
- Maximum 20 combined rule groups (managed + custom)
- Ensure SIDs are unique across ALL rule groups (not enforced cross-group)

## Ensure Symmetric Routing

- Network Firewall does not support asymmetric routing
- When using Transit Gateway centralized deployment, enable appliance mode on inspection VPC attachments
- Route tables must account for traffic going to firewall endpoint in both directions

## Port/Protocol Enforcement Patterns

Enforce that protocols use their expected ports:
```
reject tcp $HOME_NET any -> any 443 (msg:"Egress Port TCP/443 but not TLS"; app-layer-protocol:!tls; flow:to_server; sid:202501030;)
reject tls $HOME_NET any -> any !443 (msg:"Egress TLS but not port TCP/443"; flow:to_server; sid:202501031;)
reject tcp $HOME_NET any -> any 80 (msg:"Egress Port TCP/80 but not HTTP"; app-layer-protocol:!http; flow:to_server; sid:202501032;)
reject http $HOME_NET any -> any !80 (msg:"Egress HTTP but not port TCP/80"; flow:to_server; sid:202501033;)
reject tcp $HOME_NET any -> any 22 (msg:"Egress Port TCP/22 but not SSH"; app-layer-protocol:!ssh; flow:to_server; sid:202501060;)
reject ssh $HOME_NET any -> any !22 (msg:"Egress SSH but not port TCP/22"; flow:to_server; sid:202501061;)
```

## Domain Filtering Patterns

### Block by ccTLD/TLD
```
reject tls $HOME_NET any -> any any (tls.sni; content:".ru"; nocase; endswith; msg:"Egress traffic to RU ccTLD"; flow:to_server; sid:202501036;)
reject http $HOME_NET any -> any any (http.host; content:".ru"; endswith; msg:"Egress traffic to RU ccTLD"; flow:to_server; sid:202501037;)
```

### Block Direct-to-IP Connections
```
reject http $HOME_NET any -> any any (http.host; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"HTTP direct to IP"; flow:to_server; sid:202501026;)
reject tls $HOME_NET any -> any any (tls.sni; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"TLS direct to IP"; flow:to_server; sid:202501027;)
```

### Block TLS Connections with No SNI (JA4)
```
reject tls $HOME_NET any -> any any (ja4.hash; content:"_"; startswith; content:!"d"; offset:3; depth:1; msg:"JA4 No SNI Reject"; sid:1297713;)
```

### Allow AWS Service Endpoints
```
pass tls $HOME_NET any -> any any (tls.sni; content:"ssm."; startswith; nocase; content:".amazonaws.com"; endswith; nocase; flow:to_server; sid:202501048;)
```

### Allow Specific FQDN with Logging
```
alert tls $HOME_NET any -> any any (tls.sni; content:"www.example.com"; startswith; nocase; endswith; msg:"TLS SNI Allowed"; flow:to_server; sid:202501052;)
pass tls $HOME_NET any -> any any (tls.sni; content:"www.example.com"; startswith; nocase; endswith; flow:to_server; sid:202501053;)
```

### Allow Second-Level Domain and All Subdomains (dotprefix)
```
pass tls $HOME_NET any -> any any (tls.sni; dotprefix; content:".amazon.com"; nocase; endswith; flow:to_server; sid:202501078;)
```

## GeoIP Blocking
```
drop ip $HOME_NET any -> any any (msg:"Egress traffic to RU IP"; geoip:dst,RU; metadata:geo RU; flow:to_server; sid:202501028;)
drop ip $HOME_NET any -> any any (msg:"Egress traffic to CN IP"; geoip:dst,CN; metadata:geo CN; flow:to_server; sid:202501029;)
```

## Cost Optimization with Threshold

Suppress logging output to reduce costs:
```
alert ssh $HOME_NET any -> any any (msg:"Egress SSH - alert only once every ten minutes"; threshold: type limit, track by_both, seconds 600, count 1; flow:to_server; sid:898233;)
```

## TCP 3-Way Handshake Pass Rule

Allow TCP handshake setup so domain filtering rules work:
```
pass tcp $HOME_NET any -> any any (flow:not_established, to_server; sid:202501021;)
```

## Default Block Rules (Custom — Replaces Drop Established Default Action)

### Egress
```
pass tcp $HOME_NET any -> any any (msg:"Allow three-way handshake to be setup by $HOME_NET"; flow:not_established, to_server; sid:999990;)
reject tls $HOME_NET any -> any any (msg:"Default Egress HTTPS Reject"; ssl_state:client_hello; ja4.hash; content:"_"; flowbits:set,blocked; flow:to_server; sid:999991;)
alert tls $HOME_NET any -> any any (msg:"PQC"; flowbits:isnotset,blocked; flowbits:set,PQC; noalert; flow:to_server; sid:999993;)
reject http $HOME_NET any -> any any (msg:"Default Egress HTTP Reject"; flowbits:set,blocked; flow:to_server; sid:999992;)
reject tcp $HOME_NET any -> any any (msg:"Default Egress TCP Reject"; flowbits:isnotset,blocked; flowbits:isnotset,PQC; flow:to_server; sid:999994;)
drop udp $HOME_NET any -> any any (msg:"Default Egress UDP Drop"; flow:to_server; sid:999995;)
drop icmp $HOME_NET any -> any any (msg:"Default Egress ICMP Drop"; flow:to_server; sid:999996;)
drop ip $HOME_NET any -> any any (msg:"Default Egress All Other IP Drop"; ip_proto:!TCP; ip_proto:!UDP; ip_proto:!ICMP; flow:to_server; sid:999997;)
```

### Ingress
```
drop tls any any -> $HOME_NET any (msg:"Default Ingress HTTPS Drop"; ssl_state:client_hello; ja4.hash; content:"_"; flowbits:set,blocked; flow:to_server; sid:999999;)
alert tls any any -> $HOME_NET any (msg:"PQC"; flowbits:isnotset,blocked; flowbits:set,PQC; noalert; flow:to_server; sid:9999910;)
drop http any any -> $HOME_NET any (msg:"Default Ingress HTTP Drop"; flowbits:set,blocked; flow:to_server; sid:9999911;)
drop tcp any any -> $HOME_NET any (msg:"Default Ingress TCP Drop"; flowbits:isnotset,blocked; flowbits:isnotset,PQC; flow:to_server; sid:9999912;)
drop udp any any -> $HOME_NET any (msg:"Default Ingress UDP Drop"; flow:to_server; sid:9999913;)
drop icmp any any -> $HOME_NET any (msg:"Default Ingress ICMP Drop"; flow:to_server; sid:9999914;)
drop ip any any -> $HOME_NET any (msg:"Default Ingress All Other IP Drop"; ip_proto:!TCP; ip_proto:!UDP; ip_proto:!ICMP; flow:to_server; sid:9999915;)
```

## HOME_NET Validation Rule

Detect traffic not matching $HOME_NET (indicates misconfiguration):
```
alert ip $HOME_NET any -> any any (noalert; flowbits:set,egress_from_home_net; flow:to_server; sid:8925324;)
alert ip any any -> $HOME_NET any (noalert; flowbits:set,ingress_to_home_net; flow:to_server; sid:8923323;)
alert ip any any -> any any (msg:"$HOME_NET may not be set right! Set it at the firewall policy level."; flowbits:isnotset,ingress_to_home_net; flowbits:isnotset,egress_from_home_net; threshold: type limit, track by_both, seconds 600, count 1; flow:to_server; sid:8923283;)
```

## URL and Domain Category Filtering

AWS Network Firewall provides two category filtering keywords:
- `aws_url_category:<category>` — Evaluates complete URLs (HTTP) and domains. Requires TLS inspection for HTTPS.
  - Supported protocol in rules: HTTP
  - For HTTP: evaluates complete URLs. For HTTPS: requires TLS inspection (without it, HTTPS cannot be evaluated)
  - Evaluation order: complete URL path (up to 30 recursive lookups), then falls back to domain-level (up to 10 recursive subdomain lookups)
- `aws_domain_category:<category>` — Evaluates only domain information from TLS SNI or HTTP host headers.
  - Supported protocols in rules: TLS, HTTP
  - For HTTP: evaluates domain from Host field. For TLS: evaluates domain from SNI field
  - No TLS inspection required
  - Evaluates domain-level only (up to 10 recursive subdomain lookups)

### Supported Categories (complete list)
```
Abortion, Adult and Mature Content, Artificial Intelligence and Machine Learning,
Arts and Culture, Business and Economy, Career and Job Search, Child Abuse,
Command and Control, Criminal and Illegal Activities, Cryptocurrency, Dating,
Education, Email, Entertainment, Family and Parenting, Fashion, Financial Services,
Food and Dining, For Kids, Gambling, Government and Legal, Hacking, Health,
Hobbies and Interest, Home and Garden, Lifestyle, Malicious, Malware, Marijuana,
Military, News, Online Ads, Parked Domains, Pets, Phishing, Private IP Address,
Proxy Avoidance, Real Estate, Redirect, Religion, Search Engines and Portals,
Science, Shopping, Social Networking, Spam, Sports and Recreation,
Technology and Internet, Translation, Travel, Vehicles, Violence and Hate Speech
```

### Category Filtering Constraints
- CANNOT combine `aws_url_category` or `aws_domain_category` with `geoip` in the same rule — create separate rules
- Multiple categories can be specified in a single rule: `aws_url_category:Gambling,Social Networking;`
- Category database is automatically maintained and updated by AWS
- May increase traffic latency due to additional category lookups

### Category Filtering Examples
```
alert http any any -> any any (msg:"URL Category is Malicious"; aws_url_category:Malicious; sid:55555555; rev:1;)
drop http any any -> any any (msg:"Block gambling and social sites"; aws_url_category:Gambling,Social Networking; sid:55555556; rev:1;)
alert tls any any -> any any (msg:"Domain Category is Cryptocurrency"; aws_domain_category:Cryptocurrency; sid:55555557; rev:1;)
```

## HTTP/2 Domain Filtering

For decrypted HTTP/2 traffic (requires TLS inspection), use `http2` protocol with `http.request_header` or `http2.header_name`:
```
# Allow http2 traffic to specific domain
pass http2 $HOME_NET any -> $EXTERNAL_NET any (http.request_header; content:"authority|3a 20|example.com"; sid:1; rev:1;)

# Reject non-http2 TCP traffic
reject tcp $HOME_NET any -> $EXTERNAL_NET any (app-layer-protocol:!http2; flow:to_server, established; sid:2; rev:1;)

# Drop all other http2 decrypted traffic
drop http2 $HOME_NET any -> $EXTERNAL_NET any (flow:established, to_server; http2.header_name; content:"authority"; sid:3; rev:1;)
```

## AWS-Specific Keywords

Keywords specific to AWS Network Firewall (not standard Suricata):
- `aws_domain_category:<category>` — Match AWS managed domain categories (see full list above)
- `aws_url_category:<category>` — Match AWS managed URL categories (see full list above)
- `ja4.hash` — JA4 TLS fingerprint hash (newer than JA3)
- `dotprefix` — Transform for matching domain and all subdomains (place before content, include leading dot)
- `ssl_state:client_hello` — Match TLS Client Hello state
- `flowbits` — Set/check flow-level flags for multi-rule coordination
- `xbits` — Extended bits with IP tracking and expiration
- `http2.header_name` — HTTP/2 header name sticky buffer (for decrypted HTTP/2 traffic)
- `http.request_header` — HTTP request header sticky buffer (works with HTTP/1 and HTTP/2)

## JA3/JA4 Filtering for TLS SNI Manipulation Mitigation

JA3 is like an HTTP User-Agent but for TLS. Can be combined with SNI filtering:
```
pass tls $HOME_NET any -> any any (tls.sni; content:"ssm.us-east-1.amazonaws.com"; nocase; ja3.hash; content:"7a15285d4efc355608b304698cd7f9ab"; sid:11111;)
```

## Rule Evaluation Order

AWS Network Firewall supports two rule evaluation modes:

### Default Action Order
Rules are processed by action type: pass → drop → reject → alert. Within each action type, rules are processed in the order they appear. Use `priority` keyword to influence ordering within action types.

### Strict Order (Recommended)
Rules are processed top-to-bottom in the order they appear in the rule group. Earlier rules take precedence. This gives full control over rule evaluation.

**Default action options for strict order (choose one drop + one alert):**

Drop actions (choose one):
- `aws:drop_established_app_layer` (recommended) — drops at the application layer after full reassembly, allowing fragmented TLS Client Hello and HTTP headers to be fully inspected before drop decisions
- `aws:drop_established` — drops established TCP flows; may cause issues with modern TLS clients using post-quantum key exchange that fragments the Client Hello
- `aws:drop_strict` — drops all unmatched traffic including non-established; prevents L7 inspection

Alert actions (choose one):
- `aws:alert_established_app_layer` (recommended) — pairs with `drop_established_app_layer`
- `aws:alert_established` — pairs with `drop_established`
- `aws:alert_strict` — pairs with `drop_strict`

Note: The `priority` keyword is NOT supported in strict order rule groups. Do not include it in custom rules intended for strict order evaluation.

Alternatively, you can use custom default block rules instead of the built-in default actions (see the Default Block Rules section below).

### Strict Order SNI Allow/Block Pattern
```
# Allow specific domain via SNI
pass tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"example.com"; dotprefix; nocase; flow:to_server, established; sid:2;)

# Drop all other established traffic
drop tcp $HOME_NET any -> $EXTERNAL_NET any (flow:to_server, established; sid:1;)
```

### Domain List Generated Rules
When using domain list rule groups, Network Firewall auto-generates Suricata rules:

**TLS allow list generates (strict order equivalent):**
```
pass tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; dotprefix; content:".amazon.com"; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:1; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"example.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:2; rev:1;)
drop tls $HOME_NET any -> $EXTERNAL_NET any (msg:"not matching any TLS allowlisted FQDNs"; ssl_state:client_hello; flow:to_server, established; sid:3; rev:1;)
```

**HTTP deny list generates (strict order equivalent):**
```
drop tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"evil.com"; startswith; nocase; endswith; msg:"matching TLS denylisted FQDNs"; flow:to_server, established; sid:1; rev:1;)
drop http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"evil.com"; startswith; endswith; msg:"matching HTTP denylisted FQDNs"; flow:to_server, established; sid:2; rev:1;)
```

## SNI Allowlist with Certificate Issuer Verification (xbits)

Multi-rule pattern using xbits to verify both SNI and certificate issuer:
```
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (ssl_state:client_hello; tls.sni; content:"checkip.amazonaws.com"; endswith; nocase; xbits:set, allowed_sni_destination_ips, track ip_dst, expire 3600; noalert; sid:238745;)
pass tcp $HOME_NET any -> $EXTERNAL_NET 443 (xbits:isset, allowed_sni_destination_ips, track ip_dst; flow:stateless; sid:89207006;)
pass tls $EXTERNAL_NET 443 -> $HOME_NET any (tls.cert_issuer; content:"Amazon"; msg:"Pass rules do not alert"; xbits:isset, allowed_sni_destination_ips, track ip_src; sid:29822;)
reject tls $EXTERNAL_NET 443 -> $HOME_NET any (tls.cert_issuer; content:"="; nocase; msg:"Block all other cert issuers not allowed by sid:29822"; sid:897972;)
```
Note: The `flow:stateless` keyword is used in the xbits pass rule to match packets regardless of connection state.

## SSH/SFTP Banner Filtering

Allow only SSH servers with specific banners (e.g., AWS Transfer Family):
```
pass tcp $HOME_NET any -> $EXTERNAL_NET 22 (flow:stateless; sid:2221382;)
pass ssh $EXTERNAL_NET 22 -> $HOME_NET any (ssh.software; content:"AWS_SFTP"; flow:from_server; sid:217872;)
drop ssh $EXTERNAL_NET 22 -> $HOME_NET any (ssh.software; content:!"@"; pcre:"/[a-z]/i"; msg:"Block unauthorized SFTP/SSH."; flow:from_server; sid:999217872;)
```

## IP Set References (Prefix Lists)

Reference AWS VPC prefix lists in rules using `@` prefix:
```
drop tcp @BETA any -> any any (sid:1;)
```
The `@BETA` variable references a prefix list ARN defined in the rule group's `ReferenceSets.IPSetReferences`.

## Clearing Stateful Rules State Table

To apply new rules to existing flows:
1. Edit firewall policy "Stream exception policy" to a different value, save
2. Edit it back to original value (recommended: "Reject")
This forces all traffic to be re-evaluated against latest rules.

## QUIC Traffic Blocking
```
drop quic $HOME_NET any -> any any (msg:"QUIC traffic blocked"; flow:to_server; sid:3898932;)
```

## High Risk Port Monitoring
```
alert ip $HOME_NET any -> any 53 (msg:"Possible GuardDuty/DNS Firewall bypass!"; flow:to_server; sid:202501055;)
alert ip $HOME_NET any -> any 1389 (msg:"Possible Log4j callback!"; flow:to_server; sid:202501059;)
alert ip $HOME_NET any -> any [4444,666,3389] (msg:"Egress traffic to high risk port!"; flow:to_server; sid:202501058;)
```
