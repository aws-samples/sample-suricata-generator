# Squid → Suricata Conversion Reference

How the Squid Converter (File > Import Squid Configuration, and
`python -m src.importers.squid_cli`) maps Squid access policy to Suricata rules
for AWS Network Firewall (NFW). This document describes what the converter
actually produces. The source of truth is `src/importers/squid/mapping.py` (ACL
types) and `src/importers/squid/emitter.py` (rule shapes). Converter version:
see Help > About ("Squid Converter v1.0.1").

## Core concept: two layers, not one

Squid ACL **types** and Suricata **actions** are different things:

- **Verdict layer** — *what to do*: Squid `allow`/`deny`  ↔  Suricata `pass`/`drop`/`reject`
- **Match layer** — *what to look at*: Squid ACL type (`dstdomain`, `method`, …)  ↔  Suricata keyword (`tls.sni`, `http.method`, …)

A Squid ACL type maps to a Suricata **match keyword**, not to an action.

---

## 1. Verdict / action mapping

| Squid (`http_access`) | Suricata | Notes |
|-----------------------|----------|-------|
| `allow` | `pass` (with `alert;` when "Alert on pass" is on, the default) | `alert` logs the allowed traffic. |
| `deny` | `reject` (default) or `drop` ("Squid deny becomes", `--deny`) | NFW accepts `reject` only on tcp, http, tls, smb, dcerpc, ssh and smtp; elsewhere (for example `ftp` from `proto FTP`) the rule uses `drop` and a note says so. |
| `deny all` (last line) | no rule | A `NO RULE NEEDED` comment row; set the firewall policy's default action instead (section 10). |

There is no monitoring (alert-only) conversion. To monitor before enforcing,
export with the Generator's **test mode**, which turns every rule into `alert`
at export without changing the rules in the editor (test mode needs a policy
with no default drop action while you test).

### Deployment: always the explicit proxy

The output is always for AWS Network Firewall's **explicit proxy**, where
clients use the firewall as their HTTP/HTTPS proxy, as they did with Squid. The
explicit proxy is a capability of Network Firewall (the same firewall can also
do transparent filtering for other traffic); the converter does not emit rules
for transparent filtering. There is no option to choose another form of output.

- The first rule is always
  `pass dns any any -> 169.254.169.253 53 (flow:to_server; msg:"Squid import: proxy DNS"; ...)`.
  The proxy resolves each destination name itself by querying the Amazon Route 53
  Resolver (169.254.169.253), and the firewall rules check that lookup as DNS
  from the client's address. Without the rule the recommended default action
  blocks the lookups and every proxied request fails. The rule is limited to the
  Resolver address (port 53), so clients can't use it to reach other DNS
  servers. (The proxy also sends queries to port 5353, but the firewall
  classifies those as mDNS, not DNS, and name lookups work without them, so
  they are left to the default action.) A comment row explaining it is always placed directly above it.
  Keep it first.
- **Dual-stack VPCs:** the IPv6 Resolver address `fd00:ec2::253` is not in the
  rule. If your proxy resolves names over IPv6, add it to the rule's destination.
- **Custom DNS resolver:** change the rule's destination to your resolver's
  address. (Not yet verified on a live firewall.)
- Rules see the client's own IP as the source and the real destination address
  and port (443, 80, …), never the proxy listener ports. HTTPS is matched by
  `tls.sni`; plain HTTP by `http.host` / `http.uri`, where `http.uri` is the path
  only.
- **No SNI or Host spoofing.** The proxy connects only to the address it
  resolves itself for the requested host name; it does not use an IP the
  client supplies. A client cannot pair a blocked host with an allowed site's
  IP, or reach a different server with an allowed name's SNI or Host header. So
  the spoofing a transparent deployment is exposed to does not arise here
  (verified on a live proxy-mode firewall). This is also why the "Use Route 53
  resolved domains" option adds little in this deployment (section 10).
- **The proxy adds a `Via: 1.1 AWS Network Firewall` request header.** A Squid
  rule that matched on the `Via` header would not see the client's original
  value. Rules on other headers, the user agent and the URL path see the
  client's values unchanged, and plain-HTTP method, header and path rules do
  match through the proxy (verified on a live proxy-mode firewall).
- **The proxy refuses bare IP address targets.** A request such as
  `http://192.0.2.10/` or `CONNECT 192.0.2.10:443` gets HTTP 400 ("bare IP
  address targets are not permitted") from the proxy before any rule is
  evaluated, for every address, public or private. A host name that resolves
  to a loopback or link-local address (127.0.0.0/8, 169.254.0.0/16, including
  the instance metadata address 169.254.169.254) gets HTTP 403 ("target
  resolves to a blocked address range"). A host name that resolves to a
  private (RFC 1918) address is not refused: the proxy connects, and the
  rules see that destination. Clients must request host names. Squid lines that allow
  destination addresses (`dst` ACLs) still convert: the rules match the
  address the proxy resolved for the requested name, so they work for names
  that resolve into those addresses. Only requests that name the IP address
  directly change: Squid could allow them, the proxy refuses them. That can
  only block more, never allow more, and the report lists the affected allow
  lines. (Verified on a live firewall, on both proxy listeners.)
- A `reject` does not reach the client as a TCP reset: a rejected HTTPS
  connection fails during the TLS handshake (the proxy answers CONNECT with `200`
  first), and a rejected plain-HTTP request gets `502 Bad Gateway` from the proxy.

---

## 2. Protocols each match is emitted on

| Match | Rules emitted |
|-------|---------------|
| Domain (`dstdomain`, `dstdom_regex`) | `http` (`http.host`), `tls` (`tls.sni`) |
| TLS-only (`ssl::server_name*`, `server_cert_fingerprint`) | `tls` |
| HTTP-only (URL, method, header, MIME type) | `http` |
| Reply rules (`http_reply_access`) | not converted: once a `pass` rule matches, AWS Network Firewall stops inspecting the whole connection, so a rule on the response never sees replies to allowed requests. `allow all` needs no rule. |
| Header-only (only `src` / `dst` / `port`, or a `dst` host name) | `http` + `tls` pair. Never `tcp`: Squid only governs web traffic, and a `tcp` rule would also pass or block SSH, SMTP and other protocols Squid never saw. Non-web traffic falls to the firewall policy's default action. |
| `proto` ACL on the line | narrows the protocols above (section 3) |

Within one Squid line, the `http` and `tls` rule for the same value are emitted
as a pair (`http` first), in the order the values appear in the ACL. Squid lines
keep their first-match order. All rules from one line share the same action, so
this ordering doesn't change the policy under STRICT_ORDER.

No `http2` rules are generated. NFW doesn't support HTTP/2 keyword overloading,
so `http` rules don't match HTTP/2, but HTTP/2 almost always runs inside TLS,
where the `tls.sni` rule decides, and NFW still matches `tls.sni` on traffic it
decrypts. Only HTTP-level conditions (URL, method, headers, MIME type, status) on
decrypted HTTP/2 would need `http2` rules; that gap is noted in the report, and
reported as a divergence when the source Squid decrypts HTTPS.

---

## 3. ACL types: FULL (converted)

| Squid ACL type | Suricata match | Notes |
|----------------|----------------|-------|
| `src` | rule header source | User-defined `src` ACLs become `$VARIABLES` (Variables tab, description "Squid acl <name> (src)"); built-ins stay literal. Values become CIDR: ranges are split into blocks, bare IPs get `/32` or `/128`, netmasks become prefixes. A host name makes the line not convertible. A name that would land on a reserved variable (`HOME_NET`, `EXTERNAL_NET`) is renamed and the rename is reported. |
| `dst` | rule header destination | Literal addresses, normalised to CIDR like `src`. Host names: only with "Use Route 53 resolved domains" (`--route53-resolved-domains`), as `aws_route_53_resolved_domain:"name1,name2";` with destination `any`; without the option they are not convertible. IPs and names in one ACL become separate rules. A negated `dst` with names, or one on the same line as a `dstdomain` condition, is not convertible. |
| `port` | rule header destination port | User-defined `port` ACLs become port set `$VARIABLES`, like `src` ACLs become IP sets (Variables tab, description "Squid acl <name> (port)"), so a long or reused port list is defined once: `acl Safe_ports port 80 443` → `$SAFE_PORTS` = `[80,443]`, exported to `RuleVariables.PortSets`. Ranges use Network Firewall syntax: `1025-65535` → `1025:65535`, `8000-` → `8000:`. `port 0` (no port at all, e.g. URN targets) is not convertible. |
| `dstdomain` | `http.host` / `tls.sni` | With "Use Route 53 resolved domains" each rule also gets `aws_route_53_resolved_domain:"<name>";` (stricter than Squid: the destination IP must have been resolved for the name). Values lowercased (Squid is case-insensitive); `nocase` on `tls.sni` only. `.example.com` → `dotprefix; content:".example.com"; endswith;` (domain and subdomains, not `evilexample.com`); `host.example.com` → `content:"host.example.com"; startswith; endswith;` (exact). |
| `dstdom_regex` | pcre on `http.host` / `tls.sni` | No Route 53 keyword (it takes names, not regular expressions). |
| `ssl::server_name` | `tls.sni` | Same dotted/exact forms as `dstdomain`, including the Route 53 keyword. |
| `ssl::server_name_regex` | pcre on `tls.sni` | |
| `method` | `http.method` | HTTP only. `CONNECT` is dropped from HTTP rules, including from a mixed list (`PUT CONNECT` -> `PUT`), and alone produces no HTTP rule (the proxy answers CONNECT itself and the tunnel is matched by `tls.sni`); it counts as satisfied on TLS. |
| `urlpath_regex` | pcre on `http.uri` | HTTP only. |
| `browser` | `http.user_agent` | HTTP only. Needs a content prefilter (section 6). |
| `referer_regex` | header-anchored pcre on `http.header` | HTTP only. Needs a content prefilter. |
| `req_header` | header-anchored pcre on `http.header` | HTTP only. Needs a content prefilter. |
| `req_mime_type` | pcre on `http.content_type` | HTTP only. Needs a content prefilter. |
| `rep_mime_type` | not converted | `http_reply_access` only, which is not converted. |
| `http_status` | not converted | `http_reply_access` only, which is not converted. |
| `proto` | selects the rule protocol | `HTTP` → `http`, `HTTPS` → `tls`, `FTP` → `ftp`. Other schemes are not convertible. **FTP caveat:** the proxy front-ends FTP over HTTP, so a proxied `ftp://` request reaches the firewall as `http`, not `ftp` (verified live). The emitted `ftp` rules therefore don't match proxied FTP, which falls to the default action; the report notes this. Review FTP by hand. |
| `any-of` / `all-of` | groups | `any-of` → OR branches; `all-of` → AND; `!any-of` → AND of negations. `!all-of` is not convertible. |

Squid's built-in ACLs (no `acl` line needed): `all` → any. `localhost`
(source 127.0.0.1), `to_localhost` (destination 127.0.0.0/8 and 0.0.0.0) and
`to_linklocal` (destination 169.254.0.0/16) need no rule: see below.
The converter targets IPv4, so the IPv6 parts of Squid's built-ins (`::1`,
`::/128`, `fe80::/10`) are not included. IPv6 addresses you write in your own
`src` / `dst` ACLs are still converted.
**Loopback and link-local lines need no rule.** A line with one of these
non-negated conditions becomes a `# Squid line N NO RULE NEEDED (...)` comment
and a note:

- `localhost`, or a user `src` ACL whose every value is a loopback or
  unspecified address. Through the explicit proxy the rules always see the
  client's own VPC address, never a loopback source.
- `to_localhost` or `to_linklocal`, or a user `dst` ACL whose every value is a
  loopback, unspecified or link-local (169.254.0.0/16) address, for example
  `acl metadata dst 169.254.169.254`. The proxy refuses those targets itself
  before any rule is evaluated: a bare IP gets HTTP 400, and a host name that
  resolves into those ranges gets HTTP 403.

This was verified on a live firewall, including the instance metadata address
on both proxy listeners. Such a line can never match, so leaving it out cannot
change the policy. A negated condition (`!localhost`, `!to_linklocal`), an ACL
that mixes these addresses with others, and a link-local `src` ACL still
convert. Private (RFC 1918) destinations are not refused by the proxy and
convert as usual.

## 4. ACL types: PARTIAL (converted approximately, with a note)

| Squid ACL type | Suricata match | Caveat |
|----------------|----------------|--------|
| `url_regex` | pcre on `http.uri` | Squid matches the full URL (scheme + host + path); `http.uri` is path + query only. |
| `server_cert_fingerprint` | `tls.cert_fingerprint` (lowercased), no `flow:to_server` (the certificate travels server-to-client) | Visible only in TLS 1.2 and older handshakes, and stops matching on traffic NFW decrypts. |

These are classified PARTIAL but have no rule mapping, so lines using them are
reported as not convertible: `srcdomain`, `srcdom_regex` (reverse DNS),
`user_cert`, `ca_cert` (client certificates).

## 5. NOT convertible (line skipped and reported)

If any condition on a line has no Suricata equivalent, the **whole line** is
skipped and reported, never emitted with that condition dropped. In the editor
the line appears as a `# Squid line N NOT CONVERTED (<short reason>): <line>`
comment at its position; the full reason is in the report.

| Squid ACL type | Why |
|----------------|-----|
| `proxy_auth`, `proxy_auth_regex`, `ext_user`, `ext_user_regex`, `external`, `ident`, `ident_regex` | User identity; NFW has none. (`ident` is in Squid 6 and was removed in Squid 7.) |
| `localip`, `localport`, `myportname`, old names `myip` / `myport` | Squid's own listener. In the proxy deployment rules see the real destination address and port, not the proxy listener. |
| `time`, `random` | Scheduling / probability. |
| `maxconn`, `max_user_ip` | Connection and user counting. |
| `note`, `tag`, `adaptation_service`, `transaction_initiator`, `has` | Squid-internal transaction state. |
| `snmp_community`, `peername`, `peername_regex`, `hier_code` | Squid plumbing. |
| `arp`, `eui64` | Layer-2 MAC addresses. |
| `src_as`, `dst_as` | Autonomous System numbers. |
| `clientside_mark`, `client_connection_mark` | Netfilter marks. |
| `at_step`, `ssl_error`, `connections_encrypted`, built-in `cert*` ACLs | SslBump-internal state (the report's "SslBump ACL types" section says where each is handled on AWS). |
| `rep_header`, `urllogin` | Not mapped (`rep_header` is reply-only, and `http_reply_access` is not converted). |
| `squid_error` | Squid's own `ERR_*` error condition; proxy-internal. |
| `manager` (built-in) | Cache-manager interface. |

`annotate_transaction` / `annotate_client` always match, so they are dropped
from matching; a `rule=<tag>` value is added to the rule `msg` (section 9).

A line is also reported as not convertible when it:

- references an undefined ACL, or an ACL defined with two different types;
- uses an ACL list file that was not read (not found in the config's folder, or
  outside it: section 8);
- is an `http_reply_access` line other than `allow all`;
- has a host name in a `src` ACL, or in a negated `dst` ACL;
- has two non-negated ACLs on the same header field (an intersection);
- uses a reply-only type in `http_access`;
- contains an address range that cannot be converted exactly (masked range,
  mixed IPv4/IPv6, start after end, invalid address);
- expands to more than 200 rules;
- has a rule the Generator's rule validator rejects ("rejected by the rule
  validator: …", section 6).

---

## 6. Rule validation and the `pcre` rule

Every rule is checked, in its final form (with `alert;` and the `msg`), by the
Generator's shared rule validator, the same rule-local checks used for paste and
the AI assistant. If the validator rejects any rule of a Squid line, the whole
line is reported as not convertible with the validator's message, and none of
its rules is emitted. After SIDs are assigned, the complete rule set gets the
same group checks as File > Save (duplicate SIDs, undefined variables). The
converter has no rule checker of its own, and the import is completely offline:
no AWS check, no network access, no credentials.

NFW rejects a rule that uses `pcre` unless the rule also has one of `tls.sni`,
`http.host`, `dns.query`, `http.uri` or `content` (verified with CreateRuleGroup
DryRun). For `pcre` on other buffers (`http.user_agent`, `http.header`,
`http.content_type`) the converter adds a `content` prefilter taken from text
every match of the regex must contain, always with `nocase`:

```
http.user_agent; content:"python-requests"; nocase; pcre:"/python-requests/i";
```

The `pcre` still decides, so the match is unchanged.

A negated regex can't take a prefilter (requiring the text would narrow a "does
not match" condition), and some regexes guarantee no text at all (for example a
top-level alternation). Those are emitted as a bare `pcre`; whether the finished
rule has a companion elsewhere (for example an `http.host` match on the same
line) is decided by the validator's pcre check. A line where any rule lacks one
is not convertible.

---

## 7. ACL option flags

| Squid flag | Effect |
|------------|--------|
| `-i` | `nocase;` on content, `i` flag on pcre |
| `+i` | treated like `-i` (one case flag per ACL) |
| `-n` | no-op (Suricata does not resolve names) |
| `-m` | parsed; no effect on the match |
| `--` | stops option parsing |

---

## 8. Files the converter reads

The configuration is treated as untrusted. The converter only reads files, never
runs helper programs named in the config, and reads **only** from the folder that
holds the selected `squid.conf` and its subfolders:

- Copy the contents of the Squid server's config folder (usually `/etc/squid/`)
  into the folder with `squid.conf`, keeping subfolders such as `conf.d/`.
- A relative path is looked up in that folder.
- An absolute path (`/etc/squid/...`, `C:\...`, `\\host\...`) is tried as its
  trailing sub-paths in that folder, longest first, down to the file name:
  `/etc/squid/conf.d/x.conf` is tried as `etc/squid/conf.d/x.conf`,
  `squid/conf.d/x.conf`, `conf.d/x.conf`, then `x.conf`. `include` globs follow
  the same rule.
- A path that resolves outside the folder (`..`, a symlink pointing out) is not
  read. Every file not read is reported by name ("was not found in the config's
  folder: copy it there" or "is outside the config's folder"), and lines using it
  are not convertible.
- `include` nesting is limited to 16 levels (Squid's limit) and include cycles
  are reported. Files may use CRLF or LF line endings, with or without a UTF-8
  byte-order mark; binary input is rejected.

---

## 9. Rules, SIDs, messages and comments in the editor

- **Order:** Squid's first-match order, the DNS rule first.
- **SIDs:** date-based by default (`YYMMDDNNNN`, in rule order, as for new rules
  in the editor). "Use stable (content-based) SIDs" (`--stable-sids`) keeps
  content-derived SIDs in 1000000–1999999 that are the same every time the same
  config is converted (useful for pipelines and alert history); a collision is
  resolved upward and noted. The report states the scheme and range.
- **msg:** a short trace to the source, always starting with `Squid`:
  `Squid line 244 allow tls (app_allow)`, from an include file
  `Squid conf.d/rules.conf line 4 deny http`, and `Squid import: proxy DNS` for
  the generated rule. Quotes, semicolons and backslashes become `_`; at most 120
  characters (a long include path is shortened from the left).
- **Comment rows** ("Add Squid lines as comments", on by default;
  `--no-comments`): one row above each access line's rules
  (`# Squid line 244: http_access allow AppSubnet AllowedDomains tag_app_allow`),
  and one row at the position of each line that produced no rule
  (`# Squid line 237 NOT CONVERTED (external ACL ExtEng): …` or
  `# Squid line 256 NO RULE NEEDED (deny all = firewall default action): …`).
  `http_reply_access` lines are listed at the end. No rows for `acl` lines. Rows
  are ordinary comments: saved in the `.suricata` file and sent with the rules
  when exporting to AWS. The comment above the DNS rule is always added.
- **New file:** the import starts a new, untitled file (rules, variables and
  tags replaced, change tracking off). Undo restores the previous contents.

---

## 10. Firewall prerequisites

Shown in the report (Firewall prerequisites tab) and summarised by the command
line:

- **Rule order:** a stateful rule group with STRICT_ORDER, in a firewall policy
  that also uses strict order. Under the default action order, `pass` rules
  would be evaluated before `reject`/`drop` rules.
- **Default actions:** "Application drop established" and "Application alert
  established" (both server-directed only). "Drop all" or "Drop established" drop
  the connection set-up before any rule can match the domain or URL, so they block
  traffic Squid allowed. Non-web traffic falls to these default actions.
- **Proxy DNS rule:** keep it first (section 1).
- **TLS inspection** (when the source decrypts HTTPS with `ssl_bump bump` and
  HTTP-only rules were produced; also reported as a divergence): a TLS inspection
  configuration you create (by whatever method you choose) covering the clients'
  HTTPS traffic (TCP 443), a CA certificate in AWS Certificate Manager, clients
  that trust it, the configuration added to a **new** firewall policy, and QUIC
  (UDP 443) blocked. The converter does not create a TLS inspection
  configuration.
- **Route 53 resolved domains** (when the option is on): Route 53 resolved IP
  validation on the policy; a Route 53 Resolver DNS Firewall rule group (no rules
  needed) associated with the VPCs; clients resolving through the Route 53
  Resolver; the `DnsAzUnavailableFlows` metric at zero (in an unsupported
  Availability Zone the firewall drops all traffic these rules inspect, even for
  `pass` rules); the policy setting's own action applies to all traffic that
  fails validation. The rules are stricter than Squid, which checks the name only.
  In the explicit-proxy deployment the extra protection is limited: the proxy
  already connects only to addresses it resolved for the requested name, so a
  client can't send an allowed name to an unrelated IP. Validation with the
  bypass range below and the proxy's own lookups was confirmed not to break
  normal traffic in Alert or Drop mode on a live firewall.
- **Required with Route 53 resolved domains:** add `169.254.169.253/32` to the
  policy's "Bypass destination validation IP ranges". The proxy resolves each
  name by querying that Resolver address; resolved IP validation checks that
  query like any other connection, and because the Resolver's own address never
  appears in a DNS answer, a policy action of Drop or Reject blocks it, so the
  proxy can resolve no names and all proxied traffic fails. The DNS pass rule
  does not help: the policy-level check runs independently of the rules.
  Validation still applies to the real destinations. AWS's public resolved IP
  validation documentation does not cover the proxy deployment.
- **`http_reply_access`** lines can't be enforced and are reported.

### Verified on a live proxy-mode firewall

- Plain-HTTP method, header, user-agent and URL-path rules match through the
  proxy; the Host header cannot be spoofed; a path or host deny before an
  allow still enforces on a reused connection.
- The proxy refuses bare-IP targets and loopback/link-local destinations, and
  connects only to the address it resolves for the requested name (no SNI/Host
  spoofing).
- Resolved IP validation with the `169.254.169.253/32` bypass and the proxy's
  own lookups does not break normal traffic in Alert or Drop mode.

### Not yet verified on a live firewall

- The same reused-connection behaviour **under TLS inspection** (whether a
  later request on a passed HTTPS connection is still evaluated).
- TLS inspection in the explicit-proxy deployment generally.
- VPCs that use a custom DNS resolver with the explicit-proxy deployment.

---

## 11. Combining semantics

- Same-name `acl` lines are **ORed** (values merge).
- Multiple ACLs on one access line are **ANDed**.
- `!acl` → negated content / pcre, or negated header (`!$VAR`, `![ports]`).
- **No match = opposite of the last line.** A trailing `deny all` becomes the
  default-action note; a trailing `allow all` becomes a catch-all `pass` rule
  pair. A trailing *narrow* `deny` means Squid allows unmatched requests, which
  the recommended default drop does not, so it is reported as a policy
  divergence.

## 12. Settings reported, not converted

Besides other `*_access` directives, `ssl_bump` and `sslproxy_cert_error` /
`sslproxy_cert_sign` / `sslproxy_cert_adapt`, these general settings are listed
under "Directives reported" with the reason, because they change what the policy
means: `follow_x_forwarded_for`, `acl_uses_indirect_client`,
`url_rewrite_program` / `redirect_program`, `auth_param`, `auth_schemes`,
`external_acl_type`, `request_body_max_size`, `reply_body_max_size`,
`client_ip_max_connections`, the `delay_*` / `client_delay_*` /
`response_delay_pool` bandwidth settings, the Squid 2.x `http_access2`, the
ICAP/eCAP `icap_service`, `ecap_service`, `adaptation_service_set` and
`adaptation_service_chain`, and the interception settings `host_verify_strict`
(Squid checks the Host name against the destination IP; converted domain rules
check the name only, and "Use Route 53 resolved domains" is the closest
equivalent) and `client_dst_passthru`.

---

## 13. Worked example

**Squid:**
```
acl clients  src 10.0.0.0/8
acl approved dstdomain .google.com checkip.amazonaws.com
acl Safe_ports port 80
acl Safe_ports port 443
http_access deny !Safe_ports
http_access allow clients approved
http_access deny all
```

**Generator rules (defaults: reject, alert on pass, comments, date-based SIDs):**
```
# Squid import: lets the Network Firewall proxy resolve destination names through the Route 53 Resolver (169.254.169.253). Without it every proxied request fails. Keep this rule first.
pass dns any any -> 169.254.169.253 53 (msg:"Squid import: proxy DNS"; flow:to_server; alert; sid:2610300001; rev:1;)
# Squid line 5: http_access deny !Safe_ports
reject http any any -> any !$SAFE_PORTS (msg:"Squid line 5 deny http"; flow:to_server; sid:2610300002; rev:1;)
reject tls any any -> any !$SAFE_PORTS (msg:"Squid line 5 deny tls"; flow:to_server; sid:2610300003; rev:1;)
# Squid line 6: http_access allow clients approved
pass http $CLIENTS any -> any any (msg:"Squid line 6 allow http"; flow:to_server; http.host; dotprefix; content:".google.com"; endswith; alert; sid:2610300004; rev:1;)
pass tls $CLIENTS any -> any any (msg:"Squid line 6 allow tls"; flow:to_server; tls.sni; dotprefix; content:".google.com"; endswith; nocase; alert; sid:2610300005; rev:1;)
pass http $CLIENTS any -> any any (msg:"Squid line 6 allow http"; flow:to_server; http.host; content:"checkip.amazonaws.com"; startswith; endswith; alert; sid:2610300006; rev:1;)
pass tls $CLIENTS any -> any any (msg:"Squid line 6 allow tls"; flow:to_server; tls.sni; content:"checkip.amazonaws.com"; startswith; endswith; nocase; alert; sid:2610300007; rev:1;)
# Squid line 7 NO RULE NEEDED (deny all = firewall default action): http_access deny all
```

`$CLIENTS = 10.0.0.0/8` (description "Squid acl clients (src)") and
`$SAFE_PORTS = [80,443]` (description "Squid acl Safe_ports (port)") go to the
Variables tab (and the `.var` file).
