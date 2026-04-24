# Suricata Rules Complete Reference
# Source: https://docs.suricata.io/en/latest/rules/index.html
# Compiled from official Suricata documentation

## Meta Keywords

Meta keywords have no effect on inspection — they affect how Suricata reports events.

### msg (message)
Format: `msg:"description";`
- Must be first keyword in signature (standard practice)
- Characters ; \ " must be escaped
- Convention: first part uppercase indicating signature class

### sid (signature ID)
Format: `sid:<number>;`
- Must be unique within the rule group
- Standard practice: sid is last keyword (or second-to-last before rev)
- Reserved ranges at https://sidallocation.org/
- Engine events range: 2200000-2299999

### rev (revision)
Format: `rev:<number>;`
- Incremented when signature is modified
- Standard practice: rev is the last keyword, after sid

### gid (group ID)
Format: `gid:<number>;`
- Default is 1, rarely changed

### classtype
Format: `classtype:<class>;`
- Assigns classification and priority from classification.config
- Examples: web-application-attack (priority 1), not-suspicious (priority 3), bad-unknown, trojan-activity
- Standard practice: placed before sid and rev

### reference
Format: `reference:<type>,<reference>;`
- Can appear multiple times
- Types: url, cve (e.g., reference:cve,CVE-2014-1234)

### priority
Format: `priority:<1-255>;`
- 1 = highest priority, commonly 1-4 used
- Overrides classtype priority when specified

### metadata
Format: `metadata:key value;` or `metadata:key value, key value;`
- Non-functional, included in eve alerts
- Recommended: key-value pairs

### target
Format: `target:[src_ip|dest_ip];`
- Specifies which side is the attack target

## Header Keywords (IP, TCP, UDP, ICMP)

### IP Keywords
- `ttl:<number>` — match IP time-to-live (0-255)
- `ipopts:<option>` — match IP options (rr, eol, nop, ts, sec, lsrr, ssrr, satid, any)
- `sameip` — match when source IP equals destination IP
- `ip_proto:<protocol>` — match IP protocol number or name (1=ICMP, 6=TCP, 17=UDP, 47=GRE, etc.)
- `geoip:<direction>,<country_codes>` — match GeoIP country (src, dst, both, any)
  - Example: `geoip:dst,RU,CN;` or `geoip:both,US,CA;`
  - Requires MaxMind GeoIP2/GeoLite2 database
- `fragbits:[modifier]<bits>` — match IP fragmentation flags (M=More Fragments, D=Don't Fragment, R=Reserved)
  - Modifiers: + (all plus others), * (any set), ! (not set), = (exact match)
- `fragoffset:[!|<|>]<number>` — match IP fragment offset
- `ipv4.hdr` — sticky buffer for IPv4 header content
- `ipv6.hdr` — sticky buffer for IPv6 header content

### TCP Keywords
- `tcp.flags:[modifier]<flags>[,<mask>]` — match TCP flags
  - Flags: F(FIN), S(SYN), R(RST), P(PSH), A(ACK), U(URG), C(CWR), E(ECE), 0(none)
  - Modifiers: + (all plus others), * (any set), ! (not set), = (exact)
  - Mask example: `tcp.flags:S,CE;` (SYN regardless of CWR/ECE)
- `seq:<number>` — match TCP sequence number
- `ack:<number>` — match TCP acknowledgement number
- `window:[!]<number>` — match TCP window size
- `tcp.mss:<value>` — match TCP MSS option value
- `tcp.wscale:<value>` — match TCP window scaling option
- `tcp.hdr` — sticky buffer for entire TCP header

### UDP Keywords
- `udp.hdr` — sticky buffer for entire UDP header

### ICMP Keywords
- `itype:[<|>]<number>` or `itype:min<>max` — match ICMP type
  - Common: 0=Echo Reply, 3=Dest Unreachable, 8=Echo Request, 11=Time Exceeded
- `icode:[<|>]<number>` or `icode:min<>max` — match ICMP code
- `icmp_id:<number>` — match ICMP ID
- `icmp_seq:<number>` — match ICMP sequence number
- `icmpv4.hdr` / `icmpv6.hdr` — sticky buffers for ICMP headers
- `icmpv6.mtu:<value>` — match ICMPv6 MTU option

## Payload Keywords

### content
Format: `content:"<pattern>";`
- Matches bytes in payload. Case-sensitive by default.
- Hex notation: `content:"|0D 0A|";` (pipe-delimited hex bytes)
- Mixed: `content:"http|3A|//";`
- Negation: `content:!"pattern";`
- Escape: ; \ " must be escaped

### Content Modifiers
- `nocase` — case-insensitive matching
- `depth:<bytes>` — how many bytes from start to search
- `offset:<bytes>` — skip N bytes before searching
- `startswith` — match at start of buffer (shorthand for depth+offset:0)
- `endswith` — match at end of buffer (shorthand for isdataat:!1,relative)
- `distance:<bytes>` — bytes to skip after previous match (can be negative)
- `within:<bytes>` — search within N bytes after previous match

### dsize
Format: `dsize:[<>!]<number>` or `dsize:min<>max`
- Matches packet payload size
- WARNING: per-packet only, NOT total HTTP body size
- Cannot be used with app-layer keywords (http.uri, etc.)

### bsize
Format: `bsize:<number>` or `bsize:[<|>|<=|>=]<number>` or `bsize:lo<>hi`
- Matches length of a sticky buffer
- Must follow a sticky buffer keyword

### byte_test
Format: `byte_test:<num_bytes>,<operator>,<test_value>,<offset>[,relative][,endian][,string,<type>][,bitmask <value>]`
- Extracts bytes and tests against a value
- Operators: <, >, =, <=, >=, &, ^, ! (prefix)
- String types: hex, dec, oct
- When num_bytes is 0 with string modifier, auto-detects string length
- Example: `byte_test:0,>=,1048576,0,string,dec;` (test if decimal string >= 1MB)

### byte_jump
Format: `byte_jump:<num_bytes>,<offset>[,relative][,multiplier <value>][,endian][,string,<type>][,align][,from_beginning][,from_end][,post_offset <value>]`
- Extracts bytes and moves detection pointer to that position

### byte_extract
Format: `byte_extract:<num_bytes>,<offset>,<var_name>[,relative][,multiplier <value>][,endian][,string,<type>]`
- Extracts bytes and stores in variable for use by other keywords

### byte_math
Format: `byte_math:bytes <num>,offset <offset>,oper <op>,rvalue <val>,result <var>[,relative][,endian][,string,<type>]`
- Performs math on extracted values: +, -, *, /, <<, >>

### pcre
Format: `pcre:"/<regex>/<modifiers>";`
- Perl Compatible Regular Expressions
- Modifiers: i (case-insensitive), s (dotall), m (multiline)
- Suricata modifiers: R (relative), U (normalized URI), I (raw URI), P (request body), Q (response body), H (header)
- Performance impact — combine with content for pre-filtering
- **AWS Network Firewall restriction:** pcre is only allowed with `content`, `tls.sni`, `http.host`, `http.uri`, and `dns.query` keywords — pcre cannot be used alone

### isdataat
Format: `isdataat:<position>[,relative]`
- Check if data exists at position
- Can be negated: `isdataat:!1,relative;` (no more data after match)

### absent
Format: `absent;` or `absent: or_else;`
- Checks that a sticky buffer does not exist
- Example: `http.referer; absent;` (no Referer header)

## Flow Keywords

### flow
Format: `flow:<option>[,<option>]`
- `to_server` / `from_client` — packets from client to server
- `to_client` / `from_server` — packets from server to client
- `established` — established connections (TCP: after 3-way handshake; UDP: after traffic from both sides)
- `not_established` — packets not part of established connection
- `stateless` — packets part of a flow regardless of connection state
- `only_stream` — reassembled stream packets only
- `no_stream` — non-reassembled packets only
- `only_frag` — reassembled fragment packets
- `no_frag` — non-fragmented packets
- Multiple options combined: `flow:to_server,established,only_stream`

### flowbits
Format: `flowbits:<action>,<name>`
- `set,name` — set condition in flow
- `isset,name` — alert only if condition is set
- `isnotset,name` — alert only if condition is NOT set
- `toggle,name` — reverse the condition
- `unset,name` — remove condition
- `noalert` — suppress alert for this rule
- OR operation: `flowbits:isset,name1|name2;`
- Names are case-sensitive

### flowint
Format: `flowint:name,<modifier>[,value]`
- Store and manipulate integer variables in flows
- Operations: =, +, -, >, <, >=, <=, ==, !=
- Check: isset, notset/isnotset
- Useful for counting occurrences, thresholding within streams

### stream_size
Format: `stream_size:<server|client|both|either>,<modifier>,<number>`
- Match on registered byte count by sequence numbers
- Modifiers: >, <, =, !=, >=, <=

### flow.age
Format: `flow.age:[op]<seconds>`
- Match on flow age in seconds

### flow.pkts / flow.bytes
Format: `flow.pkts:<direction>,[op]<number>` / `flow.bytes:<direction>,[op]<number>`
- Directions: toclient, toserver, either, both


## HTTP Keywords

HTTP sticky buffers provide efficient inspection of specific HTTP fields.
Sticky buffer must appear BEFORE the content match it modifies.
All HTTP keywords work with payload keywords (content, pcre, bsize, etc.).

### Request Keywords

- `http.uri` — normalized request URI (double slashes collapsed, etc.)
  - Example: `http.uri; content:"/index.html"; bsize:11;`
- `http.uri.raw` — raw URI without normalization (does not allow spaces)
- `http.method` — HTTP method/verb (GET, POST, HEAD, OPTIONS, PUT, DELETE, TRACE, CONNECT, PATCH)
  - Example: `http.method; content:"POST";`
- `http.host` — normalized hostname (lowercased, no port)
  - `nocase` not allowed (already lowercase)
  - Does not include port — use `http.host.raw` for host:port matching
  - Example: `http.host; content:"example.com"; bsize:11;`
- `http.host.raw` — raw hostname without normalization (preserves case, includes port)
- `http.user_agent` — User-Agent header value (better performance than http.header)
  - Example: `http.user_agent; content:"Mozilla/5.0";`
- `http.referer` — Referer header value
- `http.request_body` — HTTP request body content
  - Inspection size controlled by `request-body-limit` in libhtp config
- `http.request_header` — match on header name + value pair
  - Format: `http.request_header; content:"Host|3a 20|example.com";`
  - `|3a 20|` = ": " (colon space separator)
- `http.request_line` — entire request line (e.g., "GET /index.html HTTP/1.1")
- `http.accept` — Accept header value
- `http.accept_enc` — Accept-Encoding header value
- `http.accept_lang` — Accept-Language header value
- `file.name` — filename from HTTP request (e.g., "picture.jpg" from GET /picture.jpg)
- `urilen` — match on normalized URI length
  - Operators: `urilen:11;` (exact), `urilen:>10;` (greater), `urilen:<100;` (less), `urilen:10<>100;` (range)

### Response Keywords

- `http.stat_code` — HTTP status code (e.g., "200", "404")
  - Example: `http.stat_code; content:"200";`
- `http.stat_msg` — HTTP status message (e.g., "OK", "Not Found")
  - Always empty for HTTP/2
- `http.response_body` — HTTP response body (matches gzip decoded data)
  - Inspection size controlled by `response-body-limit` in libhtp config
- `http.response_header` — match on response header name + value pair
  - Format: `http.response_header; content:"Location|3a 20|example.com";`
- `http.response_line` — entire response line (e.g., "HTTP/1.1 200 OK")
- `http.location` — Location header value (redirects)
- `http.server` — Server header value

### Request or Response Keywords

- `http.cookie` — Cookie (request) or Set-Cookie (response) value
  - Cookies are extracted from headers — won't match in `http.header` buffer
- `http.header` — normalized header content (trailing whitespace removed)
  - Does NOT include cookies (use `http.cookie` instead)
  - Format: `http.header; content:"User-Agent|3a 20|Mozilla/5.0|0d 0a|";`
  - `|0d 0a|` = \r\n (line terminator)
- `http.header.raw` — raw header content without normalization
- `http.header_names` — header names only (for presence/absence/order checking)
  - Starts with \r\n, ends with extra \r\n
  - Presence: `http.header_names; content:"|0d 0a|Host|0d 0a|";`
  - Absence: `http.header_names; content:!"|0d 0a|User-Agent|0d 0a|";`
- `http.content_len` — Content-Length header value (text string)
  - For numeric comparison, use with `byte_test`:
  - `http.content_len; byte_test:0,>=,100,0,string,dec;` (Content-Length >= 100)
  - `byte_test:0,...` with string modifier = auto-detect string length
- `http.content_type` — Content-Type header value
  - Example: `http.content_type; content:"text/html"; bsize:9;`
- `http.protocol` — HTTP protocol version (e.g., "HTTP/1.1", "HTTP/2")
- `http.start` — request/response line + all headers (terminated by extra \r\n)
- `http.connection` — Connection header value
- `file.data` — HTTP response body (also works for request body and other protocols)
  - Matches gzip/deflate decoded data
  - Supports multiple buffer matching

### Normalization Notes
- Duplicate headers with same name are concatenated with ", " (per RFC 2616)
- `http.host` lowercases all characters
- `http.header` removes trailing whitespace/tabs
- `http.uri` normalizes double slashes and other URI anomalies
- `.raw` variants skip normalization for matching original traffic

## TLS/SSL Keywords

TLS keywords match on properties of TLS/SSL handshakes. All sticky buffers support payload keywords.

### Core TLS Sticky Buffers
- `tls.sni` — Server Name Indication (hostname client wants to connect to)
  - Most commonly used TLS keyword for domain-based detection
  - Example: `tls.sni; content:"malware.com"; nocase; isdataat:!1,relative;`
  - Example: `tls.sni; content:"example.com"; nocase; pcre:"/example\.com$/";`
- `tls.cert_subject` — certificate Subject field (CN=, O=, etc.)
  - Example: `tls.cert_subject; content:"CN=*.googleusercontent.com"; isdataat:!1,relative;`
- `tls.cert_issuer` — certificate Issuer field
  - Example: `tls.cert_issuer; content:"Let's Encrypt"; nocase;`
- `tls.cert_serial` — certificate serial number
  - Example: `tls.cert_serial; content:"5C:19:B7:B1:32:3B:1C:A1";`
- `tls.cert_fingerprint` — SHA-1 fingerprint of certificate
- `tls.subjectaltname` — Subject Alternative Name field
- `tls.certs` — raw match on certificate chain bytes
- `tls.alpn` — ALPN (Application-Layer Protocol Negotiation) buffer
  - Example: `tls.alpn; content:"http/1.1";`

### TLS Version Matching
- `tls.version` — negotiated TLS version: "1.0", "1.1", "1.2", "1.3"
  - Example: `tls.version:1.2;`
- `ssl_version` — match SSL/TLS record version: sslv2, sslv3, tls1.0, tls1.1, tls1.2, tls1.3
  - Multiple: `ssl_version:sslv2,sslv3;`
  - Negation: `ssl_version:!tls1.2,!tls1.3;` (match if NOT these versions)

### TLS Certificate Validity
- `tls_cert_notbefore` — match NotBefore date (format: YYYY-MM-DD or ranges)
  - Example: `tls_cert_notbefore:1998-05-01<>2008-05-01;`
- `tls_cert_notafter` — match NotAfter date
  - Example: `tls_cert_notafter:>2015;`
- `tls_cert_expired` — true if certificate is expired
- `tls_cert_valid` — true if certificate is not expired (does NOT validate chain)

### Other TLS Keywords
- `tls.cert_chain_len` — certificate chain length (integer comparison)
  - Example: `tls.cert_chain_len:>0;` or `tls.cert_chain_len:1;`
- `ssl_state` — match SSL connection state: client_hello, server_hello, client_keyx, server_keyx, unknown
  - OR syntax: `ssl_state:client_hello|server_hello;`
- `tls.random` — 32-byte TLS random field (sticky buffer)
- `tls.fingerprint` — SHA1 fingerprint (legacy, lowercase hex)
- `tls.store` — store certificate to disk

## DNS Keywords

DNS keywords match on DNS message fields. Sticky buffers must be followed by payload keywords.

### DNS Query Matching
- `dns.query` — DNS query name in request messages (sticky buffer)
  - Normalized: dots instead of length bytes, no trailing NULL
  - Example: `dns.query; content:"google.com"; nocase;`
  - Example: `dns.query; content:"malware"; nocase; pcre:"/\.malware\.(com|net)$/";`
  - Only matches DNS requests (use `dns.queries.rrname` for both directions)
- `dns.queries.rrname` — query name in both requests AND responses
  - Use with `flow` to restrict direction
  - Supports multi-buffer matching

### DNS Response Matching
- `dns.answers.rrname` — name field in DNS answer records
- `dns.authorities.rrname` — name field in DNS authority records
- `dns.additionals.rrname` — name field in DNS additional records
- `dns.response.rrname` — all name/rdata fields in DNS response records
  - Matches CNAME, PTR, MX, NS, SOA rdata
  - Supports multi-buffer matching

### DNS Header Fields
- `dns.opcode` — DNS opcode (0=Query, 1=IQuery, 2=Status, 4=Notify, 5=Update)
  - Example: `dns.opcode:0;` or `dns.opcode:!0;`
- `dns.rcode` — DNS response code (0=NoError, 2=ServFail, 3=NXDomain, 5=Refused)
  - Example: `dns.rcode:3;` (match NXDOMAIN responses)
- `dns.rrtype` — DNS record type (1=A, 5=CNAME, 15=MX, 28=AAAA, 33=SRV, 255=ANY)
  - Example: `dns.rrtype:255;` (match ANY queries)

## File Keywords

File keywords match on file properties in flows. Require file extraction configuration.

- `file.data` — file content (sticky buffer, works across HTTP, SMTP, FTP, NFS, etc.)
  - Matches gzip/deflate decoded data
  - Example: `file.data; content:"MZ"; startswith;` (detect PE executables)
- `file.name` — filename (sticky buffer)
  - Example: `file.name; content:".exe"; nocase; endswith;`
- `fileext` — exact file extension match (case-insensitive, no partial match)
  - Example: `fileext:"pdf";`
- `file.magic` — libmagic file type description (sticky buffer)
  - Example: `file.magic; content:"executable for MS Windows";`
- `filesize` — file size with units (KB, MB, GB)
  - Example: `filesize:>100MB;` or `filesize:100<>200;` (range in bytes)
  - For incomplete files (packet loss), only "greater than" is checked
- `filestore` — store matching files to disk
  - Syntax: `filestore:<direction>,<scope>;`
  - Direction: request/to_server, response/to_client, both
  - Scope: file, tx, ssn/flow
- `filemd5` / `filesha1` / `filesha256` — match against hash blacklists/whitelists
  - Example: `filemd5:md5-blacklist;` or `filemd5:!md5-whitelist;`

## Thresholding Keywords

Control alert frequency and rate limiting.

**AWS Network Firewall caveat:** Thresholding keywords have limited support. Test thoroughly before relying on them in production environments.

### threshold
Format: `threshold: type <threshold|limit|both|backoff>, track <by_src|by_dst|by_rule|by_both|by_flow>, count <N>, seconds <T>;`

- `type threshold` — alert every Nth match within time window
  - Example: `threshold: type threshold, track by_src, count 10, seconds 60;`
- `type limit` — max N alerts per time window (suppress flood)
  - Example: `threshold: type limit, track by_src, count 1, seconds 180;`
- `type both` — combine threshold + limit (alert once per window after N matches)
  - Example: `threshold: type both, track by_src, count 5, seconds 360;`
- `type backoff` — exponential backoff (only with track by_flow)
  - Example: `threshold: type backoff, track by_flow, count 1, multiplier 10;`
  - Alerts at: 1st, 10th, 100th, 1000th match, etc.

Track options: by_src, by_dst, by_both (src+dst pair), by_rule (signature), by_flow

### detection_filter
Format: `detection_filter: track <by_src|by_dst|by_rule|by_both|by_flow>, count <N>, seconds <T>;`
- Alert on every match AFTER initial threshold reached
- Example: `detection_filter: track by_src, count 15, seconds 2;`
- Optional `unique_on <src_port|dst_port>` for distinct counting (TCP/UDP only)
  - Example: `detection_filter: track by_dst, count 10, seconds 60, unique_on dst_port;` (port scan detection)

## SSH Keywords

SSH keywords match on SSH connection properties. All sticky buffers support payload keywords.

- `ssh.proto` — SSH protocol version (sticky buffer)
  - Example: `ssh.proto; content:"2.0";`
- `ssh.software` — SSH software string from banner (sticky buffer)
  - Example: `ssh.software; content:"openssh"; nocase;`
- `ssh.hassh` — HASSH fingerprint (MD5 of client algorithms, sticky buffer)
  - Example: `ssh.hassh; content:"ec7378c1a92f5a8dde7e8b7a1ddf33d1";`
- `ssh.hassh.string` — HASSH algorithm string (client, sticky buffer)
- `ssh.hassh.server` — HASSH server fingerprint (MD5, sticky buffer)
- `ssh.hassh.server.string` — HASSH server algorithm string (sticky buffer)

## Transforms

Transforms modify sticky buffer data before matching. Applied after the buffer keyword, before content.
Can be chained — each transform's output feeds the next.

- `dotprefix` — prepend "." to buffer (for domain matching)
  - Example: `dns.query; dotprefix; content:".microsoft.com"; endswith;`
  - Matches "windows.update.microsoft.com" but NOT "fakemicrosoft.com"
- `domain` — extract domain name using Mozilla Public Suffix List
  - Example: `tls.sni; domain; dataset:isset,domains,type string,load domains.lst;`
- `tld` — extract Top Level Domain using Mozilla Public Suffix List
- `strip_whitespace` — remove all whitespace
- `compress_whitespace` — collapse consecutive whitespace to single space
- `to_lowercase` / `to_uppercase` — case conversion
- `to_md5` / `to_sha1` / `to_sha256` — hash the buffer content
- `url_decode` — decode URL-encoded data (%HH and + to space)
- `from_base64` — decode base64 data
  - Options: `bytes <N>`, `offset <N>`, `mode: strict|rfc4648|rfc2045`
  - Example: `content:"VGhpcyBpcyBTdXJpY2F0YQ=="; from_base64; content:"This is Suricata";`
- `header_lowercase` — lowercase HTTP header names (for HTTP/1 + HTTP/2 normalization)
- `strip_pseudo_headers` — strip HTTP/2 pseudo-headers
- `xor` — XOR decode with hex key
  - Example: `http.uri; xor:"0d0ac8ff"; content:"password=";`
- `gunzip` — gzip decompression (optional: `max-size <N>`, default 1024)
- `zlib_deflate` — zlib decompression (optional: `max-size <N>`, default 1024)

## AWS Network Firewall Specific Keywords

These keywords are specific to AWS Network Firewall and are not part of standard open-source Suricata.

### URL and Domain Category Filtering

- `aws_url_category:<category>[,<category>]` — Match traffic by URL/domain category
  - Supported protocol in rules: HTTP
  - For HTTP traffic: evaluates complete URLs
  - For HTTPS traffic: requires TLS inspection enabled on the firewall
  - Falls back to domain-level evaluation if no URL match found
  - Example: `aws_url_category:Malicious;`
  - Example: `aws_url_category:Gambling,Social Networking;`

- `aws_domain_category:<category>[,<category>]` — Match traffic by domain category
  - Supported protocols in rules: TLS, HTTP
  - For HTTP: evaluates domain from Host header
  - For TLS: evaluates domain from SNI field
  - No TLS inspection required
  - Example: `aws_domain_category:Malware;`
  - Example: `aws_domain_category:Malware,Phishing;`

**Constraint:** CANNOT combine `aws_url_category` or `aws_domain_category` with `geoip` in the same rule. Create separate rules for category and geographic filtering.

**Supported Categories:**
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

### JA4 Fingerprinting

- `ja4.hash` — JA4 TLS fingerprint hash (sticky buffer)
  - Newer and more granular than JA3
  - Example: `ja4.hash; content:"_";` (match any JA4 hash containing underscore)

### HTTP/2 Keywords

- `http2.header_name` — HTTP/2 header name sticky buffer
  - Used for matching HTTP/2 pseudo-headers (e.g., `:authority`, `:method`, `:path`)
  - Requires TLS inspection to decrypt HTTP/2 traffic
  - Example: `http2.header_name; content:"authority";`

### IP Set References

- `@VARIABLE_NAME` — Reference a VPC prefix list in rule source/destination
  - The variable must be defined in the rule group's `ReferenceSets.IPSetReferences`
  - Example: `drop tcp @BETA any -> any any (sid:1;)`

### Pass Rule Alert Keyword

- `alert` — When used inside a pass rule, generates an alert log entry for the matched traffic
  - Pass rules normally do not generate logs; the `alert` keyword overrides this
  - Example: `pass tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:".example.com"; dotprefix; endswith; nocase; alert; sid:202307052;)`

### AWS Network Firewall Unsupported Keywords

The following standard Suricata keywords are NOT supported by AWS Network Firewall:
- `filesize`, `filemagic`, `fileext`, `filemd5`, `filesha1`, `filesha256`, `filestore`
- `dataset`, `datarep`, `iprep`

For file size detection, use `http.content_len` with `byte_test` or `stream_size`.
For file type detection, use `file_data` with content matching for file signatures.

## AWS Network Firewall Rule Evaluation

### Default Action Order
Rules processed by action type: pass → drop → reject → alert. Use `priority` keyword to influence ordering within action types.

### Strict Order (Recommended)
Rules processed top-to-bottom. Earlier rules take precedence. Use with `drop established (application layer)` default action for full application layer reassembly before drop decisions. The `priority` keyword is NOT supported in strict order rule groups.

### Stateless vs Stateful Engine
- Stateless engine inspects packets individually (like VPC NACLs)
- Stateful engine inspects traffic flows using Suricata IPS rules
- Recommended: set stateless default to "Forward to stateful rule groups"
- Stateful engine provides deep packet inspection, automatic return traffic handling, logging, and reject action
