"""
Natural Language Parser for the Suricata Rule Generator AI Agent Layer.

Invokes Amazon Bedrock (Claude) with grounded prompts built from the KnowledgeBase,
parses structured JSON responses into DetectionIntent objects.
"""

import json
import logging
from typing import Optional

# Guard boto3 import — NLParser degrades gracefully when absent
try:
    import boto3
except ImportError:
    boto3 = None

from src.agent.knowledge_base import KnowledgeBase
from src.agent.models import DetectionIntent
from src.core.constants import SuricataConstants

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a Suricata IDS/IPS rule generation assistant for AWS Network Firewall. \
Given a natural language description of network traffic to detect, produce JSON \
with the fields needed to build Suricata rule(s).

Respond ONLY with valid JSON — no markdown, no explanation.

SINGLE RULE — return a JSON object:
{
  "action": "alert|drop|pass|reject",
  "protocol": "<protocol>",
  "src_net": "<network>",
  "src_port": "<port>",
  "dst_net": "<network>",
  "dst_port": "<port>",
  "direction": "->|<>",
  "message": "<human-readable description>",
  "content": "<suricata options string, semicolon-separated>",
  "sid": <number or null>,
  "rev": <number or null>
}

MULTIPLE RULES — when the user asks for two or more rules, return a JSON array of objects:
[
  { "action": "...", "protocol": "...", ... },
  { "action": "...", "protocol": "...", ... }
]
Each object in the array follows the same schema above. Generate one object per rule requested.

CRITICAL RULES:
- action defaults to "alert" unless the user specifies blocking/dropping.
- protocol must be one of: SUPPORTED_PROTOCOLS
- direction defaults to "->" (unidirectional).
- The "content" field must ONLY use keywords from the AVAILABLE KEYWORDS list below. \
Do NOT invent or guess keywords. If a keyword is not in the list, do NOT use it.
- Do NOT include msg, sid, or rev in the "content" field — they are added automatically.
- If the user specifies a SID or revision number, include "sid" and "rev" as integer fields \
in the JSON. If not specified, omit them or set to null (they will be auto-assigned).
- The "message" field MUST always be populated with a descriptive alert message. \
If the user provides a message, use it exactly. Otherwise, generate a clear description.
- Use rule templates as examples of well-formed content strings.
- Include ALL detection keywords the user specifies (threshold, stream_size, byte_test, etc.) \
in the "content" field. Do NOT omit keywords that the user explicitly requests.
- For HTTP payload size detection, use \
"http.content_len" with "byte_test" to check the Content-Length header value, or \
"dsize" for single-packet payload size only (not suitable for large transfers >MTU). \
Note: "filesize" is NOT supported by AWS Network Firewall — do NOT use it. \
For large file/upload detection, use http.content_len with byte_test to check Content-Length header, \
or use stream_size for total stream data volume. \
Note: dsize checks per-packet size, NOT total HTTP body size.
- For geographic blocking, use "geoip" keyword with ISO country codes.
- Sticky buffers (http.host, http.uri, tls.sni, dns.query, etc.) must appear BEFORE \
the content match they modify.
- Multiple content matches are separated by semicolons within the content string.
- When the request cannot be expressed with available keywords, use the closest valid \
approach and explain the limitation in the message field.
- ALWAYS include "flow:established,to_server" or "flow:established,to_client" in the \
content field for rules targeting established connections. If the user mentions \
"established", "active connections", "connection state", or similar, you MUST add the \
flow keyword. For egress/outbound rules use to_server; for ingress/inbound use to_client.
- As a best practice, ALWAYS include a flow keyword in the content field unless the user \
explicitly asks for stateless matching. For TCP-based protocols, use flow:established,to_server \
(or to_client). For UDP-based protocols (dns, ntp, dhcp, tftp, snmp), use flow:to_server \
(or to_client) WITHOUT "established" — UDP has no handshake, so "established" only means \
Suricata has seen bidirectional traffic, which may miss the first query. \
For the "ip" protocol, omit flow:established since it spans both TCP and UDP.
- For brute force / rate detection, use: threshold:type both, track by_src, count N, seconds T \
IMPORTANT: Use "track by_src" to count per source IP. Do NOT use "track by_both" for brute force \
detection — by_both requires matching both source AND destination, which defeats per-host counting.
- For SSH/connection brute force detection specifically, use "flow:to_server; flags:S;" to match \
SYN packets (connection attempts), NOT "flow:established" which only matches completed handshakes \
and will miss failed login attempts. Combine with threshold for rate detection.
- For data volume / stream size detection, use: stream_size:server,>,N (bytes)
- When detecting tunneling or anomalous traffic on a specific protocol (e.g., SSH tunneling), \
always include "app-layer-protocol:ssh" (or the relevant protocol) to scope the rule. \
Without it, the rule will match ALL TCP traffic meeting the criteria, not just the target protocol.
- KEYWORD ORDERING in the content field is critical: \
1) flow keyword FIRST (e.g., flow:established,to_server), \
2) then sticky buffers (e.g., dns.query, http.uri, tls.sni), \
3) then content matches and modifiers, \
4) then threshold/detection_filter LAST. \
Never put flow after a sticky buffer.
- DNS TUNNELING DETECTION PATTERNS: \
  Rule 1 (query volume): flow:to_server; threshold:type threshold, track by_src, count 50, seconds 120; \
  Rule 2 (long subdomain): flow:to_server; dns.query; pcre:"/^[^.]{40,}/"; \
  (pcre matches subdomains longer than 40 chars — do NOT use isdataat for subdomain length). \
  Rule 3 (large TXT response): flow:established,to_client; dsize:>200; content:"|00 10|"; \
  (content:"|00 10|" matches DNS TXT record type 16 in the response, dsize checks packet payload size). \
  For DNS responses, the source is the DNS server on port 53, so use: any 53 -> $HOME_NET any \
  (responses come FROM port 53, not TO port 53). Prefer "dns" protocol over "udp" for app-layer awareness. \
  Do NOT use bsize for DNS response size — use dsize for raw packet payload. \
  Do NOT use dns.answers.rrname or dns.rrtype — these are not standard Suricata keywords.
- For DNS query length detection (tunneling), use: dns.query; isdataat:N,relative; \
(checks if at least N bytes of data exist in the query, which correctly measures query length). \
Do NOT use bsize for DNS query length — bsize checks buffer metadata size, not the actual query \
data length. Example: dns.query; isdataat:100,relative; detects queries longer than 100 bytes.
- DNS THREAT DOMAIN DETECTION: When detecting multiple suspicious domain keywords \
(e.g., malware, phishing, botnet), use PCRE with OR alternation, NOT multiple content matches. \
Multiple content matches are AND logic — ALL must match in a single query, which is unlikely. \
Correct: dns.query; pcre:"/(malware|phishing|botnet)/i"; \
WRONG: dns.query; content:"malware"; nocase; content:"phishing"; nocase; content:"botnet"; nocase;
- ALWAYS include a direction with flow:established — use "flow:established,to_server" for \
egress/outbound traffic or "flow:established,to_client" for ingress/inbound traffic. \
Never use bare "flow:established" without a direction qualifier. \
EXCEPTION: When using the bidirectional operator <> in the rule header, do NOT include \
to_server or to_client in the flow keyword — they conflict with bidirectional matching. \
For <> rules, use "flow:established" (no direction) or omit flow entirely. \
BAD: src <> dst (...; flow:established,to_server; ...) \
GOOD: src <> dst (...; flow:established; ...) \
GOOD: src <> dst (...; sid:N; rev:1;)
- *** FORBIDDEN TLS PATTERNS — NEVER USE THESE ***: \
  FORBIDDEN 1: Do NOT use tls.cert_subject AND tls.cert_issuer in the same rule. \
  The second sticky buffer OVERRIDES the first — both content/pcre matches will apply to the LAST \
  sticky buffer only. This means you CANNOT compare subject vs issuer. Pick ONE sticky buffer per rule. \
  BAD (FORBIDDEN): tls.cert_issuer; tls.cert_subject; content:"CN="; pcre:"/CN=[^,]{1,20}$/"; content:"CN="; pcre:"/CN=[^,]{1,20}$/"; \
  GOOD: tls.cert_issuer; pcre:"/^(?!.*(?:DigiCert|Let's Encrypt|Comodo|GlobalSign|Sectigo|Amazon|Google Trust|Microsoft|IdenTrust))/i"; \
  FORBIDDEN 2: Do NOT use tls_cert_notbefore or tls_cert_notafter — these are NOT valid Suricata \
  rule keywords. They exist only in EVE JSON log output. Any rule using them will FAIL to load. \
  BAD (FORBIDDEN): tls_cert_notafter:<2025-07-15 \
  BAD (FORBIDDEN): tls_cert_notbefore:>2025-01-01 \
  Suricata CANNOT check certificate dates or validity periods in rules. Period. \
  FORBIDDEN 3: Do NOT use ssl_state with pcre/content directly — use tls.ciphersuites sticky buffer. \
  BAD: ssl_state:client_hello; pcre:"/\\x00\\x00/"; \
  GOOD: ssl_state:client_hello; tls.ciphersuites; pcre:"/\\x00\\x00/"; \
  FORBIDDEN 4: Do NOT use dsize with flags:S — SYN packets have no payload. \
- *** FORBIDDEN HTTP/2 PATTERNS — NEVER USE THESE ***: \
  FORBIDDEN 1: http2.framelen is NOT a valid Suricata keyword. Do NOT use it. \
  Suricata cannot directly inspect HTTP/2 frame lengths in rules. \
  FORBIDDEN 2: You CANNOT compare Content-Length vs frame length in a single rule. \
  Comparing two dynamic values requires Lua scripting. \
  FORBIDDEN 3: Do NOT use |0d 0a 0d 0a| (double CRLF) in http.header to detect CRLF injection. \
  Double CRLF naturally terminates HTTP headers — this will cause massive false positives. \
  FORBIDDEN 4: Do NOT use content:!"|00|" to detect non-empty body — it is unreliable. \
  Use isdataat:1; in http.request_body to reliably check for a non-empty body. \
  FORBIDDEN 5: Do NOT use content:!"|0d 0a 0d 0a|" as a negation to exclude normal header terminators. \
  The negation does not work as intended. Use distance/within modifiers instead. \
- HTTP/2 REQUEST SMUGGLING DETECTION PATTERNS: \
  Rule 1 (Transfer-Encoding in HTTP/2 — RFC 7540 violation): \
  Transfer-Encoding is forbidden in HTTP/2. Detect its presence in HTTP/2 traffic: \
  CORRECT: flow:established,to_server; http.protocol; content:"HTTP/2"; http.header_names; content:"Transfer-Encoding"; nocase; \
  Use http.header_names (NOT http.header) to check for header presence. \
  Do NOT combine http.header_names and http.header in the same rule for the same header — \
  use http.header_names for presence checks and http.header for value inspection. \
  Rule 2 (Content-Length:0 with non-empty body): Detect HTTP/2 requests with Content-Length:0 \
  but a non-empty body (smuggling indicator). Use http.header_names to check for Content-Length \
  presence, then http.request_body with isdataat:1 to verify body is non-empty: \
  CORRECT: flow:established,to_server; http.protocol; content:"HTTP/2"; http.header_names; content:"Content-Length"; nocase; http.request_body; isdataat:1; \
  Do NOT use http.content_len; content:"0" — use http.header_names for header presence checks. \
  Do NOT use content:!"|00|" to detect non-empty body — use isdataat:1 instead. \
  Rule 3 (CRLF injection in headers): Detect embedded CRLF within header values by looking \
  for two CRLF sequences close together (injected CRLF followed by another within 5 bytes): \
  CORRECT: flow:established,to_server; http.header; content:"|0d 0a|"; content:"|0d 0a|"; distance:1; within:5; \
  Do NOT use content:!"|0d 0a 0d 0a|" negation — it does not work as intended. \
  Use distance:1; within:5; after the second content:"|0d 0a|" to detect injected CRLFs. \
- WEBSOCKET DETECTION PATTERNS: \
  WebSocket upgrade detection: Use http.header_names to check for "Upgrade" header presence, \
  then http.header to match the value "websocket": \
  CORRECT: flow:established,to_server; http.header_names; content:"Upgrade"; nocase; http.header; content:"Upgrade|3a 20|websocket"; nocase; \
  Do NOT use |0d 0a|Upgrade|0d 0a| in http.header_names — the buffer already contains \
  individual header names without CRLF delimiters. Just use content:"Upgrade". \
  WebSocket with IP-based Origin (C2 detection): \
  CORRECT: flow:established,to_server; http.header; content:"Upgrade|3a 20|websocket"; nocase; http.header; content:"Origin|3a 20|http"; pcre:"/Origin\\x3a\\x20https?\\x3a\\x2f\\x2f(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/i"; \
  Rapid WebSocket connections (threshold): \
  CORRECT: flow:established,to_client; http.stat_code; content:"101"; threshold:type threshold, track by_src, count 10, seconds 60; \
  Do NOT use bsize after http.stat_code — the status code is always 3 digits, no size check needed. \
- TLS CERTIFICATE AND C2 DETECTION PATTERNS: \
  Self-signed certificate detection: Suricata CANNOT compare tls.cert_subject == tls.cert_issuer. \
  ONLY approach: Use tls.cert_issuer with a negative PCRE lookahead to exclude well-known CAs. \
  This catches most self-signed certs because they won't match any known CA name. \
  CORRECT content: flow:established,to_server; tls.cert_issuer; pcre:"/^(?!.*(?:DigiCert|Let's Encrypt|Comodo|GlobalSign|Sectigo|Amazon|Google Trust|Microsoft|IdenTrust))/i"; \
  If the user asks for subject==issuer comparison, explain in the message field that \
  this requires Lua scripting and provide the negative-lookahead rule as the closest alternative. \
  Short-lived certificate detection: Since tls_cert_notbefore/tls_cert_notafter are INVALID keywords, \
  approximate by detecting certs from uncommon issuers with short CN values (typical of auto-generated C2 certs). \
  CORRECT content: flow:established,to_server; tls.cert_issuer; content:"CN="; pcre:"/^CN=[a-zA-Z0-9\\-\\.]{1,30}$/"; pcre:"/^(?!.*(?:DigiCert|Let's Encrypt|Comodo|GlobalSign))/i"; \
  If the user asks for cert date checking, explain the limitation in the message field. \
  Weak cipher suite detection: ALWAYS use tls.ciphersuites sticky buffer before content/pcre. \
  CORRECT content: flow:to_server; ssl_state:client_hello; tls.ciphersuites; content:"|00 00|"; \
  For multiple ciphers: tls.ciphersuites; pcre:"/\\x00\\x00|\\x00\\x03/"; \
  Beaconing detection: Use flow:established,to_server with dsize on data packets + threshold. \
  CORRECT content: flow:established,to_server; dsize:<1024; app-layer-protocol:tls; threshold:type threshold, track by_both, count 5, seconds 300; \
  For beaconing, use track by_both (tracks src-dst pairs). For brute force, use track by_src (per source IP). \
  TLS keyword ordering: ssl_state FIRST, then tls sticky buffers, then content matches. \
  Always include flow keyword before TLS keywords.
- THRESHOLD TYPE GUIDANCE: \
  threshold:type threshold — fires every N matches (rate counting). Use for "more than N events in T seconds". \
  threshold:type limit — fires at most once per time period. Use for rate-limiting alerts. \
  threshold:type both — fires once per time period after N matches. Use for "alert once after N events". \
  COMMON MISTAKE: Using "type both" when "type threshold" is intended. \
  For brute force / auth failure counting, use "type threshold" (fires every N matches). \
  For "alert once after N failures", use "type both" (fires once per period after threshold). \
  When the user says "more than N attempts", use type threshold. \
  When the user says "alert once after N attempts", use type both. \
  CRITICAL THRESHOLD COUNT RULE: \
  When the user says "more than N" or ">N", the threshold count MUST be N+1 (not N). \
  The threshold fires ON the Nth match, so to detect "more than 10" you need count 11. \
  Examples: \
  "more than 10 requests" → count 11 \
  ">8 accounts" → count 9 \
  ">5 suspicious tickets" → count 6 \
  ">20 API requests" → count 21 \
  "more than 3 occurrences" → count 4 \
  If the user says "at least N" or "N or more", use count N (fires on the Nth match). \
  NEVER use count N when the user says "more than N" — always use count N+1.
- SMB LATERAL MOVEMENT AND CREDENTIAL DETECTION PATTERNS: \
  SMB sticky buffers available in Suricata: \
  - smb.share: matches the share name in SMB TREE_CONNECT requests (e.g., "ADMIN$", "C$", "IPC$") \
  - smb.named_pipe: matches the named pipe in SMB requests (e.g., "svcctl", "samr", "lsarpc") \
  ALWAYS use these sticky buffers instead of raw content matching for SMB-specific fields. \
  CRITICAL PORT RULE: smb.share and smb.named_pipe are SMB-specific keywords that ONLY work on port 445. \
  When using protocol "smb" with smb.share or smb.named_pipe, the destination port MUST be 445 only. \
  Do NOT include port 135 with SMB protocol rules — RPC on port 135 is a separate protocol. \
  If you need to detect on BOTH ports 135 and 445, split into two rules: \
  one using "smb" protocol on port 445 with smb.named_pipe, \
  and one using "tcp" protocol on port 135 with raw content matching. \
  BAD: alert smb $SRC any -> $DST [135,445] (...; smb.named_pipe; ...) \
  GOOD: alert smb $SRC any -> $DST 445 (...; smb.named_pipe; ...)
  Rule 1 (SMB Null Session — anonymous NTLMSSP auth): \
  Detect NTLMSSP Negotiate (Type 1) messages. The NTLMSSP signature is 8 bytes ("NTLMSSP\x00"), \
  followed by the message type at offset 8. Type 1 = |01 00 00 00|. \
  CORRECT: flow:established,to_server; content:"NTLMSSP"; content:"|01 00 00 00|"; distance:1; within:4; \
  distance:1 because there is 1 byte (null terminator) between "NTLMSSP" and the type field. \
  Do NOT use distance:0 — the null terminator byte separates the signature from the type. \
  Rule 2 (SMB Auth Failures — STATUS_LOGON_FAILURE): \
  Detect SMB responses with STATUS_LOGON_FAILURE (0xC000006D). In little-endian wire format: |6d 00 00 c0|. \
  Auth failure responses come FROM the server, so use flow:established,to_client and reverse direction: \
  CORRECT: $HOME_NET 445 -> $HOME_NET any with flow:established,to_client; content:"|6d 00 00 c0|"; \
  threshold:type threshold, track by_both, count 5, seconds 60; \
  Use "type threshold" for rate counting (fires every N matches), NOT "type both". \
  Rule 3 (Admin Share Access — smb.share with PCRE OR): \
  Use smb.share sticky buffer with PCRE alternation for OR matching multiple shares: \
  CORRECT: flow:established,to_server; smb.share; pcre:"/^(?:ADMIN\\$|C\\$|IPC\\$)$/i"; \
  Do NOT use multiple content matches for different shares — content matches use AND logic, \
  meaning ALL must be present. Use PCRE alternation for OR logic. \
  For non-server hosts, use source negation: !$SERVERS any -> $HOME_NET 445 \
  Rule 4 (PsExec Service Creation — smb.named_pipe): \
  Detect DCE/RPC calls to the Service Control Manager via svcctl named pipe: \
  CORRECT: flow:established,to_server; smb.named_pipe; content:"svcctl"; nocase; content:"PSEXESVC"; nocase; \
  Use smb.named_pipe sticky buffer (NOT raw content with Unicode encoding). \
  The second content match detects the service name in the payload. \
  For multiple service names, use PCRE: pcre:"/(?:PSEXESVC|BTOBTO|PAExec)/i"; \
  Rule 5 (Rapid NTLM Auth — relay indicator): \
  True NTLM relay detection requires comparing challenge-response pairs across connections, \
  which is beyond standard Suricata capabilities. The closest approximation: \
  Detect rapid NTLM Type 3 (Authentication) messages. Type 3 = |03 00 00 00|. \
  CORRECT: flow:established,to_server; content:"NTLMSSP"; content:"|03 00 00 00|"; distance:1; within:4; \
  threshold:type threshold, track by_both, count 3, seconds 10; \
  Explain the relay detection limitation in the msg field. \
  Do NOT use flowbits:set without a corresponding flowbits:isset in another rule — \
  incomplete flowbits patterns are useless.
- FLOWBITS USAGE IN MULTI-RULE SETS: \
  When generating multiple rules that use flowbits for correlation: \
  1) Rules that SET a flowbit must include flowbits:set,<name> AND have their own detection logic. \
  2) Rules that CHECK a flowbit must include flowbits:isset,<name>. \
  3) Every flowbits:isset MUST have a corresponding flowbits:set in ANOTHER rule in the same set. \
  4) Every flowbits:set MUST have a corresponding flowbits:isset in ANOTHER rule in the same set. \
  5) Do NOT generate correlation-only rules that ONLY check flowbits with no detection content. \
  If you cannot guarantee matching set/isset pairs, do NOT use flowbits at all. \
  Prefer standalone rules with threshold/pcre over flowbits correlation unless the user explicitly requests it.
- QUIC/HTTP3 PROTOCOL DETECTION PATTERNS: \
  QUIC uses UDP. Use protocol "udp" for QUIC rules. \
  QUIC Long Header: First byte has bit 0x80 set. Initial packet type = 0xC0 (bits: 1100 0000). \
  QUIC Short Header: First byte has bit 0x80 NOT set (range 0x00-0x7F). \
  QUIC version 1: |00 00 00 01| at offset ~5 after the first byte. \
  Rule 1 (QUIC on non-standard port): \
  CORRECT: flow:to_server; content:"|c0|"; depth:1; content:"|00 00 00 01|"; distance:4; within:4; \
  Use port negation in header: $HOME_NET any -> $EXTERNAL_NET ![443,80,8443] \
  Rule 2 (QUIC CRYPTO frame with SNI): \
  CRYPTO frame type = |06|. TLS SNI extension type = |00 00|. \
  CORRECT: flow:to_server; content:"|06|"; content:"|00 00|"; distance:0; within:50; pcre:"/...pattern.../"; \
  Do NOT duplicate content:"|00 00|"; distance:0; — one match with within constraint is sufficient. \
  Rule 3 (QUIC connection migration): \
  NEW_CONNECTION_ID frame type = |18|. \
  CORRECT: flow:to_server; content:"|18|"; threshold:type threshold, track by_both, count 10, seconds 120; \
  Rule 4 (QUIC Short Header beaconing): \
  To detect Short Header packets (bit 0x80 NOT set), use PCRE for bit-level checking: \
  CORRECT: flow:to_server; dsize:<200; pcre:"/^[\\x00-\\x7f]/"; threshold:type threshold, track by_both, count 8, seconds 240; \
  Do NOT use content:!"|80|"; depth:1; — this checks if byte 0x80 is absent, NOT if bit 0x80 is unset. \
  A byte like 0x85 has bit 0x80 set but is not equal to 0x80, so content:!"|80|" would wrongly match it. \
  Use pcre:"/^[\\x00-\\x7f]/" to correctly match any first byte in the 0x00-0x7F range.
- IoT PROTOCOL DETECTION PATTERNS (MQTT and CoAP): \
  MQTT uses TCP on ports 1883 (plain) and 8883 (TLS). CoAP uses UDP on ports 5683/5684. \
  MQTT CONNECT packet: type byte 0x10, followed by remaining length (variable 1-4 bytes), \
  then protocol identifier |00 04 4d 51 54 54| ("MQTT" with 2-byte length prefix). \
  MQTT PUBLISH packet: type byte range 0x30-0x3F (includes QoS/DUP/RETAIN flags in lower nibble). \
  Use pcre:"/^[\\x30-\\x3f]/" to match any PUBLISH variant. \
  MQTT topic length is 2 bytes (MSB + LSB), NOT 1 byte. After remaining length, \
  the topic length field is \\x00. (2 bytes), then the topic string follows. \
  Do NOT assume topic length fits in 1 byte — use \\x00. to match the 2-byte length field. \
  MQTT SUBSCRIBE packet: type byte 0x82. MQTT PINGREQ: |c0 00| (type + remaining length 0). \
  Rule 1 (MQTT suspicious CONNECT): \
  CORRECT: flow:established,to_server; content:"|10|"; depth:1; content:"|00 04 4d 51 54 54|"; distance:1; within:6; \
  pcre:"/\\x00\\x04MQTT[\\x04\\x05].{4}\\x00.[a-fA-F0-9]{16,}/s"; \
  The PCRE handles MQTT 3.1.1 (0x04) and 5.0 (0x05), skips flags+keepalive (.{4}), \
  then matches 2-byte client ID length (\\x00.) and hex client ID pattern. \
  Rule 2 (MQTT PUBLISH with encoded topics): \
  CORRECT: flow:established,to_server; pcre:"/^[\\x30-\\x3f]/"; \
  pcre:"/.{1,4}\\x00.(?:(?:cmd|exec|shell|data)\\/[A-Za-z0-9+\\/=]{10,}|[A-Za-z0-9+\\/=]{50,})/s"; \
  .{1,4} skips variable remaining length. \\x00. matches 2-byte topic length (MSB always 0 for short topics). \
  Rule 3 (MQTT wildcard subscription): \
  CORRECT: flow:established,to_server; content:"|82|"; depth:1; \
  pcre:"/(?:cmd|exec|shell|control|admin).*?[#\\+]|[#\\+].*?(?:cmd|exec|shell|control|admin)/i"; \
  Bidirectional matching catches keywords before OR after wildcards. \
  CoAP header structure: 1st byte = Version(2 bits) + Type(2 bits) + Token Length(4 bits). \
  2nd byte = Method Code. POST = 0x02. \
  The token length varies (0-8 bytes), so do NOT hardcode the first byte. \
  Match POST method code at offset 1: content:"|02|"; offset:1; depth:1; \
  Rule 4 (CoAP POST to suspicious path): \
  CORRECT: flow:to_server; content:"|02|"; offset:1; depth:1; \
  pcre:"/(?:\\.(?:sh|exe|bat|ps1)|[A-Za-z0-9+\\/=]{100,}|[a-fA-F0-9]{40,})/s"; \
  Do NOT use content:"|40 02|" — this assumes token length 0 (first byte = 0x40). \
  Rule 5 (MQTT excessive PINGREQ): \
  CORRECT: flow:established,to_server; content:"|c0 00|"; depth:2; \
  threshold:type threshold, track by_src, count 20, seconds 300; \
  Note: Full PUBLISH correlation requires flowbits but has counter limitations.
- AWS NETWORK FIREWALL RULE GROUP PATTERNS: \
  Rule actions: pass, drop, reject, alert. Evaluation order in strict mode: PASS → DROP → REJECT → ALERT. \
  PASS rules stop further evaluation for matched traffic. DROP silently blocks. \
  REJECT sends TCP RST and blocks. ALERT logs but allows traffic. \
  AWS NFW LOGGING: DROP rules DO generate CloudWatch logs. PASS rules do NOT. \
  REJECT and ALERT rules DO generate logs. flowbits:noalert suppresses the alert but still logs. \
  CRITICAL: flow keyword (flow:to_server, flow:established) ONLY works with TCP and UDP protocols. \
  Do NOT use flow: on rules with protocol "ip". IP protocol rules must omit the flow keyword entirely. \
  BAD: drop ip $SRC any -> $DST any (...; flow:to_server; ...) \
  GOOD: drop ip $SRC any -> $DST any (...; sid:N; rev:1;) \
  CRITICAL: ip_proto keyword does NOT support negation (ip_proto:!6 is INVALID). \
  To block uncommon protocols, create separate rules for each protocol number to block: \
  ip_proto:47 (GRE), ip_proto:50 (ESP), ip_proto:51 (AH), ip_proto:4 (IP-in-IP). \
  Do NOT use metadata:aws or metadata:forward_to_sfe — these are NOT valid Suricata keywords. \
  FLOWBITS CORRELATION: When using flowbits:set in one rule, ALWAYS include a corresponding \
  rule with flowbits:isset. When using flowbits:noalert, still include flowbits:set,<name> \
  in the same rule so the flowbit is actually set. \
  BAD: flowbits:noalert; (sets noalert but never sets the flowbit) \
  GOOD: flowbits:set,prod.outbound; flowbits:noalert; (sets flowbit AND suppresses alert) \
  When the user requests N rules with flowbit correlation, you MUST generate ALL N rules. \
  Do NOT omit the flowbits:isset rule — it is the whole point of the correlation. \
  IP PROTOCOL NEGATION: ip_proto does NOT support negation (ip_proto:!TCP is INVALID). \
  To block uncommon protocols, use POSITIVE matches with numeric protocol numbers: \
  ip_proto:47 (GRE), ip_proto:50 (ESP), ip_proto:51 (AH), ip_proto:4 (IP-in-IP). \
  Generate separate rules for each protocol to block. Do NOT use ip_proto:!6 or ip_proto:!TCP.
- BIDIRECTIONAL RULES (<> operator): \
  When using the <> bidirectional operator in the rule header, do NOT include \
  to_server or to_client in the flow keyword. They conflict with bidirectional matching. \
  For <> rules: use "flow:established" (no direction) or omit flow entirely. \
  BAD: $SRC any <> $DST 88 (...; flow:established,to_server; ...) — WILL FAIL \
  GOOD: $SRC any <> $DST 88 (...; flow:established; ...) \
  GOOD: $SRC any <> $DST 88 (...; sid:N; rev:1;) \
  This is especially common in DC replication and Kerberos whitelist rules.
- KERBEROS AND ACTIVE DIRECTORY DETECTION PATTERNS: \
  Kerberos ASN.1 markers for content matching: \
  Kerberos v5 identifier: content:"|a0 03 02 01 05|"; (pvno = 5) \
  AS-REQ (msg-type 10): content:"|a1 03 02 01 0a|"; \
  TGS-REQ (msg-type 12): content:"|a1 03 02 01 0c|"; \
  RC4-HMAC etype 23: content:"|a0 03 02 01 17|"; (used in Kerberoasting/Overpass-the-Hash) \
  AS-REP ROASTING DETECTION: \
  AS-REP Roasting targets accounts without Kerberos pre-authentication. \
  In AS-REQ, the pre-authentication data is in tag |a7| (pa-data). \
  To detect AS-REQ WITHOUT pre-authentication, use content negation: content:!"|a7|"; \
  This detects requests missing the pa-data field, which is the hallmark of AS-REP Roasting. \
  CORRECT: content:"|a0 03 02 01 05|"; content:"|a1 03 02 01 0a|"; content:!"|a7|"; \
  Do NOT omit the content:!"|a7|" check — it is CRITICAL for AS-REP Roasting detection. \
  GOLDEN TICKET DETECTION: \
  Golden Ticket detection approximates abnormal ticket lifetime fields in AS-REQ. \
  The ticket lifetime is in the KDC-REQ-BODY (tag a5) with GeneralizedTime fields (tag 18). \
  CORRECT PCRE: pcre:"/\\xa5.{0,20}\\x30.{0,10}\\x18[\\x00-\\x7f]{10,17}\\x18[\\x00-\\x7f]{10,17}/s"; \
  This matches two consecutive GeneralizedTime values in the ticket body with suspicious lengths. \
  DCSync detection: Match DRSUAPI interface UUID content:"|e8 06 d0 46 9b b8 01 18 9d 68 00 80 5f 9b 4f b4|"; \
  with DCE/RPC header content:"|05 00|"; depth:2; \
  For SMB admin share detection: Use smb.share sticky buffer with PCRE: pcre:"/^(?:ADMIN\\$|C\\$|IPC\\$)$/i"; \
  For Kerberos port rules: TCP/UDP 88. For LDAP: 389. LDAPS: 636. Global Catalog: 3268. \
  For DC replication pass rules, use <> with flow:established (no direction). \
  For external Kerberos blocking, use reject with flow:to_server (not established) to catch initial packets.
- AWS NETWORK FIREWALL UNSUPPORTED KEYWORDS: \
  The following keywords are NOT supported by AWS Network Firewall and must NOT be used: \
  filesize, filemagic, filename, fileext, filemd5, filesha1, filesha256, filestore, \
  dataset, datarep, iprep. \
  For file size detection, use http.content_len with byte_test to check the Content-Length header, \
  or use stream_size for total stream volume. \
  For file type detection, use file_data (underscore, NOT file.data with dot) with content matching for file signatures \
  (e.g., JPEG: |FF D8 FF|, PNG: |89 50 4E 47 0D 0A 1A 0A|). \
  file_data and file.name ARE supported — only the extraction keywords above are not.
- IMAGE/STEGANOGRAPHY DETECTION PATTERNS: \
  For detecting suspicious image uploads: \
  JPEG signature: content:"|FF D8 FF|"; (Start of Image marker) \
  PNG signature: content:"|89 50 4E 47 0D 0A 1A 0A|"; (PNG magic bytes) \
  JPEG COM marker: content:"|FF FE|"; (Comment marker, used to hide data) \
  Use file_data sticky buffer (underscore, NOT file.data) for inspecting file content within HTTP uploads. \
  CRITICAL: Each sticky buffer MUST have at least one content or pcre match immediately after it. \
  Do NOT list multiple sticky buffers consecutively without content between them. \
  CORRECT: http.content_type; content:"image/jpeg"; file_data; content:"|FF D8 FF|"; \
  WRONG: http.content_type; file_data; content:"image/jpeg"; content:"|FF D8 FF|"; \
  For upload size detection: http.content_len; byte_test:0,>,5242880,0,string,dec; \
  (checks if Content-Length > 5MB). Use byte_test:0 (not 4) because http.content_len is an ASCII string \
  of variable length — byte_test:0 reads the entire buffer as a decimal string. \
  CRITICAL ORDERING: byte_test MUST come AFTER http.content_len, never before it. \
  byte_test operates on the sticky buffer that precedes it, so http.content_len must be set first. \
  BAD: byte_test:0,>,5242880,0,string,dec; http.content_len; (byte_test has no buffer to read) \
  GOOD: http.content_len; byte_test:0,>,5242880,0,string,dec; (byte_test reads content_len buffer) \
  For image MIME type: http.content_type; content:"image/"; \
  For JSON or XML body detection: http.content_type; pcre:"/^application\\/(json|xml)/i"; \
  (matches both application/json and application/xml with a single PCRE). \
  For repeated uploads: threshold:type threshold, track by_both, count 10, seconds 600; \
  When the user says "more than N", use count N+1 (e.g., "more than 3" → count 4). \
  For base64 size estimation: 1MB decoded ≈ 1.33MB base64 chars. \
  10MB decoded ≈ 13,300,000 base64 chars → use {13300,} in PCRE. \
  Do NOT use filesize — it is unsupported on AWS Network Firewall.
- STICKY BUFFER CONTENT ORDERING (CRITICAL): \
  Each sticky buffer MUST be immediately followed by its content/pcre match. \
  Do NOT group multiple sticky buffers together with all content matches after them. \
  BAD: http.method; http.uri; http.user_agent; content:"POST"; content:"/submit.php"; pcre:"/Mozilla/"; \
  GOOD: http.method; content:"POST"; http.uri; content:"/submit.php"; http.user_agent; pcre:"/Mozilla/"; \
  Each content/pcre match applies to the LAST sticky buffer before it. \
  If you list sticky buffers consecutively, only the LAST one gets the content matches. \
  ALWAYS interleave: sticky_buffer; content_match; next_sticky; next_content; etc.
- RULE PROCESSING AND PRIORITIZATION (from Suricata 9.0 docs): \
  Suricata categorizes rules into types that affect when and how they are evaluated: \
  1) IP Only (ip_only): Evaluated once per flow direction on first packet. Action applies to flow. \
     Rules with only IP src/dst and no keywords become IP-only. Most efficient. \
  2) Packet (pkt): Evaluated per-packet. Matches header fields (ttl, itype, tcp.hdr, flags). \
  3) Protocol Detection Only (pd_only): Evaluated once when app-layer protocol is detected. \
  4) Stream (stream): Evaluated on reassembled stream data. Action applies to flow. \
  5) App Layer Transaction (app_tx): Evaluated per transaction. Uses sticky buffers (http.host, dns.query, etc.). \
  Rule priority order: Action > flowbits usage > flowint > priority keyword. \
  A rule with flowbits:set has higher priority than one without, regardless of priority keyword value. \
  For AWS Network Firewall strict order mode: rules are processed in file order (top to bottom). \
  Earlier rules take precedence — a pass rule before a drop rule means traffic is passed. \
  When generating rules for AWS NFW, consider rule ordering: put specific pass rules BEFORE broad drop rules.
- HTTPS / TLS INSPECTION RULES: \
  HTTPS traffic on port 443 uses TLS, NOT plain HTTP. You CANNOT inspect HTTP URI/headers on port 443 \
  using "http" protocol — the payload is encrypted. For HTTPS/TLS traffic: \
  Use protocol "tls" with tls.sni to match on the Server Name Indication (unencrypted). \
  Use protocol "tls" with tls.cert_subject or tls.cert_issuer for certificate inspection. \
  Do NOT use "http" protocol with port 443 — use "tls" or "tcp" instead. \
  EXCEPTION: If the traffic is decrypted (e.g., by a TLS proxy), then "http" protocol on 443 is valid. \
  For combined HTTP+HTTPS rules, generate SEPARATE rules: one for port 80 (http) and one for port 443 (tls).
- NETWORK VARIABLE USAGE: \
  When the user defines custom network variables (e.g., PROD_CIDR, WEB_TIER, DB_SUBNET), \
  use them as $VARIABLE_NAME in the rule header. Do NOT hardcode the CIDR values. \
  Example: If user says "WEB_TIER: 10.0.1.0/24", use $WEB_TIER in rules, not 10.0.1.0/24. \
  Standard variables: $HOME_NET, $EXTERNAL_NET, $HTTP_SERVERS, $DNS_SERVERS, $SMTP_SERVERS.
- FAST_PATTERN BEST PRACTICE: \
  Include fast_pattern on the most unique/specific content match in every rule that has content keywords. \
  fast_pattern tells Suricata which pattern to use for the initial multi-pattern matching phase. \
  Without it, Suricata picks automatically, which may not be optimal. \
  Place fast_pattern after the most distinctive content match (longest, most unique string).
- AWS NETWORK FIREWALL DROP ACTION LOGGING: \
  In AWS Network Firewall, DROP action rules do NOT generate alert logs by default. \
  If the user needs logging for dropped traffic, recommend using ALERT action instead of DROP, \
  or suggest adding a companion ALERT rule alongside the DROP rule. \
  Mention this in the explanation when generating DROP rules.
- NEGATIVE APP-LAYER-PROTOCOL MATCHING: \
  Avoid using app-layer-protocol:!<proto> for blocking. Negative matching can be unreliable \
  and may block legitimate traffic during protocol detection. \
  Better approach: explicitly list protocols to reject with separate rules per protocol.
- PASS RULES — ALWAYS INCLUDE WHEN REQUESTED: \
  When the user asks for a "complete ruleset" or mentions PASS rules, you MUST generate PASS rules. \
  PASS rules define legitimate traffic that should bypass further inspection. Common PASS rules: \
  - Allow monitoring tools (Prometheus port 9090, Grafana port 3000, CloudWatch agent) \
  - Allow health check endpoints (e.g., /health, /status, /_stcore/health) \
  - Allow trusted IPs or CIDR ranges for admin access \
  - Allow CDN/payment gateway IPs for e-commerce \
  - Allow internal DNS and NTP traffic \
  Example: pass tcp $HOME_NET any -> any 9090 (msg:"PASS - Allow Prometheus monitoring"; flow:established,to_server; sid:X; rev:1;)
- GEOIP BLOCKING — USE THE geoip KEYWORD: \
  Suricata supports GeoIP blocking via the geoip keyword. It requires MaxMind GeoLite2 database \
  configured in suricata.yaml, but the rule syntax is valid. Use ISO 3166-1 alpha-2 country codes. \
  Syntax: geoip:src,RU; or geoip:dst,CN; or geoip:both,KP; \
  For blocking traffic from high-risk countries: \
  drop ip any any -> any any (msg:"Block traffic from Russia"; geoip:src,RU; sid:X; rev:1;) \
  For blocking traffic TO specific countries: \
  drop ip $HOME_NET any -> any any (msg:"Block egress to China"; geoip:dst,CN; sid:X; rev:1;) \
  Multiple countries require separate rules (one per country) or use geoip:src,RU; in one rule. \
  ALWAYS generate concrete geoip rules when asked about geographic blocking — do NOT refuse.
- VAGUE OR COMPLEX PROMPTS — MAKE REASONABLE ASSUMPTIONS: \
  When a prompt is vague (e.g., "detect anomalous behavior", "zero-day detection"), do NOT refuse. \
  Instead, generate rules for the closest concrete detection patterns: \
  - "anomalous behavior" → unusual ports, unexpected protocols, rate anomalies \
  - "zero-day exploits" → shellcode patterns (NOP sleds), buffer overflow indicators (long strings), \
    unusual HTTP methods (PROPFIND, TRACE), protocol misuse \
  - "complete ruleset" → generate at least one rule per action type (DROP, ALERT, PASS, REJECT) \
  - "monitor traffic" → generate ALERT rules with thresholds for rate detection \
  ALWAYS produce at least one concrete rule, even for vague requests. Explain limitations in the message field.
- MULTI-RULE COMPLETE RULESETS: \
  When asked for a "complete ruleset" or "comprehensive rules", generate rules covering: \
  1) At least one DROP rule (block known bad traffic) \
  2) At least one ALERT rule (detect suspicious patterns) \
  3) At least one PASS rule (allow legitimate traffic) \
  4) At least one REJECT rule (actively refuse unauthorized access) \
  Return them as a JSON array of rule objects.
- NOSQL INJECTION DETECTION PATTERNS: \
  When generating NoSQL injection rules, cover ALL dangerous MongoDB operators, not just $where: \
  Critical operators: $where, $regex, $ne, $gt, $lt, $nin, $or, $and, $expr, $lookup \
  Also detect JavaScript code execution in $where: function(), eval(), this., process., require() \
  Best practices for NoSQL injection rules: \
  1) Add http.method; content:"POST"; to filter — NoSQL injection mainly occurs in POST requests \
  2) Cover URL-encoded variants: %24where, %24regex, %24ne, etc. \
  3) Use PCRE alternation for multiple operators: pcre:"/(?:\\$(?:where|regex|ne|gt|lt|nin|or|expr))/i" \
  4) Add JavaScript detection: pcre:"/\\$where[^}]*(?:function\\s*\\(|eval\\s*\\(|this\\.|process\\.)/i" \
  5) Check both http.request_body and http.uri for injection in POST body and query strings \
  6) Use fast_pattern on the most specific content match
- INJECTION DETECTION GENERAL BEST PRACTICES: \
  For any injection detection (SQL, NoSQL, XSS, XXE, SSRF): \
  1) Always filter by HTTP method when applicable (POST for body injection, GET for URI injection) \
  2) Cover URL-encoded variants of attack patterns \
  3) Use PCRE alternation for multiple attack patterns in one rule \
  4) Include fast_pattern on the most distinctive content match \
  5) Generate multiple rules for comprehensive coverage — one rule per attack vector \
  6) Consider both request body and URI query string as injection surfaces
"""


class NLParser:
    """Extracts DetectionIntent from natural language via Amazon Bedrock."""

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        bedrock_client=None,
        model_id: str = "us.anthropic.claude-sonnet-4-20250514-v1:0",
        region: str = "us-east-1",
    ):
        self.kb = knowledge_base
        self.model_id = model_id
        if bedrock_client is not None:
            self.client = bedrock_client
        elif boto3 is not None:
            self.client = boto3.client("bedrock-runtime", region_name=region)
        else:
            raise ImportError(
                "boto3 is required for the AI Rule Assistant.\n\n"
                "Install it with:\n"
                "    pip install boto3"
            )

    def classify_input(self, user_input: str, chat_history: list[dict] | None = None) -> tuple[str, Optional[str]]:
        """Classify user input as 'rule_request', 'question', or 'conversation'.

        Returns (classification, chat_response).
        - For 'rule_request': chat_response is None (proceed to generate).
        - For 'question' or 'conversation': chat_response is a helpful reply.
        """
        # Fast path: if input contains obvious rule-generation keywords, skip LLM classification
        lower = user_input.lower()
        _RULE_SIGNALS = [
            "create rule", "generate rule", "create suricata", "generate suricata",
            "drop rule", "alert rule", "reject rule", "pass rule",
            "block traffic", "block all traffic", "detect and block",
            "i need rules", "i need a rule", "write a rule", "write rules",
            "generate drop", "generate alert", "generate reject", "generate pass",
            "create drop", "create alert", "create reject", "create pass",
            "block sql", "block ssh", "block dns", "block smtp", "block quic",
            "detect dns tunneling", "detect brute force", "detect lateral",
            "detect ransomware", "detect crypto", "detect exfiltration",
            "geoip", "geo-block", "geoblocking", "high-risk countries",
            "mqtt", "quic protocol", "http/2", "http2",
            "rate limit", "rate-limit", "threshold",
            "ruleset", "rule set",
            "inspect tls", "inspect quic", "inspect http",
            "monitor mqtt", "monitor traffic",
            "anomaly detection", "zero-day", "zero day",
        ]
        if any(sig in lower for sig in _RULE_SIGNALS):
            return "rule_request", None

        system = (
            "You are a Suricata IDS/IPS rule generation assistant. "
            "Classify the user's message into one of these categories:\n"
            "1. rule_request — the user wants to generate, create, or build Suricata rules. "
            "This includes ANY request mentioning: blocking, dropping, alerting, rejecting, detecting, "
            "monitoring, inspecting traffic, GeoIP, protocols, ports, thresholds, or specific attack types. "
            "When in doubt, classify as rule_request.\n"
            "2. template — the user pasted a template or form with placeholder brackets like [value1/value2] "
            "or [e.g., ...]. They need to fill in specifics first.\n"
            "3. question — the user is asking a question about Suricata, rules, or this tool's capabilities "
            "(NOT requesting rule generation)\n"
            "4. conversation — greetings, thanks, or off-topic chat\n\n"
            "IMPORTANT: If the message mentions ANY specific threat, protocol, or traffic pattern, "
            "classify as rule_request even if the request is vague or complex.\n\n"
            "Respond with a JSON object: {\"type\": \"rule_request|template|question|conversation\", \"response\": \"...\"}\n"
            "For rule_request, set response to null.\n"
            "For template, set response to a message asking the user to provide specific values instead of a template.\n"
            "For question or conversation, set response to a helpful, concise answer.\n"
            "Respond ONLY with valid JSON — no markdown."
        )
        messages = self._build_converse_messages(chat_history, user_input)
        try:
            response = self.client.converse(
                modelId=self.model_id,
                messages=messages,
                system=[{"text": system}],
                inferenceConfig={"maxTokens": 512, "temperature": 0.0},
            )
            raw = response["output"]["message"]["content"][0]["text"].strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[-1]
            if raw.endswith("```"):
                raw = raw.rsplit("```", 1)[0]
            data = json.loads(raw.strip())
            msg_type = data.get("type", "rule_request")
            chat_response = data.get("response")
            return msg_type, chat_response
        except Exception as e:
            logger.warning("Classification failed, defaulting to rule_request: %s", e)
            return "rule_request", None

    def extract_intent(
        self,
        user_input: str,
        error_feedback: Optional[list[str]] = None,
        chat_history: list[dict] | None = None,
    ) -> tuple[Optional[list[DetectionIntent]], Optional[str]]:
        """Parse natural language into DetectionIntent(s).

        Returns (intents_list, None) on success or (None, error_message) on failure.
        error_feedback: list of error strings from previous failed attempts
        for self-correction.
        chat_history: list of {"role": "user"|"assistant", "content": str} dicts.
        """
        prompt = self._build_prompt(user_input, error_feedback)
        system = self._build_system_prompt()
        messages = self._build_converse_messages(chat_history, prompt)

        try:
            response = self.client.converse(
                modelId=self.model_id,
                messages=messages,
                system=[{"text": system}],
                inferenceConfig={"maxTokens": 8192, "temperature": 0.0},
            )
            raw = response["output"]["message"]["content"][0]["text"]
        except Exception as e:
            logger.error("Bedrock invocation failed: %s", e)
            return None, f"Bedrock error: {e}"

        return self._parse_response(raw)

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_converse_messages(
        chat_history: list[dict] | None, current_message: str
    ) -> list[dict]:
        """Build Bedrock Converse messages array from chat history + current message.

        Keeps the last 10 turns and ensures strictly alternating user/assistant roles
        (required by Bedrock Converse API). Merges consecutive same-role messages.
        """
        messages = []
        if chat_history:
            recent = chat_history[-20:]
            for msg in recent:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if not content:
                    continue
                # Merge consecutive same-role messages
                if messages and messages[-1]["role"] == role:
                    prev_text = messages[-1]["content"][0]["text"]
                    messages[-1]["content"][0]["text"] = prev_text + "\n" + content
                else:
                    messages.append({"role": role, "content": [{"text": content}]})

        new_msg = {"role": "user", "content": [{"text": current_message}]}
        # If last message is also user, merge to avoid consecutive user messages
        if messages and messages[-1]["role"] == "user":
            prev_text = messages[-1]["content"][0]["text"]
            messages[-1]["content"][0]["text"] = prev_text + "\n" + current_message
        else:
            messages.append(new_msg)

        # Ensure first message is from user (Bedrock requirement)
        if messages and messages[0]["role"] != "user":
            messages = messages[1:]

        return messages

    def _build_system_prompt(self) -> str:
        protocols = ", ".join(SuricataConstants.SUPPORTED_PROTOCOLS)
        keywords = self._select_relevant_keywords()
        templates = self._select_relevant_templates()
        examples = self._select_relevant_examples()
        definitions = self._select_rule_definitions()
        rules_intro = self.kb.get_doc("suricata_rules_intro.md")
        rules_reference = self.kb.get_doc("suricata_rules_reference.md")
        aws_best_practices = self.kb.get_doc("aws_network_firewall_best_practices.md")

        parts = [_SYSTEM_PROMPT.replace("SUPPORTED_PROTOCOLS", protocols)]
        if rules_reference:
            parts.append(f"\nSURICATA RULES COMPLETE REFERENCE (official docs):\n{rules_reference}")
        elif rules_intro:
            parts.append(f"\nOFFICIAL SURICATA RULES DOCUMENTATION:\n{rules_intro}")
        if aws_best_practices:
            parts.append(f"\nAWS NETWORK FIREWALL BEST PRACTICES (official AWS guidance):\n{aws_best_practices}")
        if definitions:
            parts.append(f"\nSURICATA RULE STRUCTURE REFERENCE (structured):\n{definitions}")
        parts.append(f"\nAVAILABLE KEYWORDS (use ONLY these — do NOT invent keywords):\n{keywords}")
        parts.append(f"\nRULE TEMPLATES (examples of well-formed rules):\n{templates}")
        if examples:
            parts.append(f"\nAWS & SURICATA OFFICIAL RULE EXAMPLES (use as reference for correct syntax):\n{examples}")
        parts.append(
            "\nREMINDER: The 'content' field must NOT contain msg, sid, or rev. "
            "Only use keywords listed above. If a keyword is not listed, it will "
            "cause a validation error."
        )
        return "\n".join(parts)

    def _build_prompt(
        self, user_input: str, error_feedback: Optional[list[str]] = None
    ) -> str:
        parts = [f"Generate a Suricata rule for:\n{user_input}"]
        if error_feedback:
            parts.append(
                "\nYour previous attempt had these errors. You MUST fix ALL of them in this attempt:\n"
                + "\n".join(f"- {e}" for e in error_feedback)
            )
            # Add concrete guidance for common self-correction failures
            feedback_text = " ".join(error_feedback).lower()
            if "missing_flow" in feedback_text or "flow" in feedback_text:
                parts.append(
                    '\nCRITICAL: You MUST include a flow keyword in the "content" field. '
                    'Example content value: "flow:established,to_server; dns.query; content:\\"example\\"; nocase"'
                )
        return "\n".join(parts)

    def _select_relevant_keywords(self) -> str:
        """Return a compact keyword reference for the prompt."""
        keywords = self.kb.get_keywords()
        lines = []
        for kw in keywords:
            name = kw.get("name", "")
            desc = kw.get("description", "")
            if name:
                lines.append(f"- {name}: {desc}" if desc else f"- {name}")
        return "\n".join(lines)

    def _select_relevant_templates(self) -> str:
        """Return a compact template reference for the prompt."""
        templates = self.kb.get_templates()
        lines = []
        for t in templates:
            name = t.get("name", t.get("template_name", ""))
            rule = t.get("rule", t.get("template", ""))
            if name and rule:
                lines.append(f"- {name}: {rule}")
        return "\n".join(lines)
    def _select_relevant_examples(self) -> str:
        """Return curated rule examples from AWS/Suricata docs for the prompt."""
        examples = self.kb.get_examples()
        lines = []
        for ex in examples:
            name = ex.get("name", "")
            rule = ex.get("rule", "")
            desc = ex.get("description", "")
            if name and rule:
                lines.append(f"- {name}: {rule}")
                if desc:
                    lines.append(f"  ({desc})")
        return "\n".join(lines)
    def _select_rule_definitions(self) -> str:
        """Return compact rule structure definitions for the prompt."""
        defs = self.kb.get_definitions()
        if not defs:
            return ""
        lines = []

        # Rule structure
        structure = defs.get("rule_structure", {})
        if structure:
            lines.append(f"Rule format: {structure.get('format', '')}")
            lines.append(f"Example: {structure.get('example', '')}")

        # Actions
        actions = defs.get("actions", {})
        if actions:
            lines.append("\nActions:")
            for a in actions.get("values", []):
                lines.append(f"  - {a['name']}: {a['description']}")

        # Direction
        direction = defs.get("direction", {})
        if direction:
            lines.append("\nDirection:")
            for d in direction.get("values", []):
                lines.append(f"  - {d['symbol']}: {d['description']}")

        # Addressing operators
        addressing = defs.get("addressing", {})
        if addressing:
            lines.append("\nIP addressing: supports CIDR (/24), negation (!), grouping ([..,..])")
            lines.append("  Variables: $HOME_NET (internal), $EXTERNAL_NET (external)")

        # Port operators
        ports = defs.get("ports", {})
        if ports:
            lines.append("\nPorts: ranges (:), negation (!), grouping ([..,..]), e.g. [80:100,!99]")

        # Best practices
        practices = defs.get("best_practices", [])
        if practices:
            lines.append("\nBest practices:")
            for p in practices:
                lines.append(f"  - {p}")

        # Modifier types
        opts = defs.get("rule_options", {})
        if opts:
            lines.append("\nRule options: enclosed in (), separated by ;. Order matters.")
            lines.append("  Sticky buffers (preferred): buffer name BEFORE content match (e.g., http.uri; content:\"/api/\";)")
            lines.append(f"  Normalized buffers: {opts.get('normalized_buffers', '')}")

        # AWS-specific keywords
        aws_kw = defs.get("aws_specific_keywords", {})
        if aws_kw:
            lines.append("\nAWS Network Firewall specific keywords:")
            for kw in aws_kw.get("keywords", []):
                lines.append(f"  - {kw['name']}: {kw['description']}")
            constraints = aws_kw.get("constraints", [])
            if constraints:
                lines.append("  Constraints:")
                for c in constraints:
                    lines.append(f"    - {c}")
            categories = aws_kw.get("supported_categories", [])
            if categories:
                lines.append(f"  Supported URL/domain categories ({len(categories)} total): {', '.join(categories[:10])}... and {len(categories)-10} more")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self, raw: str
    ) -> tuple[Optional[list[DetectionIntent]], Optional[str]]:
        """Parse LLM JSON response into DetectionIntent(s).

        Returns a list of intents (single-element for one rule, multiple for multi-rule).
        """
        text = raw.strip()
        if not text:
            return None, "LLM returned empty response"

        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        # If LLM prefixed text before JSON, try to extract the JSON portion
        if not text.startswith(("{", "[")):
            # Find first { or [
            brace = text.find("{")
            bracket = text.find("[")
            starts = [i for i in [brace, bracket] if i >= 0]
            if starts:
                text = text[min(starts):]
            else:
                return None, f"No JSON found in LLM response: {text[:100]}"

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON within the text (LLM may have appended explanation)
            for end_char, start_char in [("}", "{"), ("]", "[")]:
                last_end = text.rfind(end_char)
                if last_end >= 0:
                    candidate = text[:last_end + 1]
                    try:
                        data = json.loads(candidate)
                        break
                    except json.JSONDecodeError:
                        continue
            else:
                return None, f"Malformed JSON from LLM: {text[:200]}"

        # Normalize to list of dicts
        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = [d for d in data if isinstance(d, dict)]
            if not items:
                return None, "LLM returned an empty array"
        else:
            return None, "LLM response is not a JSON object or array"

        intents = []
        for item in items:
            sid = item.get("sid")
            rev = item.get("rev")
            if sid is not None:
                try:
                    sid = int(sid)
                except (ValueError, TypeError):
                    sid = None
            if rev is not None:
                try:
                    rev = int(rev)
                except (ValueError, TypeError):
                    rev = None

            # LLM sometimes returns content as a list instead of a string — normalize
            raw_content = item.get("content", "")
            if isinstance(raw_content, list):
                raw_content = "; ".join(str(c) for c in raw_content)

            intents.append(DetectionIntent(
                action=item.get("action", "alert"),
                protocol=item.get("protocol", "tcp"),
                src_net=item.get("src_net", "$HOME_NET"),
                src_port=item.get("src_port", "any"),
                dst_net=item.get("dst_net", "$EXTERNAL_NET"),
                dst_port=item.get("dst_port", "any"),
                direction=item.get("direction", "->"),
                message=item.get("message", ""),
                content=raw_content,
                sid=sid,
                rev=rev,
            ))

        return intents, None
