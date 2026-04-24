"""
Best Practice Checker for the Suricata Rule Generator AI Agent Layer.

Checks generated rules against Suricata best practices derived from the
knowledge base documentation. Returns actionable feedback that the agent
loop feeds back to the LLM for self-correction.

Unlike the validator (which checks syntax/structure) and the analyzer
(which checks conflicts), this checker catches quality gaps — rules that
are technically valid but suboptimal for production deployment.
"""

import re
from dataclasses import dataclass, field


def _split_options(options: str) -> list[str]:
    """Split Suricata rule options by semicolons, respecting quoted strings.

    Naive split(';') breaks when msg or content values contain semicolons
    inside quotes. This function tracks quote state to split correctly.
    """
    parts = []
    current = []
    in_quotes = False
    i = 0
    while i < len(options):
        ch = options[i]
        if ch == '\\' and i + 1 < len(options):
            current.append(ch)
            current.append(options[i + 1])
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == ';' and not in_quotes:
            part = ''.join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(ch)
        i += 1
    part = ''.join(current).strip()
    if part:
        parts.append(part)
    return parts


@dataclass
class BestPracticeIssue:
    """A single best-practice violation."""
    category: str       # e.g., "missing_flow", "missing_content_match"
    severity: str       # "suggestion" | "recommendation" | "strong_recommendation"
    message: str
    fix_hint: str       # actionable hint for the LLM to self-correct


@dataclass
class BestPracticeResult:
    """Result of best-practice checking."""
    passed: bool
    issues: list[BestPracticeIssue] = field(default_factory=list)


class BestPracticeChecker:
    """Checks Suricata rules against production best practices."""

    def check(self, rule_str: str, user_input: str = "") -> BestPracticeResult:
        """Run all best-practice checks on a rule string.

        Args:
            rule_str: The generated Suricata rule string.
            user_input: Original user request (for context-aware checks).

        Returns:
            BestPracticeResult with any issues found.
        """
        issues: list[BestPracticeIssue] = []
        options = self._extract_options(rule_str)
        user_lower = user_input.lower()

        issues.extend(self._check_flow_keyword(options, rule_str, user_lower))
        issues.extend(self._check_flow_direction(options, rule_str))
        issues.extend(self._check_content_match(options, rule_str))
        issues.extend(self._check_flow_before_sticky_buffer(options))
        issues.extend(self._check_sticky_buffer_order(options))
        issues.extend(self._check_dsize_with_app_layer(options))
        issues.extend(self._check_dns_query_length(options))
        issues.extend(self._check_brute_force_flow(options, user_lower))
        issues.extend(self._check_stream_size_protocol(options, rule_str))
        issues.extend(self._check_dual_tls_sticky_buffers(options))
        issues.extend(self._check_invalid_tls_cert_keywords(options))
        issues.extend(self._check_cipher_without_sticky_buffer(options))
        issues.extend(self._check_invalid_http2_keywords(options))
        issues.extend(self._check_broad_crlf_detection(options))
        issues.extend(self._check_bsize_after_stat_code(options))
        issues.extend(self._check_crlf_in_header_names(options))
        issues.extend(self._check_empty_content(options))
        issues.extend(self._check_duplicate_sticky_buffers(options))
        issues.extend(self._check_unreliable_body_detection(options))
        issues.extend(self._check_flow_on_ip_protocol(options, rule_str))
        issues.extend(self._check_ip_proto_negation(options))
        issues.extend(self._check_bidir_flow_direction(options, rule_str))
        issues.extend(self._check_dns_multiple_content_or(options, rule_str))

        # Only fail on strong_recommendation — others are informational
        has_strong = any(i.severity == "strong_recommendation" for i in issues)
        return BestPracticeResult(passed=not has_strong, issues=issues)

    @staticmethod
    def _extract_options(rule_str: str) -> str:
        """Extract the options section from a rule string."""
        match = re.search(r'\((.+)\)\s*$', rule_str, re.DOTALL)
        return match.group(1) if match else ""

    @staticmethod
    def _check_flow_keyword(
        options: str, rule_str: str, user_lower: str
    ) -> list[BestPracticeIssue]:
        """Check that flow keyword is present for TCP/HTTP/TLS rules."""
        issues = []
        has_flow = "flow:" in options

        if has_flow:
            return issues

        # Determine protocol from rule header
        header = rule_str.split("(")[0].strip() if "(" in rule_str else rule_str
        parts = header.split()
        protocol = parts[1].lower() if len(parts) > 1 else ""

        # flow is strongly recommended for stateful protocols
        stateful_protocols = {"tcp", "http", "tls", "ftp", "smtp", "ssh", "dns"}
        if protocol in stateful_protocols:
            # If user explicitly asked for established connections, this is a strong issue
            established_terms = [
                "established", "active connection", "connection state",
                "stateful", "existing connection",
            ]
            user_wants_established = any(t in user_lower for t in established_terms)

            if user_wants_established:
                issues.append(BestPracticeIssue(
                    category="missing_flow",
                    severity="strong_recommendation",
                    message=(
                        f"Rule uses {protocol} protocol and user requested established "
                        f"connections, but 'flow' keyword is missing."
                    ),
                    fix_hint=(
                        "Add 'flow:established,to_server' for egress/outbound rules "
                        "or 'flow:established,to_client' for ingress/inbound rules "
                        "to the content field."
                    ),
                ))
            else:
                issues.append(BestPracticeIssue(
                    category="missing_flow",
                    severity="recommendation",
                    message=(
                        f"Rule uses {protocol} protocol but has no 'flow' keyword. "
                        f"Production rules should specify flow direction and state."
                    ),
                    fix_hint=(
                        "Add 'flow:established,to_server' for outbound rules or "
                        "'flow:established,to_client' for inbound rules."
                    ),
                ))

        return issues

    @staticmethod
    def _check_content_match(
        options: str, rule_str: str
    ) -> list[BestPracticeIssue]:
        """Check that app-layer rules have content matches beyond just flow/meta."""
        issues = []
        header = rule_str.split("(")[0].strip() if "(" in rule_str else rule_str
        parts = header.split()
        protocol = parts[1].lower() if len(parts) > 1 else ""

        # For app-layer protocols, having at least one content/pcre match is recommended
        app_protocols = {"http", "tls", "dns", "ftp", "smtp", "ssh"}
        if protocol in app_protocols:
            has_content = "content:" in options
            has_pcre = "pcre:" in options
            has_app_keyword = any(
                kw in options for kw in [
                    "http.", "tls.", "dns.", "file.", "urilen",
                ]
            )
            if not has_content and not has_pcre and not has_app_keyword:
                issues.append(BestPracticeIssue(
                    category="missing_content_match",
                    severity="recommendation",
                    message=(
                        f"Rule uses {protocol} protocol but has no content match "
                        f"or app-layer keyword. This may match too broadly."
                    ),
                    fix_hint=(
                        "Add specific content matches or app-layer sticky buffers "
                        "to narrow detection scope and reduce false positives."
                    ),
                ))

        return issues

    @staticmethod
    def _check_sticky_buffer_order(options: str) -> list[BestPracticeIssue]:
        """Check that sticky buffers appear before their content matches.

        Valid pattern: sticky_buffer; content:"..."; another_sticky; content:"..."
        Invalid pattern: content:"..."; sticky_buffer (content has no preceding buffer)
        """
        issues = []
        parts = _split_options(options)

        sticky_buffers = {
            "http.uri", "http.host", "http.method", "http.user_agent",
            "http.cookie", "http.header", "http.content_type",
            "http.content_len", "http.stat_code", "http.stat_msg",
            "http.request_body", "http.response_body", "http.referer",
            "http.server", "http.location", "http.protocol",
            "http.request_header", "http.response_header",
            "http.request_line", "http.response_line",
            "http.header_names", "http.start", "http.connection",
            "http.accept", "http.accept_enc", "http.accept_lang",
            "http.host.raw", "http.uri.raw", "http.header.raw",
            "tls.sni", "tls.cert_subject", "tls.cert_issuer", "tls.ciphersuites",
            "dns.query", "file.data", "file.name", "file_data",
            "smb.share", "smb.named_pipe", "dcerpc.stub_data",
        }

        # Content modifiers that belong to the preceding content match
        content_modifiers = {
            "nocase", "depth", "offset", "distance", "within",
            "fast_pattern", "startswith", "endswith", "bsize",
            "rawbytes", "isdataat",
        }

        # Track whether we've seen a sticky buffer that "owns" subsequent content
        has_active_buffer = False
        last_was_unowned_content = False

        for part in parts:
            kw_name = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw_name in sticky_buffers:
                if last_was_unowned_content:
                    # Content appeared before ANY sticky buffer — wrong order
                    issues.append(BestPracticeIssue(
                        category="sticky_buffer_order",
                        severity="strong_recommendation",
                        message=(
                            f"Sticky buffer '{kw_name}' appears after a content match "
                            f"that has no preceding sticky buffer. Sticky buffers must "
                            f"come BEFORE the content they modify."
                        ),
                        fix_hint=(
                            f"Move '{kw_name}' before its associated content match."
                        ),
                    ))
                # This sticky buffer now owns subsequent content
                has_active_buffer = True
                last_was_unowned_content = False
            elif kw_name in ("content", "pcre"):
                if not has_active_buffer:
                    # Content with no preceding sticky buffer — might be wrong
                    # (but could be raw payload matching, which is valid)
                    # Only flag if a sticky buffer appears LATER
                    last_was_unowned_content = True
                # If has_active_buffer, this content belongs to it — fine
            elif kw_name in content_modifiers:
                pass  # Modifiers don't change state
            elif kw_name in ("msg", "flow", "sid", "rev", "threshold",
                             "detection_filter", "classtype", "priority",
                             "metadata", "reference", "flags", "dsize",
                             "app-layer-protocol", "ssl_state", "ssl_version",
                             "byte_test", "byte_extract", "flowbits", "xbits",
                             "stream_size", "geoip", "ip_proto", "noalert",
                             "filesize", "filemagic"):
                pass  # Meta/detection keywords don't affect buffer ownership

        return issues
    @staticmethod
    def _check_flow_before_sticky_buffer(options: str) -> list[BestPracticeIssue]:
        """Check that flow keyword appears before any sticky buffer keyword.

        Correct ordering: flow FIRST, then sticky buffers, then content/modifiers.
        Example bad:  dns.query; flow:established;
        Example good: flow:established; dns.query;
        """
        issues = []
        parts = _split_options(options)

        sticky_buffers = {
            "http.uri", "http.host", "http.method", "http.user_agent",
            "http.cookie", "http.header", "http.content_type",
            "http.content_len", "http.stat_code", "http.stat_msg",
            "http.request_body", "http.response_body", "http.referer",
            "http.server", "http.location", "http.protocol",
            "http.request_header", "http.response_header",
            "http.request_line", "http.response_line",
            "http.header_names", "http.start", "http.connection",
            "http.accept", "http.accept_enc", "http.accept_lang",
            "http.host.raw", "http.uri.raw", "http.header.raw",
            "tls.sni", "tls.cert_subject", "tls.cert_issuer", "tls.ciphersuites",
            "dns.query", "file.data", "file.name", "file_data",
            "smb.share", "smb.named_pipe", "dcerpc.stub_data",
        }

        flow_seen = False
        for part in parts:
            kw_name = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw_name == "flow":
                flow_seen = True
            elif kw_name in sticky_buffers and not flow_seen:
                # A sticky buffer appeared before flow — wrong order
                issues.append(BestPracticeIssue(
                    category="flow_before_sticky_buffer",
                    severity="strong_recommendation",
                    message=(
                        f"Sticky buffer '{kw_name}' appears before 'flow' keyword. "
                        f"The 'flow' keyword must come FIRST in the options, before "
                        f"any sticky buffers or content matches."
                    ),
                    fix_hint=(
                        "Move 'flow:...' to be the first keyword after 'msg:' in the "
                        "rule options. Correct order: msg → flow → sticky buffers → "
                        "content → modifiers → sid/rev."
                    ),
                ))
                break  # One issue is enough to trigger self-correction
        return issues

    @staticmethod
    def _check_dsize_with_app_layer(options: str) -> list[BestPracticeIssue]:
        """Check that dsize isn't used with app-layer keywords."""
        issues = []
        has_dsize = "dsize:" in options
        app_keywords = [
            "http.", "tls.", "dns.", "file.", "urilen",
        ]
        has_app = any(kw in options for kw in app_keywords)

        if has_dsize and has_app:
            issues.append(BestPracticeIssue(
                category="dsize_with_app_layer",
                severity="strong_recommendation",
                message=(
                    "Rule uses 'dsize' with app-layer keywords. "
                    "dsize checks per-packet payload size and cannot be used "
                    "with app-layer buffers."
                ),
                fix_hint=(
                    "Remove 'dsize' and use 'bsize' after a sticky buffer, or "
                    "use 'http.content_len' with 'byte_test' for HTTP body size."
                ),
            ))

        return issues

    @staticmethod
    def _check_flow_direction(options: str, rule_str: str = "") -> list[BestPracticeIssue]:
        """Check that flow:established includes a direction (to_server or to_client).

        Bare 'flow:established' without direction is ambiguous and should always
        specify to_server (egress) or to_client (ingress).

        EXCEPTION: Bidirectional rules (<>) must NOT have a direction qualifier.
        """
        issues = []

        # Skip this check for bidirectional rules — they must use bare flow:established
        header = rule_str.split("(")[0] if "(" in rule_str else rule_str
        if "<>" in header:
            return issues

        # Find flow keyword and its value
        match = re.search(r'flow\s*:\s*([^;]+)', options)
        if not match:
            return issues

        flow_value = match.group(1).strip().lower()
        has_established = "established" in flow_value
        has_direction = "to_server" in flow_value or "to_client" in flow_value

        if has_established and not has_direction:
            issues.append(BestPracticeIssue(
                category="flow_missing_direction",
                severity="strong_recommendation",
                message=(
                    "Rule has 'flow:established' without a direction qualifier. "
                    "Always specify 'to_server' or 'to_client' with established."
                ),
                fix_hint=(
                    "Change 'flow:established' to 'flow:established,to_server' for "
                    "egress/outbound rules or 'flow:established,to_client' for "
                    "ingress/inbound rules."
                ),
            ))
        return issues

    @staticmethod
    def _check_dns_query_length(options: str) -> list[BestPracticeIssue]:
        """Check that dns.query length detection uses isdataat, not bsize.

        bsize checks buffer metadata size, not actual query data length.
        isdataat:N,relative correctly checks if at least N bytes of data exist.
        """
        issues = []
        has_dns_query = "dns.query" in options
        has_bsize = "bsize:" in options

        if has_dns_query and has_bsize:
            issues.append(BestPracticeIssue(
                category="dns_query_bsize",
                severity="strong_recommendation",
                message=(
                    "Rule uses 'bsize' after 'dns.query' for query length detection. "
                    "'bsize' checks buffer metadata size, not the actual DNS query "
                    "data length. Use 'isdataat' instead."
                ),
                fix_hint=(
                    "Replace 'bsize:>N' with 'isdataat:N,relative' after 'dns.query'. "
                    "Example: dns.query; isdataat:100,relative; detects queries "
                    "longer than 100 bytes."
                ),
            ))
        return issues

    @staticmethod
    def _check_brute_force_flow(options: str, user_lower: str) -> list[BestPracticeIssue]:
        """Check that brute force detection rules use flags:S, not flow:established.

        Brute force attacks involve connection attempts (SYN packets).
        flow:established only matches completed handshakes and misses failed attempts.

        EXCEPTION: If the rule has content/pcre matches (e.g., inspecting SMB
        STATUS_LOGON_FAILURE bytes), it NEEDS flow:established because SYN packets
        have no payload to inspect. Only flag pure connection-counting rules.
        """
        issues = []
        brute_force_terms = ["brute force", "brute-force", "connection attempts", "login attempts"]
        is_brute_force = any(t in user_lower for t in brute_force_terms)

        if not is_brute_force:
            return issues

        has_threshold = "threshold:" in options
        has_established = "flow:established" in options.replace(" ", "").lower() or "flow: established" in options.lower()
        has_flags_s = "flags:S" in options or "flags: S" in options
        has_content = "content:" in options or "pcre:" in options

        # Only flag if there are NO content matches — pure connection counting.
        # Rules with content/pcre need established connections to inspect payload.
        if has_threshold and has_established and not has_flags_s and not has_content:
            issues.append(BestPracticeIssue(
                category="brute_force_flow",
                severity="strong_recommendation",
                message=(
                    "Brute force detection uses 'flow:established' which only matches "
                    "completed TCP handshakes. This will miss failed connection attempts. "
                    "Use 'flow:to_server; flags:S;' to detect SYN packets instead."
                ),
                fix_hint=(
                    "Replace 'flow:established,to_server' with 'flow:to_server; flags:S;' "
                    "to catch connection attempts (SYN packets) rather than only established "
                    "connections."
                ),
            ))
        return issues

    @staticmethod
    def _check_stream_size_protocol(options: str, rule_str: str) -> list[BestPracticeIssue]:
        """Check that stream_size rules include app-layer-protocol to scope detection.

        Without app-layer-protocol, stream_size matches ALL TCP traffic exceeding
        the threshold, not just the target protocol (e.g., SSH tunneling).
        """
        issues = []
        has_stream_size = "stream_size:" in options
        has_app_layer = "app-layer-protocol:" in options

        if not has_stream_size:
            return issues

        # Check if the rule header already uses a specific protocol (not tcp)
        header = rule_str.split("(")[0].strip() if "(" in rule_str else rule_str
        parts = header.split()
        protocol = parts[1].lower() if len(parts) > 1 else ""

        # If protocol is generic tcp and no app-layer-protocol, suggest adding one
        if protocol == "tcp" and not has_app_layer:
            issues.append(BestPracticeIssue(
                category="stream_size_no_protocol",
                severity="strong_recommendation",
                message=(
                    "Rule uses 'stream_size' with generic TCP protocol but no "
                    "'app-layer-protocol' keyword. This will match ALL TCP traffic "
                    "exceeding the size threshold, not just the target protocol."
                ),
                fix_hint=(
                    "Add 'app-layer-protocol:ssh' (or the relevant protocol) to scope "
                    "the rule. Example: flow:established,to_server; "
                    "app-layer-protocol:ssh; stream_size:server,>,10485760;"
                ),
            ))
        return issues

    @staticmethod
    def _check_dual_tls_sticky_buffers(options: str) -> list[BestPracticeIssue]:
        """Check that tls.cert_subject and tls.cert_issuer are NOT both in the same rule.

        Suricata cannot compare subject vs issuer — the second sticky buffer overrides
        the first, so all content/pcre matches apply to the LAST buffer only.
        """
        issues = []
        has_subject = "tls.cert_subject" in options
        has_issuer = "tls.cert_issuer" in options

        if has_subject and has_issuer:
            issues.append(BestPracticeIssue(
                category="dual_tls_sticky_buffers",
                severity="strong_recommendation",
                message=(
                    "Rule uses BOTH tls.cert_subject AND tls.cert_issuer. "
                    "The second sticky buffer overrides the first — all content/pcre "
                    "matches apply to the LAST buffer only. You CANNOT compare "
                    "subject vs issuer this way."
                ),
                fix_hint=(
                    "Remove tls.cert_subject and keep ONLY tls.cert_issuer with a "
                    "negative PCRE lookahead to exclude well-known CAs. Example: "
                    "tls.cert_issuer; pcre:\"/^(?!.*(?:DigiCert|Let's Encrypt|Comodo|"
                    "GlobalSign|Sectigo|Amazon|Google Trust|Microsoft|IdenTrust))/i\";"
                ),
            ))
        return issues

    @staticmethod
    def _check_invalid_tls_cert_keywords(options: str) -> list[BestPracticeIssue]:
        """Check for invalid tls_cert_notbefore / tls_cert_notafter keywords.

        These appear in EVE JSON log output but are NOT valid Suricata rule keywords.
        Any rule using them will fail to load.
        """
        issues = []
        invalid_keywords = {
            "tls_cert_notbefore": "tls_cert_notbefore",
            "tls_cert_notafter": "tls_cert_notafter",
        }
        for kw_name, kw_text in invalid_keywords.items():
            if kw_text in options:
                issues.append(BestPracticeIssue(
                    category="invalid_tls_cert_keyword",
                    severity="strong_recommendation",
                    message=(
                        f"Rule uses '{kw_name}' which is NOT a valid Suricata rule keyword. "
                        f"It exists only in EVE JSON log output and will cause the rule to "
                        f"fail to load in Suricata."
                    ),
                    fix_hint=(
                        f"Remove '{kw_name}' entirely. Suricata cannot check certificate "
                        "dates or validity periods in rules. Instead, detect certs from "
                        "uncommon issuers using: tls.cert_issuer; pcre:\"/^(?!.*(?:DigiCert|"
                        "Let's Encrypt|Comodo|GlobalSign|Sectigo|Amazon))/i\";"
                    ),
                ))
        return issues

    @staticmethod
    def _check_cipher_without_sticky_buffer(options: str) -> list[BestPracticeIssue]:
        """Check that cipher suite detection uses tls.ciphersuites sticky buffer.

        When ssl_state:client_hello is used with pcre/content for cipher bytes,
        tls.ciphersuites must be used as the sticky buffer before the match.

        Skip this check if other TLS sticky buffers (tls.sni, tls.cert_subject, etc.)
        are present — the hex content likely targets those buffers, not cipher suites.
        """
        issues = []
        has_ssl_state = "ssl_state:client_hello" in options or "ssl_state: client_hello" in options
        has_ciphersuites = "tls.ciphersuites" in options

        if not has_ssl_state or has_ciphersuites:
            return issues

        # If other TLS sticky buffers are present, the hex content is likely
        # targeting those buffers, not cipher suites — skip the check
        other_tls_buffers = ["tls.sni", "tls.cert_subject", "tls.cert_issuer"]
        if any(buf in options for buf in other_tls_buffers):
            return issues

        # Also skip if HTTP sticky buffers are present (mixed TLS+HTTP rule)
        http_buffers = ["http.uri", "http.host", "http.method", "http.user_agent",
                        "http.header", "http.content_type"]
        if any(buf in options for buf in http_buffers):
            return issues

        has_cipher_pcre = False
        # Check for hex byte patterns typical of cipher suite matching
        parts = _split_options(options)
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw in ("pcre", "content") and ("\\x" in part or "|" in part):
                has_cipher_pcre = True
                break

        if has_cipher_pcre:
            issues.append(BestPracticeIssue(
                category="cipher_no_sticky_buffer",
                severity="strong_recommendation",
                message=(
                    "Rule uses ssl_state:client_hello with hex byte matching but "
                    "without tls.ciphersuites sticky buffer. The pcre/content match "
                    "needs tls.ciphersuites to target the cipher suite list."
                ),
                fix_hint=(
                    "Add 'tls.ciphersuites' before the content/pcre match. "
                    "Example: ssl_state:client_hello; tls.ciphersuites; content:\"|00 00|\"; "
                    "or: ssl_state:client_hello; tls.ciphersuites; pcre:\"/\\x00\\x00/\";"
                ),
            ))
        return issues

    @staticmethod
    def _check_invalid_http2_keywords(options: str) -> list[BestPracticeIssue]:
        """Check for invalid http2.framelen keyword.

        http2.framelen is NOT a valid Suricata rule keyword. Suricata cannot
        directly inspect HTTP/2 frame lengths in rules.
        Only flag when it appears as an actual keyword, not inside msg or content strings.
        """
        issues = []
        parts = _split_options(options)
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http2.framelen":
                issues.append(BestPracticeIssue(
                    category="invalid_http2_keyword",
                    severity="strong_recommendation",
                    message=(
                        "Rule uses 'http2.framelen' which is NOT a valid Suricata keyword. "
                        "Suricata cannot directly inspect HTTP/2 frame lengths in rules. "
                        "Comparing Content-Length vs frame length requires Lua scripting."
                    ),
                    fix_hint=(
                        "Remove 'http2.framelen' and related byte_test. For HTTP/2 smuggling, "
                        "detect Transfer-Encoding presence (forbidden in HTTP/2) or "
                        "Content-Length:0 with non-empty body instead."
                    ),
                ))
                break
        return issues

    @staticmethod
    def _check_broad_crlf_detection(options: str) -> list[BestPracticeIssue]:
        """Check for overly broad CRLF injection detection patterns.

        1. |0d 0a 0d 0a| (double CRLF) naturally terminates HTTP headers — false positives.
        2. content:!"|0d 0a 0d 0a|" negation doesn't work as intended for exclusion.
        Both should use: content:"|0d 0a|"; content:"|0d 0a|"; distance:1; within:5;
        """
        issues = []
        if "http.header" not in options:
            return issues

        # Check 1: Positive double-CRLF match
        if 'content:"|0d 0a 0d 0a|"' in options:
            has_negation = 'content:!"|0d 0a 0d 0a|"' in options
            has_positive = 'content:"|0d 0a 0d 0a|"' in options
            if has_positive and not has_negation:
                issues.append(BestPracticeIssue(
                    category="broad_crlf_detection",
                    severity="strong_recommendation",
                    message=(
                        "Rule matches |0d 0a 0d 0a| (double CRLF) in http.header. "
                        "This sequence naturally terminates HTTP headers and will "
                        "cause massive false positives on ALL HTTP traffic."
                    ),
                    fix_hint=(
                        "For CRLF injection, detect two single CRLFs close together: "
                        "http.header; content:\"|0d 0a|\"; content:\"|0d 0a|\"; "
                        "distance:1; within:5;"
                    ),
                ))

        # Check 2: Negation pattern that doesn't work as intended
        if 'content:!"|0d 0a 0d 0a|"' in options:
            issues.append(BestPracticeIssue(
                category="broad_crlf_negation",
                severity="strong_recommendation",
                message=(
                    "Rule uses content:!\"|0d 0a 0d 0a|\" negation which does not "
                    "work as intended for excluding normal header terminators."
                ),
                fix_hint=(
                    "Remove the negation. Instead use distance/within modifiers: "
                    "http.header; content:\"|0d 0a|\"; content:\"|0d 0a|\"; "
                    "distance:1; within:5;"
                ),
            ))

        return issues

    @staticmethod
    def _check_bsize_after_stat_code(options: str) -> list[BestPracticeIssue]:
        """Check for unnecessary bsize after http.stat_code.

        HTTP status codes are always exactly 3 digits. Using bsize:3 is
        redundant and not standard practice.
        """
        issues = []
        parts = _split_options(options)
        stat_code_seen = False
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http.stat_code":
                stat_code_seen = True
            elif kw == "bsize" and stat_code_seen:
                issues.append(BestPracticeIssue(
                    category="bsize_after_stat_code",
                    severity="recommendation",
                    message=(
                        "Rule uses 'bsize' after 'http.stat_code'. HTTP status codes "
                        "are always 3 digits — bsize is redundant here."
                    ),
                    fix_hint=(
                        "Remove 'bsize:3' after http.stat_code. The content match "
                        "alone (e.g., content:\"101\") is sufficient."
                    ),
                ))
                break
            elif kw in ("http.header", "http.uri", "http.host", "http.header_names",
                        "http.content_len", "http.protocol"):
                stat_code_seen = False
        return issues

    
    @staticmethod
    def _check_crlf_in_header_names(options: str) -> list[BestPracticeIssue]:
        """Check for CRLF hex bytes in content matches within http.header_names context.

        http.header_names buffer contains header names without CRLF delimiters.
        Using |0d 0a|HeaderName|0d 0a| is incorrect — just use content:"HeaderName".
        For http.header, only flag CRLF wrapping patterns (|0d 0a|Name|0d 0a|),
        not standalone |0d 0a| used for CRLF injection detection.
        """
        issues = []
        parts = _split_options(options)
        current_buffer = None
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http.header_names":
                current_buffer = "header_names"
            elif kw == "http.header":
                current_buffer = "header"
            elif kw == "content" and current_buffer is not None:
                if "|0d 0a|" in part:
                    if current_buffer == "header_names":
                        # Any CRLF in header_names is wrong
                        issues.append(BestPracticeIssue(
                            category="crlf_in_header_names",
                            severity="strong_recommendation",
                            message=(
                                "Rule uses CRLF hex bytes (|0d 0a|) in content match within "
                                "http.header_names buffer. This buffer contains individual "
                                "header names without CRLF delimiters."
                            ),
                            fix_hint=(
                                "Remove |0d 0a| from the content match. "
                                "Example: http.header_names; content:\"Transfer-Encoding\"; nocase; "
                                "instead of content:\"|0d 0a|Transfer-Encoding|0d 0a|\"."
                            ),
                        ))
                        break
                    elif current_buffer == "header":
                        # In http.header, only flag wrapping patterns like |0d 0a|Name|0d 0a|
                        # Standalone |0d 0a| for injection detection is valid
                        content_val = part.split(":", 1)[1].strip().strip('"') if ":" in part else ""
                        if content_val.startswith("|0d 0a|") and content_val.endswith("|0d 0a|") and len(content_val) > 14:
                            issues.append(BestPracticeIssue(
                                category="crlf_in_header_names",
                                severity="strong_recommendation",
                                message=(
                                    "Rule wraps header name in CRLF (|0d 0a|Name|0d 0a|) within "
                                    "http.header buffer. Use the header name directly without CRLF wrapping."
                                ),
                                fix_hint=(
                                    "Remove |0d 0a| wrapping. Use content:\"HeaderName\"; or "
                                    "content:\"HeaderName|3a 20|value\"; instead."
                                ),
                            ))
                            break
            elif kw in ("nocase", "depth", "offset", "distance", "within",
                        "fast_pattern", "startswith", "endswith", "bsize",
                        "pcre"):
                pass  # modifiers don't change buffer context
            else:
                current_buffer = None
        return issues

    @staticmethod
    def _check_dns_multiple_content_or(options: str, rule_str: str) -> list[BestPracticeIssue]:
        """Check for multiple content matches on dns.query that should use OR logic.

        Multiple content matches in Suricata are AND logic — ALL must match.
        For DNS threat detection (malware OR phishing OR botnet), a single
        query won't contain all terms. Use PCRE with alternation instead.
        """
        issues = []
        if "dns.query" not in options:
            return issues

        parts = _split_options(options)
        # Count content matches that appear after dns.query
        dns_query_seen = False
        content_after_dns = []
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "dns.query":
                dns_query_seen = True
            elif kw == "content" and dns_query_seen:
                # Extract the content value
                match = re.search(r'content\s*:\s*"([^"]*)"', part)
                if match:
                    content_after_dns.append(match.group(1))
            elif kw in ("nocase", "depth", "offset", "distance", "within",
                        "fast_pattern", "startswith", "endswith", "bsize",
                        "isdataat"):
                pass  # modifiers don't break the dns.query context
            elif kw not in ("msg", "flow", "sid", "rev", "threshold",
                            "classtype", "priority", "metadata", "reference"):
                # A non-modifier, non-meta keyword resets context
                if kw != "pcre":
                    dns_query_seen = False

        if len(content_after_dns) >= 3:
            terms = ", ".join(f'"{c}"' for c in content_after_dns)
            pcre_alt = "|".join(re.escape(c) for c in content_after_dns)
            issues.append(BestPracticeIssue(
                category="dns_multiple_content_and",
                severity="strong_recommendation",
                message=(
                    f"Rule has {len(content_after_dns)} content matches after dns.query "
                    f"({terms}). In Suricata, multiple content matches are AND logic — "
                    f"ALL must be present in a single DNS query. A query is unlikely to "
                    f"contain all these terms simultaneously."
                ),
                fix_hint=(
                    f"Replace multiple content matches with a single PCRE using OR logic: "
                    f'pcre:"/({pcre_alt})/i"; This matches if ANY of the terms appear.'
                ),
            ))

        return issues
    @staticmethod
    def _check_empty_content(options: str) -> list[BestPracticeIssue]:
        """Check for empty content matches like content:"".

        Empty content matches are invalid and will cause the rule to
        malfunction or fail to load.
        """
        issues = []
        parts = _split_options(options)
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "content":
                # Check for empty content: content:"" or content:""
                if re.search(r'content\s*:\s*""\s*$', part):
                    issues.append(BestPracticeIssue(
                        category="empty_content",
                        severity="strong_recommendation",
                        message=(
                            "Rule has an empty content match (content:\"\"). "
                            "Empty content is invalid and will cause the rule to "
                            "malfunction. Every content match must have a pattern."
                        ),
                        fix_hint=(
                            "Remove the empty content match or replace it with a "
                            "meaningful pattern. For CRLF injection detection, use: "
                            "content:\"|0d 0a|\"; to match embedded CRLF bytes."
                        ),
                    ))
                    break
        return issues

    @staticmethod
    def _check_duplicate_sticky_buffers(options: str) -> list[BestPracticeIssue]:
        """Check for duplicate consecutive sticky buffers like http.header; http.header;

        Two identical sticky buffers in a row is redundant — the second one
        just re-selects the same buffer. This usually indicates the LLM intended
        to use two different buffers (e.g., http.header_names then http.header).
        """
        issues = []
        sticky_buffers = {
            "http.uri", "http.host", "http.method", "http.user_agent",
            "http.cookie", "http.header", "http.content_type",
            "http.content_len", "http.stat_code", "http.stat_msg",
            "http.request_body", "http.response_body", "http.referer",
            "http.server", "http.location", "http.protocol",
            "http.header_names", "http.start",
            "tls.sni", "tls.cert_subject", "tls.cert_issuer", "tls.ciphersuites",
            "dns.query", "file.data", "file.name", "file_data",
            "smb.share", "smb.named_pipe", "dcerpc.stub_data",
        }

        parts = _split_options(options)
        prev_kw = None
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw in sticky_buffers:
                if kw == prev_kw:
                    issues.append(BestPracticeIssue(
                        category="duplicate_sticky_buffer",
                        severity="strong_recommendation",
                        message=(
                            f"Rule has duplicate consecutive sticky buffer '{kw}'. "
                            f"The second '{kw}' is redundant — it just re-selects "
                            f"the same buffer. Remove the duplicate."
                        ),
                        fix_hint=(
                            f"Remove the duplicate '{kw}'. If you intended to match "
                            f"different content in the same buffer, use a single '{kw}' "
                            f"followed by multiple content matches."
                        ),
                    ))
                    break
                prev_kw = kw
            elif kw in ("nocase", "depth", "offset", "distance", "within",
                        "fast_pattern", "startswith", "endswith", "bsize",
                        "content", "pcre"):
                pass  # Don't reset prev_kw for content/modifiers
            else:
                prev_kw = None
        return issues

    @staticmethod
    def _check_unreliable_body_detection(options: str) -> list[BestPracticeIssue]:
        """Check for unreliable non-empty body detection using content:!"|00|".

        content:!"|00|" does NOT reliably detect a non-empty body.
        Use isdataat:1; in http.request_body instead.
        """
        issues = []
        if 'content:!"|00|"' in options and "http.request_body" in options:
            issues.append(BestPracticeIssue(
                category="unreliable_body_detection",
                severity="strong_recommendation",
                message=(
                    "Rule uses content:!\"|00|\" in http.request_body to detect "
                    "non-empty body. This is unreliable — a body can be non-empty "
                    "without containing a null byte."
                ),
                fix_hint=(
                    "Replace content:!\"|00|\" with isdataat:1; after "
                    "http.request_body to reliably check for a non-empty body."
                ),
            ))
        return issues

    @staticmethod
    def _check_flow_on_ip_protocol(options: str, rule_str: str) -> list[BestPracticeIssue]:
        """Check that flow keyword is NOT used with IP protocol rules.

        flow:to_server/to_client only works with TCP/UDP stateful protocols.
        For rules using 'ip' protocol, the flow keyword is invalid.
        """
        issues = []
        if "flow:" not in options:
            return issues

        header = rule_str.split("(")[0].strip() if "(" in rule_str else rule_str
        parts = header.split()
        protocol = parts[1].lower() if len(parts) > 1 else ""

        if protocol == "ip":
            issues.append(BestPracticeIssue(
                category="flow_on_ip_protocol",
                severity="strong_recommendation",
                message=(
                    "Rule uses 'ip' protocol with 'flow' keyword. The flow keyword "
                    "only works with TCP/UDP stateful protocols. For IP protocol rules, "
                    "the flow keyword is invalid and must be removed."
                ),
                fix_hint=(
                    "Remove the 'flow:...' keyword from this rule. IP protocol rules "
                    "cannot use flow state tracking."
                ),
            ))
        return issues

    @staticmethod
    def _check_ip_proto_negation(options: str) -> list[BestPracticeIssue]:
        """Check for invalid ip_proto negation syntax.

        Suricata does NOT support ip_proto:!TCP, ip_proto:!6, etc.
        Protocol negation must use positive matches for specific protocols.
        """
        issues = []
        if "ip_proto:!" not in options:
            return issues

        issues.append(BestPracticeIssue(
            category="ip_proto_negation",
            severity="strong_recommendation",
            message=(
                "Rule uses ip_proto negation (ip_proto:!...) which is NOT supported "
                "by Suricata. Protocol negation is invalid syntax and will cause "
                "the rule to fail to load."
            ),
            fix_hint=(
                "Replace negated ip_proto with positive matches for specific protocols "
                "to block. Use separate rules: ip_proto:47 (GRE), ip_proto:50 (ESP), "
                "ip_proto:51 (AH), ip_proto:4 (IP-in-IP). Use numeric protocol numbers, "
                "not names."
            ),
        ))
        return issues

    @staticmethod
    def _check_bidir_flow_direction(options: str, rule_str: str) -> list[BestPracticeIssue]:
        """Check that bidirectional rules don't use flow direction qualifiers.

        The <> operator means traffic in both directions. Using flow:to_server
        or flow:to_client with <> is contradictory and will cause issues.
        """
        issues = []
        header = rule_str.split("(")[0] if "(" in rule_str else rule_str
        if "<>" not in header:
            return issues

        flow_match = re.search(r'flow\s*:\s*([^;]+)', options)
        if not flow_match:
            return issues

        flow_val = flow_match.group(1).strip().lower()
        if "to_server" in flow_val or "to_client" in flow_val:
            issues.append(BestPracticeIssue(
                category="bidir_flow_direction",
                severity="strong_recommendation",
                message=(
                    "Rule uses bidirectional operator <> with directional flow qualifier "
                    f"(flow:{flow_val}). The <> operator matches traffic in both directions, "
                    "which conflicts with to_server/to_client."
                ),
                fix_hint=(
                    "Remove the direction qualifier from flow. Use 'flow:established' "
                    "(no direction) with <> rules, or omit flow entirely."
                ),
            ))
        return issues

