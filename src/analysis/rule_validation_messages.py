"""
Rule Validation Messages (UI-free)

Code -> display string tables for findings produced by
``src/analysis/rule_validator.py``. Detection emits only codes and params;
each audience gets its own wording from here:

- TERSE_TEMPLATES / render_terse: the Advanced Editor's terse strings, also
  used by the paste comment header and the disk-save/export aggregate dialog.
- VERBOSE_TEMPLATES / render_verbose: the main editor's novice-friendly
  (title, body) dialogs.

Both tables follow the spec's Message Catalog. Every catalog row in phase 1
has an explicit dialog title, so no default title is applied.
This module must not import wx or tkinter.
"""

from __future__ import annotations


def _terse_forbidden_modifier(finding):
    p = _params(finding)
    if p.get("reason"):
        return "{modifier} is redundant \u2014 {reason}".format(**p)
    return "{modifier} cannot be used with {keyword}".format(**p)


def _terse_geoip_invalid(finding):
    p = _params(finding)
    if p.get("suggestion"):
        return "Invalid country code '{code}' \u2014 use {suggestion} (ISO 3166-1 alpha-2)".format(**p)
    return "Invalid country code '{code}' \u2014 check ISO 3166-1 alpha-2 codes".format(**p)


def _terse_invalid_enum(finding):
    p = _params(finding)
    if "min" in p and "max" in p:
        return ("Invalid value '{value}' for keyword '{keyword}' \u2014 "
                "use a protocol name or number ({min}-{max})").format(**p)
    return "Invalid value '{value}' for keyword '{keyword}'".format(**p)


# code -> terse template string (or callable(finding) -> str for conditional variants).
# The Advanced Editor's existing wording, byte-for-byte (U+2014 em dashes).
TERSE_TEMPLATES = {
    "AWS_UNSUPPORTED_KEYWORD":
        "{keyword} is not supported in AWS Network Firewall: {reason}",
    "SYNTAX_MODE_DIRECT_AS_STICKY":
        "{keyword} takes its value directly \u2014 use "
        "{keyword}:\"value\" instead of {keyword}; content:\"value\"",
    "SYNTAX_MODE_STICKY_AS_DIRECT":
        "{keyword} is a sticky buffer \u2014 use "
        "{keyword}; content:\"value\" instead of {keyword}:\"{value}\"",
    "SSL_VERSION_NEGATION":
        "ssl_version allows only a single leading ! that negates the whole list "
        "(e.g. ssl_version:!tls1.0,tls1.1)",
    "SSL_VERSION_DUPLICATE":
        "duplicate ssl_version value '{name}'",
    "XBITS_TRACK_TX":
        "xbits with track tx is not supported in AWS Network Firewall \u2014 use flowbits instead",
    "FORBIDDEN_MODIFIER": _terse_forbidden_modifier,
    "JA3_HASH_LENGTH":
        "JA3/JA3S hash must be exactly 32 characters (MD5 hash)",
    "PACKET_APP_LAYER_MIXING":
        "{packet_keyword} is a packet-level keyword \u2014 cannot be combined "
        "with app-layer keywords ({app_layer_list}) in the same rule. "
        "Split into separate rules.",
    "PCRE_COMPANION":
        "pcre requires one of: content, tls.sni, http.host, http.uri, or dns.query in the same rule",
    "IP_PROTO_PROTOCOL":
        "ip_proto keyword can only be used with 'ip' protocol in the rule header",
    "FLOW_DIRECTION_RESPONSE_ON_TO_SERVER":
        "{keyword} is a response buffer \u2014 use flow:to_client instead of flow:to_server",
    "FLOW_DIRECTION_REQUEST_ON_TO_CLIENT":
        "{keyword} is a request buffer \u2014 use flow:to_server instead of flow:to_client",
    "GEOIP_INVALID_COUNTRY_CODE": _terse_geoip_invalid,
    "GEOIP_MISSING_COUNTRY_CODE":
        "geoip requires at least one country code after the direction (e.g., geoip:src,US)",
    "INVALID_ENUM_VALUE": _terse_invalid_enum,
    "AWS_URL_CATEGORY_PROTOCOL":
        "aws_url_category only supports HTTP or HTTP2 protocols",
    "AWS_DOMAIN_CATEGORY_PROTOCOL":
        "aws_domain_category only supports TLS, HTTP, or HTTP2 protocols",
    "R53_DOMAIN_UNQUOTED":
        'aws_route_53_resolved_domain value must be in double quotes, '
        'e.g. aws_route_53_resolved_domain:"example.com"',
    "R53_DOMAIN_MULTIPLE":
        "only one aws_route_53_resolved_domain keyword is allowed per rule",
    "R53_DOMAIN_ASTERISK":
        "use a leading dot for wildcards (.example.com), not an asterisk",
    "APP_LAYER_PROTOCOL_REDUNDANT":
        "app-layer-protocol is redundant \u2014 the protocol is already "
        "set by the rule header or other keywords",
    "APP_LAYER_PROTOCOL_CONFLICT":
        "conflicting app-layer-protocol keywords \u2014 use one non-negated value, "
        "or only negated values",
    "REJECT_UNSUPPORTED_PROTOCOL":
        "reject is only valid on tcp, http, tls, smb, dcerpc, ssh, or smtp",
    # Phase 2 (task 16)
    "MIXED_DIRECTION_BUFFERS":
        "{req_kw} (request) and {resp_kw} (response) cannot be used in the same "
        "rule \u2014 split into separate rules",
    "IP_REFERENCE_IN_GROUP":
        "IP set reference {reference} cannot be used inside a group \u2014 use it "
        "alone as {reference} or !{reference}",
    "GID_NOT_ALLOWED":
        "gid is not allowed \u2014 AWS Network Firewall assigns its own gid",
    # Phase 2 (task 18)
    "HTTP_HOST_UPPERCASE":
        "http.host content must be lowercase \u2014 the buffer is normalized to lowercase",
    "MD5_BUFFER_NOT_HEX":
        "JA3/JA3S hash must contain only hexadecimal characters (0-9, a-f)",
    "MD5_BUFFER_NOCASE":
        "nocase cannot be used with {keyword} \u2014 JA3/JA3S hashes are matched exactly",
    # Phase 2 (task 19)
    "CATEGORY_DUPLICATE_VALUE":
        "duplicate {keyword} value '{value}'",
    "CATEGORY_EMPTY":
        "{keyword} must contain at least one category",
    "CATEGORY_KEYWORD_CONFLICT":
        "use either aws_url_category or aws_domain_category, once per rule \u2014 "
        "not both or more than one",
    "R53_DOMAIN_EMPTY":
        "aws_route_53_resolved_domain must contain at least one domain",
    "R53_DOMAIN_INVALID":
        "aws_route_53_resolved_domain contains invalid domain '{domain}'",
    # Phase 2 (task 20)
    "RULE_TOO_LONG":
        "rule is {length} bytes with variables expanded \u2014 AWS Network Firewall "
        "allows at most 8191",
    # Phase 2 (task 21, group)
    "FLOWBITS_ISSET_NOT_SET":
        "flowbit '{name}' is checked but never set by any rule in this file",
    # Non-blocking / group codes
    "UNKNOWN_KEYWORD": "Unknown keyword: {keyword}",
    "UNDEFINED_VARIABLE": "Undefined variable: {variable}",
    "DUPLICATE_SID": "Duplicate SID {sid}: also used on line(s) {lines}",
}

def _protocol_upper(finding):
    return str(_params(finding).get("protocol", "")).upper()


def _verbose_forbidden_modifier(finding):
    p = _params(finding)
    if p.get("reason"):
        reason_or_generic = "Reason: {reason}".format(**p)
    else:
        reason_or_generic = "'{modifier}' is not valid in combination with '{keyword}'.".format(**p)
    body = ("The modifier '{modifier}' cannot be used after '{keyword}'.\n\n"
            "{reason_or_generic}\n\n"
            "Please remove '{modifier}' from this rule.").format(
                reason_or_generic=reason_or_generic, **p)
    return "Invalid Modifier", body


def _verbose_geoip_invalid(finding):
    p = _params(finding)
    if p.get("suggestion"):
        suggestion_clause = "\n\nDid you mean '{suggestion}'?".format(**p)
    else:
        suggestion_clause = ""
    body = ("'{code}' is not a valid country code. GeoIP matching uses ISO 3166-1 "
            "alpha-2 codes (two letters).{suggestion_clause}\n\n"
            "Please correct the country code in the geoip keyword.").format(
                suggestion_clause=suggestion_clause, **p)
    return "Invalid Country Code", body


def _verbose_invalid_enum(finding):
    p = _params(finding)
    if "min" in p and "max" in p:
        range_clause = ("\n\nValid values are a protocol name or a number "
                        "from {min} to {max}.").format(**p)
    else:
        range_clause = ""
    body = ("'{value}' is not a valid value for the '{keyword}' keyword.{range_clause}\n\n"
            "Please choose a valid value for '{keyword}'.").format(
                range_clause=range_clause, **p)
    # Category refinement (aws_url_category / aws_domain_category): a value that
    # matches a category only case-insensitively carries the correctly-cased
    # category as params["suggestion"].
    if p.get("suggestion"):
        body += ("\n\nCategory names are case-sensitive. "
                 "Did you mean '{suggestion}'?").format(**p)
    return "Invalid Keyword Value", body


def _verbose_url_category_protocol(finding):
    protocol = _protocol_upper(finding)
    return (
        "Protocol/Category Mismatch",
        f"The Content Keywords field contains aws_url_category which only supports HTTP or HTTP2 protocols.\n\n"
        f"Current protocol: {protocol}\n"
        f"Required protocol: HTTP or HTTP2\n\n"
        f"Please either:\n"
        f"1. Change protocol to HTTP or HTTP2\n"
        f"2. Remove aws_url_category from Content Keywords"
    )


def _verbose_domain_category_protocol(finding):
    protocol = _protocol_upper(finding)
    return (
        "Protocol/Category Mismatch",
        f"The Content Keywords field contains aws_domain_category which only supports TLS, HTTP, or HTTP2 protocols.\n\n"
        f"Current protocol: {protocol}\n"
        f"Required protocols: TLS, HTTP, or HTTP2\n\n"
        f"Please either:\n"
        f"1. Change protocol to TLS, HTTP, or HTTP2\n"
        f"2. Remove aws_domain_category from Content Keywords"
    )


def _verbose_reject_unsupported(finding):
    protocol = _protocol_upper(finding)
    return (
        "Action/Protocol Mismatch",
        "The 'reject' action is only supported on these protocols in "
        "AWS Network Firewall: tcp, http, tls, smb, dcerpc, ssh, smtp.\n\n"
        f"Current protocol: {protocol}\n\n"
        "Please either:\n"
        "1. Change the action to 'drop', or\n"
        "2. Change the protocol to one of the protocols listed above."
    )


def _verbose_app_layer_redundant(finding):
    p = _params(finding)
    keyword = p.get("keyword", "app-layer-protocol")
    if p.get("source") == "keyword":
        origin = "the '{}' keyword".format(p.get("source_name", ""))
    elif p.get("source") == "header":
        origin = "its protocol field '{}'".format(p.get("source_name", ""))
    else:
        origin = "its protocol field or another keyword"
    body = (
        "This rule already sets its application protocol through {origin}. AWS "
        "Network Firewall then rejects any {keyword} keyword that comes after it, "
        "even a negated one or one naming a different protocol.\n\n"
        "Please either:\n"
        "1. Remove the {keyword} keyword, or\n"
        "2. Change the rule protocol to tcp (or udp) and place {keyword} before any "
        "protocol-specific keywords.").format(origin=origin, keyword=keyword)
    return "Redundant app-layer-protocol", body


# code -> (title, body template) (or callable(finding) -> (title, body)).
# The main editor's novice-friendly dialogs (Message Catalog "Main editor
# (verbose)" column). Phase 2 codes add their rows in their own tasks.
# UNDEFINED_VARIABLE / DUPLICATE_SID keep their existing hard-block messages in
# their current code paths; UNKNOWN_KEYWORD is never shown by the main editor.
VERBOSE_TEMPLATES = {
    "AWS_UNSUPPORTED_KEYWORD": (
        "Unsupported Keyword",
        "The keyword '{keyword}' is not supported by AWS Network Firewall and will "
        "cause the rule group to fail on import.\n\n"
        "Reason: {reason}\n\n"
        "Please remove '{keyword}' from the Content Keywords, or replace it with a "
        "supported alternative."),
    "SYNTAX_MODE_DIRECT_AS_STICKY": (
        "Keyword Syntax Error",
        "'{keyword}' takes its value directly, so it should not be followed by a "
        "separate content match.\n\n"
        "Incorrect: {keyword}; content:\"value\"\n"
        "Correct:   {keyword}:\"value\"\n\n"
        "Please rewrite this keyword to put the value directly after the colon."),
    "SYNTAX_MODE_STICKY_AS_DIRECT": (
        "Keyword Syntax Error",
        "'{keyword}' is a sticky buffer, so its value must be given with a following "
        "content match rather than directly.\n\n"
        "Incorrect: {keyword}:\"{value}\"\n"
        "Correct:   {keyword}; content:\"{value}\"\n\n"
        "Please rewrite this keyword to use a separate content match."),
    "SSL_VERSION_NEGATION": (
        "Invalid ssl_version Negation",
        "AWS Network Firewall allows only one '!' in an ssl_version value, and it must "
        "be the very first character. That single '!' negates the whole list.\n\n"
        "Correct:   ssl_version:!tls1.0,tls1.1   (matches any version except TLS 1.0 "
        "and TLS 1.1)\n"
        "Incorrect: ssl_version:tls1.0,!tls1.1\n"
        "Incorrect: ssl_version:!tls1.0,!tls1.1\n\n"
        "Please either:\n"
        "1. Keep a single '!' at the start of the value to negate the whole list, or\n"
        "2. Remove the '!' and list only the versions you want to match."),
    "SSL_VERSION_DUPLICATE": (
        "Duplicate ssl_version Value",
        "The ssl_version value lists '{name}' more than once. AWS Network Firewall "
        "rejects a rule that repeats an ssl_version value.\n\n"
        "Please remove the extra '{name}' from the ssl_version list."),
    "XBITS_TRACK_TX": (
        "Unsupported xbits Tracking",
        "AWS Network Firewall does not support xbits with 'track tx'. xbits tracked by "
        "IP address (track ip_src, track ip_dst, or track ip_pair) is supported.\n\n"
        "Please either:\n"
        "1. Change the tracking to track ip_src, track ip_dst, or track ip_pair, or\n"
        "2. Use flowbits instead to keep state within a single flow."),
    "FORBIDDEN_MODIFIER": _verbose_forbidden_modifier,
    "JA3_HASH_LENGTH": (
        "Invalid JA3/JA3S Hash",
        "A JA3 or JA3S fingerprint is an MD5 hash and must be exactly 32 hexadecimal "
        "characters.\n\n"
        "The value you entered has {actual_len} characters.\n\n"
        "Please provide a valid 32-character JA3/JA3S hash."),
    "PACKET_APP_LAYER_MIXING": (
        "Incompatible Keyword Combination",
        "'{packet_keyword}' inspects individual packets, while {app_layer_list} inspect "
        "the application layer. AWS Network Firewall cannot evaluate both kinds of "
        "match in the same rule.\n\n"
        "Please split this into two separate rules \u2014 one for the packet-level match "
        "and one for the application-layer match."),
    "PCRE_COMPANION": (
        "pcre Requires a Companion Keyword",
        "A 'pcre' match is too expensive to run on its own, so AWS Network Firewall "
        "requires at least one companion keyword in the same rule to pre-filter "
        "traffic.\n\n"
        "Please add one of: content, tls.sni, http.host, http.uri, or dns.query "
        "alongside the pcre match."),
    "IP_PROTO_PROTOCOL": (
        "ip_proto Protocol Mismatch",
        "The 'ip_proto' keyword is only valid when the rule's protocol (the second "
        "field of the rule header) is 'ip'.\n\n"
        "Current protocol: {protocol}\n\n"
        "Please either:\n"
        "1. Change the rule protocol to 'ip', or\n"
        "2. Remove the ip_proto keyword."),
    "FLOW_DIRECTION_RESPONSE_ON_TO_SERVER": (
        "Flow Direction Conflict",
        "'{keyword}' inspects server-to-client (response) data, but this rule specifies "
        "flow:to_server (client-to-server). The rule can never match.\n\n"
        "Please change the flow direction to flow:to_client, or remove '{keyword}'."),
    "FLOW_DIRECTION_REQUEST_ON_TO_CLIENT": (
        "Flow Direction Conflict",
        "'{keyword}' inspects client-to-server (request) data, but this rule specifies "
        "flow:to_client (server-to-client). The rule can never match.\n\n"
        "Please change the flow direction to flow:to_server, or remove '{keyword}'."),
    "GEOIP_INVALID_COUNTRY_CODE": _verbose_geoip_invalid,
    "GEOIP_MISSING_COUNTRY_CODE": (
        "Incomplete geoip Keyword",
        "The geoip keyword needs a direction followed by at least one country code, "
        "for example geoip:src,US.\n\n"
        "Please add one or more ISO 3166-1 alpha-2 country codes after the direction."),
    "INVALID_ENUM_VALUE": _verbose_invalid_enum,
    "AWS_URL_CATEGORY_PROTOCOL": _verbose_url_category_protocol,
    "AWS_DOMAIN_CATEGORY_PROTOCOL": _verbose_domain_category_protocol,
    "R53_DOMAIN_UNQUOTED": (
        "Invalid aws_route_53_resolved_domain Syntax",
        "The domain value for aws_route_53_resolved_domain must be enclosed in double "
        "quotes.\n\n"
        "Example: aws_route_53_resolved_domain:\"example.com\"\n\n"
        "Please add double quotes around the domain value."),
    "R53_DOMAIN_MULTIPLE": (
        "Too Many aws_route_53_resolved_domain Keywords",
        "A rule may contain only one aws_route_53_resolved_domain keyword. To match "
        "several domains, put them in a single comma-separated value, e.g. "
        "aws_route_53_resolved_domain:\"a.example.com,b.example.com\".\n\n"
        "Please combine the domains into a single keyword."),
    "R53_DOMAIN_ASTERISK": (
        "Invalid Wildcard Syntax",
        "aws_route_53_resolved_domain wildcards are written with a leading dot, not an "
        "asterisk.\n\n"
        "Incorrect: \"*.example.com\"\n"
        "Correct:   \".example.com\"\n\n"
        "A leading dot matches the domain and all of its subdomains. Please replace "
        "the asterisk with a leading dot."),
    "REJECT_UNSUPPORTED_PROTOCOL": _verbose_reject_unsupported,
    "APP_LAYER_PROTOCOL_REDUNDANT": _verbose_app_layer_redundant,
    "APP_LAYER_PROTOCOL_CONFLICT": (
        "Conflicting app-layer-protocol Keywords",
        "This rule has more than one app-layer-protocol keyword, and they conflict "
        "('{keyword}:{first}' and '{keyword}:{protocol}'). AWS Network Firewall "
        "allows only one non-negated app-layer-protocol value per rule, and does "
        "not allow a non-negated value to be mixed with negated ones.\n\n"
        "Please either:\n"
        "1. Keep a single non-negated app-layer-protocol keyword, or\n"
        "2. Use only negated values (for example app-layer-protocol:!http; "
        "app-layer-protocol:!tls;)."),
    # Phase 2 (task 16)
    "MIXED_DIRECTION_BUFFERS": (
        "Request and Response Keywords Mixed",
        "'{req_kw}' inspects the request (client to server), while '{resp_kw}' "
        "inspects the response (server to client). AWS Network Firewall rejects a "
        "rule that mixes request and response keywords.\n\n"
        "Please split this into two separate rules \u2014 one that matches the request "
        "and one that matches the response."),
    "IP_REFERENCE_IN_GROUP": (
        "IP Set Reference Inside a Group",
        "The {field} '{value}' puts the IP set reference '{reference}' inside a "
        "bracketed group. AWS Network Firewall accepts an IP set reference only as "
        "the whole field, for example @MY_SET or !@MY_SET.\n\n"
        "Please either:\n"
        "1. Use '{reference}' alone as the {field}, or\n"
        "2. Add the other addresses to the IP set itself, or use a $ variable for "
        "the group."),
    "GID_NOT_ALLOWED": (
        "gid Not Allowed",
        "AWS Network Firewall sets the gid (group ID) of every rule itself and rejects "
        "rules that include their own gid option.\n\n"
        "Please remove 'gid:{value}' from the Content Keywords."),
    # Phase 2 (task 18)
    "HTTP_HOST_UPPERCASE": (
        "Uppercase Letters in http.host",
        "AWS Network Firewall converts the HTTP Host header to lowercase before "
        "matching, so http.host content with uppercase letters can never match and "
        "is rejected.\n\n"
        "Current value: \"{value}\"\n"
        "Suggested:     \"{suggestion}\"\n\n"
        "Please change the http.host content to lowercase."),
    "MD5_BUFFER_NOT_HEX": (
        "Invalid JA3/JA3S Hash",
        "A JA3 or JA3S fingerprint is an MD5 hash written as 32 hexadecimal "
        "characters (0-9 and a-f). The value you entered is 32 characters long but "
        "contains other characters.\n\n"
        "Please provide a valid 32-character hexadecimal JA3/JA3S hash."),
    "MD5_BUFFER_NOCASE": (
        "Invalid Modifier",
        "The modifier 'nocase' cannot be used after '{keyword}'. A JA3/JA3S hash is "
        "matched as an exact hexadecimal string, and AWS Network Firewall rejects "
        "nocase on it.\n\n"
        "Please remove 'nocase' from this rule."),
    # Phase 2 (task 19)
    "CATEGORY_DUPLICATE_VALUE": (
        "Duplicate Category",
        "The {keyword} value lists '{value}' more than once. AWS Network Firewall "
        "rejects a rule that repeats a category.\n\n"
        "Please remove the extra '{value}'."),
    "CATEGORY_EMPTY": (
        "Missing Category",
        "The {keyword} keyword has no category value. AWS Network Firewall requires "
        "at least one category.\n\n"
        "Example: {keyword}:Malware\n\n"
        "Please add one or more categories, separated by commas."),
    "CATEGORY_KEYWORD_CONFLICT": (
        "Conflicting Category Keywords",
        "A rule may contain only one category keyword: a single aws_url_category or "
        "a single aws_domain_category, not both and not more than one of the same.\n\n"
        "To match several categories, list them in one keyword separated by commas, "
        "for example aws_url_category:Malware,Phishing.\n\n"
        "Please either:\n"
        "1. Combine the categories into a single keyword, or\n"
        "2. Split this into separate rules."),
    "R53_DOMAIN_EMPTY": (
        "Missing Domain",
        "The aws_route_53_resolved_domain value is empty. AWS Network Firewall "
        "requires at least one domain.\n\n"
        "Example: aws_route_53_resolved_domain:\"example.com\"\n\n"
        "Please add one or more domains inside the quotes, separated by commas."),
    "R53_DOMAIN_INVALID": (
        "Invalid Domain",
        "'{domain}' is not a valid domain for aws_route_53_resolved_domain.\n\n"
        "Each comma-separated domain must be a full domain name (for example "
        "example.com or api.example.com) or a leading-dot wildcard (for example "
        ".example.com). Labels may contain only letters, digits, and hyphens and "
        "cannot start with a hyphen. The last label must be 2-63 letters or digits. "
        "Empty entries, such as a trailing comma, are not allowed.\n\n"
        "Please correct or remove '{domain}'."),
    # Phase 2 (task 20)
    "RULE_TOO_LONG": (
        "AWS Network Firewall Quota Violation",
        "Rule length exceeds AWS Network Firewall limit!\n\n"
        "Total length (with variables expanded): {length} bytes\n"
        "AWS limit: 8,191 bytes (UTF-8)\n\n"
        "AWS measures the rule in UTF-8 bytes, with $ variables and @ references in "
        "the rule header expanded and the gid it adds included.\n\n"
        "Please reduce the rule length by:\n"
        "\u2022 Shortening the message text\n"
        "\u2022 Reducing content keywords\n"
        "\u2022 Simplifying variable definitions"),
    # Phase 2 (task 21, group). The aggregate dialog lists the terse line;
    # this is used only if a single-finding dialog is ever needed.
    "FLOWBITS_ISSET_NOT_SET": (
        "flowbit Checked but Never Set",
        "This rule checks the flowbit '{name}' with flowbits:{op}, but no active rule "
        "in this file sets it with flowbits:set or flowbits:toggle. AWS Network "
        "Firewall rejects a rule group with a flowbit that is checked but never set.\n\n"
        "Please either:\n"
        "1. Add a rule that sets '{name}', or\n"
        "2. Remove or correct the flowbits:{op},{name} check."),
}

# Editor-save "approaching the limit" warning for RULE_TOO_LONG's measurement
# (shown above RULE_WARN_BYTES). Not a finding code, so it lives outside the
# code tables. Params: length, remaining.
RULE_LENGTH_WARNING = (
    "Rule Length Warning",
    "Rule length is approaching AWS Network Firewall limit!\n\n"
    "Current length: {length} bytes\n"
    "AWS limit: 8,191 bytes (UTF-8)\n"
    "Remaining: {remaining} bytes\n\n"
    "Consider reducing rule complexity to stay within limits.")


def render_rule_length_warning(length, remaining):
    """Return ``(title, body)`` for the editor-save rule length warning."""
    title, body = RULE_LENGTH_WARNING
    return title, body.format(length=length, remaining=remaining)


def _params(finding):
    params = getattr(finding, 'params', None)
    return params if params else {}


def render_terse(finding):
    """Return the terse display string for ``finding``.

    Raises:
        KeyError: if the finding's code has no terse template.
    """
    template = TERSE_TEMPLATES[finding.code]
    if callable(template):
        return template(finding)
    return template.format(**_params(finding))


def render_verbose(finding):
    """Return ``(title, body)`` for the main editor's single-finding dialog.

    Raises:
        KeyError: if the finding's code has no verbose template.
    """
    template = VERBOSE_TEMPLATES[finding.code]
    if callable(template):
        return template(finding)
    title, body = template
    params = _params(finding)
    return title.format(**params), body.format(**params)
