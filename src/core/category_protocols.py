"""Header protocols on which the AWS category keywords are valid.

UI-free shared source of truth for the AWS Network Firewall category keyword
protocol rules. Used by the main editor's save checks (suricata_generator.py)
and the Insert Category button/picker (src/gui/ui_manager.py). Kept in its own
module so ui_manager.py can import it without a circular import through
suricata_generator.py.
"""

# Header protocols on which AWS Network Firewall accepts the AWS category
# keywords (mirrors the service's own validator). 'http1' is not in the app's
# protocol dropdown but is accepted by the service, so it is allowed here too.
AWS_CATEGORY_ALLOWED_PROTOCOLS = {
    'aws_url_category': frozenset({'http', 'http1', 'http2'}),
    'aws_domain_category': frozenset({'http', 'http1', 'http2', 'tls'}),
}

# Display order of the category keywords in the Insert Category picker
# (the first entry is the default selection).
_CATEGORY_KEYWORD_DISPLAY_ORDER = ('aws_url_category', 'aws_domain_category')


def is_category_protocol_allowed(keyword, protocol):
    """Return True if the AWS category `keyword` is allowed on `protocol`.

    `keyword` is 'aws_url_category' or 'aws_domain_category' (see
    AWS_CATEGORY_ALLOWED_PROTOCOLS). The comparison is case-insensitive. An
    unrecognized keyword is not restricted (returns True).
    """
    allowed = AWS_CATEGORY_ALLOWED_PROTOCOLS.get((keyword or '').strip().lower())
    if allowed is None:
        return True
    return (protocol or '').strip().lower() in allowed


def category_keyword_options(protocol):
    """Return the category keywords valid on `protocol`, in display order.

    ['aws_url_category', 'aws_domain_category'] for http/http1/http2,
    ['aws_domain_category'] for tls, and [] for any other (or empty/None)
    protocol. The comparison is case-insensitive.
    """
    protocol = (protocol or '').strip().lower()
    return [kw for kw in _CATEGORY_KEYWORD_DISPLAY_ORDER
            if protocol in AWS_CATEGORY_ALLOWED_PROTOCOLS[kw]]
