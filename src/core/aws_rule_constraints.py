"""AWS Network Firewall rule constraints shared across the app.

UI-free shared source of truth for the `reject` action protocol allowlist.
Used by the main editor's save checks (suricata_generator.py, which re-exports
these names) and the Rule Analyzer (src/analysis/rule_analyzer.py). Kept in its
own module so the analyzer can import it without importing the GUI module.
"""

# Protocols on which the Suricata `reject` action is valid. This set mirrors
# AWS Network Firewall's own reject allowlist: the service accepts `reject` only
# on these header protocols and rejects every other protocol as unsupported.
REJECT_CAPABLE_PROTOCOLS = frozenset({
    'tcp', 'http', 'tls', 'smb', 'dcerpc', 'ssh', 'smtp',
})

# The same allowlist in a fixed display order, for user-facing messages.
REJECT_CAPABLE_PROTOCOLS_DISPLAY = (
    'tcp', 'http', 'tls', 'smb', 'dcerpc', 'ssh', 'smtp',
)


def reject_allowlist_text():
    """Return the allowlist as English prose: 'tcp, http, ..., ssh, and smtp'."""
    names = list(REJECT_CAPABLE_PROTOCOLS_DISPLAY)
    return ', '.join(names[:-1]) + ', and ' + names[-1]


def is_reject_allowed(action, protocol):
    """Return True if the given action/protocol combination is allowed.

    Only the `reject` action is restricted: it is allowed only on the AWS
    Network Firewall reject allowlist (see REJECT_CAPABLE_PROTOCOLS). All other
    actions are always allowed. The comparison is case-insensitive, and an
    unknown/empty protocol is treated as NOT reject-capable (reject blocked) to
    be safe.
    """
    action = (action or '').strip().lower()
    protocol = (protocol or '').strip().lower()
    if action == 'reject':
        return protocol in REJECT_CAPABLE_PROTOCOLS
    return True
