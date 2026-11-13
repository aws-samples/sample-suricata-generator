"""
User feedback support for Help > Send Feedback (UI-free).

This module holds everything about sending feedback that does not need a
display, so it can be unit-tested headlessly:

- the table of feedback types (one per GitHub issue form in the public
  repository's ``.github/ISSUE_TEMPLATE/`` folder) and the feature-area list
  used by the dialog and listed in the forms' feature-area field;
- collection of non-identifying environment details (application and module
  versions, OS, Python, Tcl/Tk, optional package versions);
- building the GitHub "new issue" URL that opens a form with those details
  pre-filled.

Privacy rules (the repository is public):

- Never collect the computer's host name, the user name, file system paths,
  environment variables, AWS profile/account/region details, or any rule,
  policy or configuration content.
- The URL builder only accepts a feedback type from the fixed table, the
  environment text, and a feature area from the fixed list. It has no title,
  body or free-text parameter, so user content can't reach the URL.
- The application never contacts GitHub. The dialog only asks the operating
  system to open the URL in the user's browser.

The table here and the issue forms must stay in step (field ids, file names,
listed feature areas). tests/test_feedback_templates.py checks this.
GitHub pre-fills only text fields (input, textarea) from the URL, so every
pre-filled field must be one of those, never a dropdown.
"""

from __future__ import annotations

import getpass
import os
import platform
import re
import socket
from typing import List, NamedTuple, Optional, Tuple
from urllib.parse import quote, urlencode

from src.core import version as _version


REPOSITORY_URL = "https://github.com/aws-samples/sample-suricata-generator"
NEW_ISSUE_URL = REPOSITORY_URL + "/issues/new"

# Pre-fillable issue-form field ids shared by the forms. Every form that the
# app pre-fills must use exactly these ids.
FIELD_ENVIRONMENT = "environment"
FIELD_FEATURE_AREA = "feature-area"

# Conservative cap for the whole URL. GitHub and current browsers accept
# considerably more; this leaves headroom.
MAX_URL_LENGTH = 6000

UNKNOWN = "unknown"
NOT_INSTALLED = "not installed"
REDACTED = "[redacted]"
TRUNCATION_NOTE = ("(details truncated - use Copy to Clipboard in the app "
                   "for the full list)")

PRIVACY_NOTICE = (
    "This creates a public GitHub issue. Don't include IP addresses, domain "
    "names, AWS account IDs, credentials, or internal hostnames. Replace them "
    "with placeholders such as 10.0.0.1 or example.com."
)


class FeedbackType(NamedTuple):
    """One kind of report, mapped one-to-one to a GitHub issue form."""
    key: str                          # stable internal key
    display_name: str                 # dropdown entry; equals the form's name
    description: str                  # one-line help shown under the dropdown
    template_file: str                # file name in .github/ISSUE_TEMPLATE/
    prefill_fields: Tuple[str, ...]   # field ids the app may pre-fill
    has_feature_area: bool            # the form has the feature-area field
    is_conversion: bool               # a converter form (shows the snippet tip)


# To add a feedback type: add a row here AND add the matching form file in
# .github/ISSUE_TEMPLATE/. The template test fails if the two disagree.
FEEDBACK_TYPES: Tuple[FeedbackType, ...] = (
    FeedbackType("bug", "Bug report",
                 "Something doesn't work the way it should.",
                 "bug_report.yml",
                 (FIELD_ENVIRONMENT, FIELD_FEATURE_AREA), True, False),
    FeedbackType("squid_conversion", "Squid conversion issue",
                 "A Squid rule converted wrongly, or wasn't converted.",
                 "squid_conversion.yml",
                 (FIELD_ENVIRONMENT,), False, True),
    FeedbackType("palo_alto_conversion", "Palo Alto conversion issue",
                 "A Palo Alto rule converted wrongly, or wasn't converted.",
                 "palo_alto_conversion.yml",
                 (FIELD_ENVIRONMENT,), False, True),
    FeedbackType("feature_request", "Feature request",
                 "An idea for a new feature or an improvement.",
                 "feature_request.yml",
                 (FIELD_ENVIRONMENT, FIELD_FEATURE_AREA), True, False),
    FeedbackType("general", "Question or general feedback",
                 "Anything else: a question, a comment, or general feedback.",
                 "general_feedback.yml",
                 (FIELD_ENVIRONMENT,), False, False),
)

DEFAULT_FEEDBACK_TYPE_KEY = "bug"

# Feature areas offered by the dialog's dropdown, in display order. On GitHub
# the feature-area field is a single-line text input (GitHub pre-fills only
# text fields from the URL), and its description lists these same values for
# people filing directly. The two must match character for character (tested).
FEATURE_AREAS: Tuple[str, ...] = (
    "Rule editor (main window)",
    "Advanced Editor",
    "Rule Analyzer",
    "Flow Tester",
    "AI Rule Assistant",
    "AWS rule group import / export",
    "Rule Usage Analyzer",
    "Traffic Analysis & VPC Endpoints",
    "Container Associations",
    "Managed Rule Group Generator",
    "Squid Converter",
    "Palo Alto Importer",
    "Rule templates",          # adding new rules from a template
    "Change tracking / history",
    "Other / not sure",
)

DEFAULT_FEATURE_AREA = "Other / not sure"

# Application and module versions, in the order shown in Help > About.
_VERSION_ITEMS: Tuple[Tuple[str, str], ...] = (
    ("Suricata Rule Generator", "get_main_version"),
    ("Rule Analyzer", "get_analyzer_version"),
    ("Flow Tester", "get_flow_tester_version"),
    ("Palo Alto Importer", "get_palo_alto_importer_version"),
    ("Squid Converter", "get_squid_converter_version"),
    ("Managed Rule Group Generator", "get_mrg_version"),
)

# Optional third-party packages the application uses: (display name,
# distribution name). Read from package metadata, never imported.
_PACKAGES: Tuple[Tuple[str, str], ...] = (
    ("boto3", "boto3"),
    ("botocore", "botocore"),
    ("wxPython", "wxPython"),
    ("intervaltree", "intervaltree"),
    ("requests", "requests"),
    ("certifi", "certifi"),
    ("defusedxml", "defusedxml"),
)

VERSION_NAMES: Tuple[str, ...] = tuple(n for n, _ in _VERSION_ITEMS)
PACKAGE_NAMES: Tuple[str, ...] = tuple(n for n, _ in _PACKAGES)

# Scrub skips values shorter than this, so an ordinary short word is not
# redacted by accident.
_MIN_SCRUB_LENGTH = 3


# ---------------------------------------------------------------------------
# Feedback types
# ---------------------------------------------------------------------------

def get_feedback_type(key: str) -> FeedbackType:
    """Return the FeedbackType for ``key``. Raises KeyError if unknown."""
    for ft in FEEDBACK_TYPES:
        if ft.key == key:
            return ft
    raise KeyError(key)


# ---------------------------------------------------------------------------
# Environment information
# ---------------------------------------------------------------------------

class _NotInstalled(Exception):
    """The distribution is not installed."""


class _NoMetadata(Exception):
    """No package-metadata API is available."""


def _clean(value) -> str:
    text = "" if value is None else str(value).strip()
    return text if text else UNKNOWN


def _safe(fn) -> str:
    """Call ``fn`` and return its value as text, or UNKNOWN on any failure."""
    try:
        return _clean(fn())
    except Exception:
        return UNKNOWN


def _linux_pretty_name() -> str:
    """Distribution name from /etc/os-release (PRETTY_NAME), or ''."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8",
                  errors="replace") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    value = line.split("=", 1)[1].strip().strip('"').strip("'")
                    return value[:100]
    except Exception:
        pass
    return ""


def _os_description() -> str:
    system = platform.system()
    if system == "Darwin":
        mac = platform.mac_ver()[0]
        return ("macOS " + mac) if mac else "macOS"
    release = platform.release()
    ver = platform.version()
    desc = " ".join(p for p in (system, release) if p) or UNKNOWN
    if ver and ver != release:
        desc += " (" + ver + ")"
    if system == "Linux":
        pretty = _linux_pretty_name()
        if pretty:
            desc = pretty + "; " + desc
    return desc


def _python_description() -> str:
    return "%s (%s)" % (platform.python_version(),
                        platform.python_implementation())


def _metadata_version(dist: str) -> str:
    """Installed version of distribution ``dist`` from package metadata.

    Raises _NotInstalled when the distribution is missing and _NoMetadata
    when no metadata API exists. Never imports the package itself.
    """
    md = None
    try:
        import importlib.metadata as md  # Python 3.8+
    except ImportError:
        try:
            import importlib_metadata as md  # 3.7 backport, if installed
        except ImportError:
            md = None
    if md is not None:
        try:
            return md.version(dist)
        except md.PackageNotFoundError:
            raise _NotInstalled(dist)
    try:
        import pkg_resources  # last resort on 3.7
    except ImportError:
        raise _NoMetadata()
    try:
        return pkg_resources.get_distribution(dist).version
    except pkg_resources.DistributionNotFound:
        raise _NotInstalled(dist)


def _package_version(dist: str) -> str:
    try:
        return _clean(_metadata_version(dist))
    except _NotInstalled:
        return NOT_INSTALLED
    except Exception:
        return UNKNOWN


def collect_environment_info(tk_patchlevel: Optional[str] = None
                             ) -> List[Tuple[str, str]]:
    """Return the non-identifying environment details as (name, value) pairs.

    ``tk_patchlevel`` is the Tcl/Tk patch level (the dialog passes
    ``root.tk.call("info", "patchlevel")``); this module has no tkinter
    dependency. Every value is collected independently and falls back to
    "unknown"; this function never raises.
    """
    items: List[Tuple[str, str]] = []
    for name, getter in _VERSION_ITEMS:
        items.append((name, _safe(lambda g=getter: getattr(_version, g)())))
    items.append(("OS", _safe(_os_description)))
    items.append(("Architecture", _safe(platform.machine)))
    items.append(("Python", _safe(_python_description)))
    items.append(("Tcl/Tk", _clean(tk_patchlevel) if tk_patchlevel else UNKNOWN))
    for name, dist in _PACKAGES:
        items.append((name, _package_version(dist)))
    return items


def _sensitive_values() -> List[str]:
    """Host name, user name and home folder, for the scrub comparison only.

    These values are never emitted.
    """
    values: List[str] = []
    for fn in (socket.gethostname, platform.node, getpass.getuser,
               lambda: os.path.expanduser("~")):
        try:
            v = fn()
        except Exception:
            continue
        if not v:
            continue
        v = str(v).strip()
        if len(v) < _MIN_SCRUB_LENGTH or v == "~":
            continue
        values.append(v)
        # A host name may appear without its domain suffix.
        short = v.split(".", 1)[0]
        if short != v and len(short) >= _MIN_SCRUB_LENGTH:
            values.append(short)
        # The home folder may appear with either path separator.
        for alt in (v.replace("\\", "/"), v.replace("/", "\\")):
            if alt != v:
                values.append(alt)
    # Longest first, so a home path is replaced before the user name in it.
    return sorted(set(values), key=len, reverse=True)


def _scrub(text: str) -> str:
    for value in _sensitive_values():
        pattern = (r"(?<![A-Za-z0-9])" + re.escape(value)
                   + r"(?![A-Za-z0-9])")
        try:
            text = re.sub(pattern, REDACTED, text, flags=re.IGNORECASE)
        except Exception:
            continue
    return text


def format_environment_info(items: List[Tuple[str, str]]) -> str:
    """Format Environment_Info as ``name: value`` lines, then scrub it.

    Any occurrence of the host name, user name or home folder is replaced with
    "[redacted]" as a final safety net. Never raises.
    """
    try:
        text = "\n".join("%s: %s" % (name, value) for name, value in items)
    except Exception:
        return ""
    try:
        return _scrub(text)
    except Exception:
        return text


# ---------------------------------------------------------------------------
# Pre-fill URL
# ---------------------------------------------------------------------------

def _line_name(line: str) -> str:
    return line.split(":", 1)[0].strip()


def _encode(feedback_type: FeedbackType, environment_text: Optional[str],
            feature_area: Optional[str]) -> str:
    params = [("template", feedback_type.template_file)]
    if environment_text is not None and FIELD_ENVIRONMENT in feedback_type.prefill_fields:
        params.append((FIELD_ENVIRONMENT, environment_text))
    if feature_area is not None:
        params.append((FIELD_FEATURE_AREA, feature_area))
    return NEW_ISSUE_URL + "?" + urlencode(params, quote_via=quote)


def build_prefill_url(feedback_type: FeedbackType,
                      environment_text: str,
                      feature_area: Optional[str] = None) -> str:
    """Build the GitHub new-issue URL that opens ``feedback_type``'s form.

    Only the environment text and an optional feature area (one of
    FEATURE_AREAS, and only for types with the feature-area field) are
    pre-filled.
    If the URL would exceed MAX_URL_LENGTH, the environment text is
    shortened (package lines first, then everything but the version lines)
    and a truncation note is added.
    """
    if feedback_type not in FEEDBACK_TYPES:
        raise ValueError("unknown feedback type: %r" % (feedback_type,))
    if feature_area is not None:
        if not feedback_type.has_feature_area:
            raise ValueError("feedback type %r has no feature area"
                             % feedback_type.key)
        if feature_area not in FEATURE_AREAS:
            raise ValueError("unknown feature area: %r" % feature_area)

    text = environment_text or ""
    url = _encode(feedback_type, text, feature_area)
    if len(url) <= MAX_URL_LENGTH:
        return url

    lines = text.splitlines()
    candidates = (
        [ln for ln in lines if _line_name(ln) not in PACKAGE_NAMES],
        [ln for ln in lines if _line_name(ln) in VERSION_NAMES],
        [],
    )
    for keep in candidates:
        url = _encode(feedback_type, "\n".join(keep + [TRUNCATION_NOTE]),
                      feature_area)
        if len(url) <= MAX_URL_LENGTH:
            return url
    # Not reachable with the fixed table, but never exceed the cap.
    return _encode(feedback_type, None, feature_area)
