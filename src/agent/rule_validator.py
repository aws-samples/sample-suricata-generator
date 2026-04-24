"""
Rule Validator for the Suricata Rule Generator AI Agent Layer.

Validates Suricata rule strings using SuricataRule.from_string() for parsing,
then checks action, protocol, keywords, and SID against known-good sets.
"""

import re
from src.agent.knowledge_base import KnowledgeBase
from src.agent.models import ValidationError, ValidationResult
from src.core.constants import SuricataConstants
from src.core.suricata_rule import SuricataRule

# Standard Suricata meta-keywords that are always valid (not in content_keywords.json)
_META_KEYWORDS = {
    "msg", "sid", "rev", "classtype", "priority", "metadata",
    "reference", "gid", "target", "noalert",
}

# Keywords that are definitively INVALID in Suricata rules — hard reject
_FORBIDDEN_KEYWORDS = {
    "http2.framelen": "http2.framelen is NOT a valid Suricata keyword. Suricata cannot inspect HTTP/2 frame lengths. Remove it.",
    "tls_cert_notbefore": "tls_cert_notbefore is NOT a valid rule keyword (EVE JSON only). Remove it.",
    "tls_cert_notafter": "tls_cert_notafter is NOT a valid rule keyword (EVE JSON only). Remove it.",
    "dns.answers.rrname": "dns.answers.rrname is NOT a valid Suricata rule keyword. Use dns.query instead.",
    "dns.rrtype": "dns.rrtype is NOT a valid Suricata rule keyword.",
}


class RuleValidator:
    """Validates Suricata rule strings against parsing, constants, and KB."""

    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base

    def validate(self, rule_str: str) -> ValidationResult:
        """Validate a single rule string. Returns structured ValidationResult."""
        errors: list[ValidationError] = []

        # 1. Parse
        parsed = SuricataRule.from_string(rule_str)
        if parsed is None:
            errors.append(ValidationError(
                type="parse_failure",
                message="Rule could not be parsed by SuricataRule.from_string()",
                location="full rule",
            ))
            return ValidationResult(valid=False, errors=errors)

        # 2. Action check
        if parsed.action not in SuricataConstants.SUPPORTED_ACTIONS:
            errors.append(ValidationError(
                type="invalid_action",
                message=f"Unsupported action '{parsed.action}'. Valid: {SuricataConstants.SUPPORTED_ACTIONS}",
                location="action field",
            ))

        # 3. Protocol check
        if parsed.protocol not in SuricataConstants.SUPPORTED_PROTOCOLS:
            errors.append(ValidationError(
                type="invalid_protocol",
                message=f"Unsupported protocol '{parsed.protocol}'. Valid: {SuricataConstants.SUPPORTED_PROTOCOLS}",
                location="protocol field",
            ))

        # 4. SID range check
        if not (SuricataConstants.SID_MIN <= parsed.sid <= SuricataConstants.SID_MAX):
            errors.append(ValidationError(
                type="sid_out_of_range",
                message=f"SID {parsed.sid} outside valid range {SuricataConstants.SID_MIN}-{SuricataConstants.SID_MAX}",
                location="sid field",
            ))

        # 5. Forbidden keyword check — known-invalid keywords are hard errors
        rule_keywords = self._extract_keywords(rule_str)
        for kw in rule_keywords:
            if kw in _FORBIDDEN_KEYWORDS:
                errors.append(ValidationError(
                    type="forbidden_keyword",
                    message=_FORBIDDEN_KEYWORDS[kw],
                    location=f"content keyword: {kw}",
                ))

        # 6. Keyword check against KB — unknown keywords are warnings, not errors
        #    The KB doesn't cover every valid Suricata keyword, so we don't fail on unknowns
        warnings: list[ValidationError] = []
        valid_keywords = self.kb.get_keyword_names() | _META_KEYWORDS
        for kw in rule_keywords:
            if kw not in valid_keywords and kw not in _FORBIDDEN_KEYWORDS:
                warnings.append(ValidationError(
                    type="unknown_keyword",
                    message=f"Keyword '{kw}' not in knowledge base (may still be valid Suricata keyword)",
                    location=f"content keyword: {kw}",
                ))

        # Unknown keywords don't block validation — only hard errors do
        all_issues = errors + warnings
        return ValidationResult(
            valid=len(errors) == 0,
            errors=all_issues,
            parsed_rule=parsed,
        )

    @staticmethod
    def _extract_keywords(rule_str: str) -> set[str]:
        """Extract keyword names from the options section of a rule string.

        Handles both colon-separated (geoip:dst,RU) and space-separated
        (geoip dst RU) keyword formats by taking the first token before
        any colon or space as the keyword name.
        """
        # Find options between ( ... )
        match = re.search(r'\((.+)\)\s*$', rule_str, re.DOTALL)
        if not match:
            return set()
        options = match.group(1)
        keywords = set()
        for part in options.split(';'):
            part = part.strip()
            if not part:
                continue
            # Extract keyword name: first token before ':' or ' '
            # This handles both "geoip:dst,RU" and "geoip dst RU" formats
            name = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if name:
                keywords.add(name)
        return keywords
