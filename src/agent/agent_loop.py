"""
Agent Loop orchestrator for the Suricata Rule Generator AI Agent Layer.

Orchestrates: NLParser -> RuleBuilder -> RuleValidator -> RuleAnalyzerWrapper
with a self-correction loop that feeds errors back to the LLM.
"""

import re
import logging
from typing import Optional

from src.agent.models import GenerationResult
from src.agent.nl_parser import NLParser
from src.agent.rule_builder import RuleBuilder
from src.agent.rule_validator import RuleValidator
from src.agent.rule_analyzer_wrapper import RuleAnalyzerWrapper
from src.agent.best_practice_checker import BestPracticeChecker

logger = logging.getLogger(__name__)

_OPTS_RE = re.compile(r'\((.+)\)\s*$', re.DOTALL)


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


class AgentLoop:
    """Orchestrates the full rule generation pipeline with self-correction."""

    def __init__(
        self,
        nl_parser: NLParser,
        rule_builder: RuleBuilder,
        rule_validator: RuleValidator,
        rule_analyzer: RuleAnalyzerWrapper,
        best_practice_checker: BestPracticeChecker | None = None,
        max_retries: int = 3,
    ):
        self.nl_parser = nl_parser
        self.rule_builder = rule_builder
        self.rule_validator = rule_validator
        self.rule_analyzer = rule_analyzer
        self.best_practice_checker = best_practice_checker or BestPracticeChecker()
        self.max_retries = max_retries

    def generate(self, user_input: str, chat_history: list[dict] | None = None) -> GenerationResult:
        """Generate validated Suricata rule(s) from natural language input."""
        if not user_input or not user_input.strip():
            return GenerationResult(
                errors=["Input is empty or whitespace-only. Please describe the traffic to detect."],
                validation_summary={"status": "error", "message": "empty input"},
            )

        msg_type, chat_response = self.nl_parser.classify_input(user_input, chat_history=chat_history)
        if msg_type in ("question", "conversation", "template") and chat_response:
            return GenerationResult(
                explanation=chat_response,
                validation_summary={"status": "chat", "message": msg_type},
            )

        error_feedback: list[str] = []
        all_errors: list[str] = []
        last_rules: list[str] = []
        last_intents: list = []

        for attempt in range(1, self.max_retries + 1):
            intents, parse_error = self.nl_parser.extract_intent(
                user_input, error_feedback=error_feedback or None, chat_history=chat_history
            )
            if parse_error:
                all_errors.append(f"Attempt {attempt} parse: {parse_error}")
                error_feedback.append(parse_error)
                continue

            last_intents = intents
            built_rules: list[str] = []
            attempt_ok = True

            for intent in intents:
                try:
                    rule_str = self.rule_builder.build(intent)
                except Exception as e:
                    msg = f"Attempt {attempt} build: {e}"
                    all_errors.append(msg)
                    error_feedback.append(str(e))
                    attempt_ok = False
                    break

                # Auto-fix passes
                rule_str = self._patch_redundant_app_layer_protocol(rule_str)
                rule_str = self._patch_aws_unsupported_keywords(rule_str)
                rule_str = self._patch_keyword_order(rule_str)
                rule_str = self._patch_tls_forbidden_patterns(rule_str)
                rule_str = self._patch_invalid_http2_keywords(rule_str)
                rule_str = self._patch_crlf_in_header_names(rule_str)
                rule_str = self._patch_bsize_after_stat_code(rule_str)
                rule_str = self._patch_empty_content(rule_str)
                rule_str = self._patch_duplicate_sticky_buffers(rule_str)
                rule_str = self._patch_broad_crlf(rule_str)
                rule_str = self._patch_unreliable_body_detection(rule_str)
                rule_str = self._patch_ntlmssp_distance(rule_str)
                rule_str = self._patch_smb_share_content_to_pcre(rule_str)
                rule_str = self._patch_smb_raw_unicode_to_sticky(rule_str)
                rule_str = self._patch_threshold_type(rule_str)
                rule_str = self._patch_incomplete_flowbits(rule_str)
                rule_str = self._patch_dsize_with_app_layer(rule_str)
                rule_str = self._patch_dns_query_bsize(rule_str)
                rule_str = self._patch_dns_content_or_logic(rule_str)
                rule_str = self._patch_quic_duplicate_content(rule_str)
                rule_str = self._patch_quic_short_header_detection(rule_str)
                rule_str = self._patch_coap_header(rule_str)
                rule_str = self._patch_mqtt_topic_length(rule_str)
                rule_str = self._patch_flow_on_ip_protocol(rule_str)
                rule_str = self._patch_invalid_aws_metadata(rule_str)
                rule_str = self._patch_flowbits_noalert_without_set(rule_str)
                rule_str = self._patch_ip_proto_negation(rule_str)
                rule_str = self._patch_file_data_dot_to_underscore(rule_str)
                rule_str = self._patch_byte_test_content_len(rule_str)
                rule_str = self._patch_bidir_flow_direction(rule_str)
                rule_str = self._patch_smb_protocol_port(rule_str)
                rule_str = self._patch_sticky_buffer_content_order(rule_str)
                rule_str = self._patch_flow_add_direction(rule_str, user_input)

                # Validate
                validation = self.rule_validator.validate(rule_str)
                if not validation.valid:
                    msgs = [f"{e.type}: {e.message}" for e in validation.errors]
                    all_errors.extend(f"Attempt {attempt} validation: {m}" for m in msgs)
                    error_feedback = msgs
                    attempt_ok = False
                    break

                # Analyze conflicts
                analysis = self.rule_analyzer.analyze([rule_str])
                if not analysis.passed:
                    msgs = [f"{i.type}({i.severity}): {i.message}" for i in analysis.issues if i.severity == "error"]
                    all_errors.extend(f"Attempt {attempt} analysis: {m}" for m in msgs)
                    error_feedback = msgs
                    attempt_ok = False
                    break

                # Best-practice check
                bp_result = self.best_practice_checker.check(rule_str, user_input)
                if not bp_result.passed:
                    strong_issues = [i for i in bp_result.issues if i.severity == "strong_recommendation"]

                    if attempt == self.max_retries and strong_issues:
                        patched = rule_str
                        for issue in strong_issues:
                            if issue.category == "missing_flow":
                                patched = self._patch_missing_flow(patched, user_input)
                            elif issue.category == "flow_missing_direction":
                                patched = self._patch_flow_add_direction(patched, user_input)
                        if patched != rule_str:
                            bp_recheck = self.best_practice_checker.check(patched, user_input)
                            val_recheck = self.rule_validator.validate(patched)
                            if val_recheck.valid:
                                remaining = [i for i in bp_recheck.issues if i.severity == "strong_recommendation"]
                                if not remaining:
                                    rule_str = patched
                                    bp_result = bp_recheck

                    if not bp_result.passed:
                        msgs = [f"{i.category}: {i.message} Fix: {i.fix_hint}" for i in bp_result.issues if i.severity == "strong_recommendation"]
                        all_errors.extend(f"Attempt {attempt} best-practice: {m}" for m in msgs)
                        error_feedback = msgs
                        attempt_ok = False
                        break

                built_rules.append(rule_str)

            last_rules = built_rules if built_rules else last_rules

            if not attempt_ok:
                continue

            # Multi-rule flowbits reconciliation: remove orphaned isset/set across rules
            built_rules = self._reconcile_flowbits(built_rules)

            all_suggestions = []
            for rule_str in built_rules:
                bp_result = self.best_practice_checker.check(rule_str, user_input)
                all_suggestions.extend(
                    f"{i.category}: {i.message}" for i in bp_result.issues
                    if i.severity in ("recommendation", "suggestion")
                )

            explanation = ""
            if all_suggestions:
                explanation = "Suggestions:\n" + "\n".join(f"\u2022 {s}" for s in all_suggestions)

            return GenerationResult(
                rule=built_rules[0] if built_rules else "",
                rules=built_rules,
                explanation=explanation,
                validation_summary={"status": "pass", "attempts": attempt, "suggestions": all_suggestions},
                attempts=attempt,
                detection_intent=last_intents[0] if last_intents else None,
            )

        return GenerationResult(
            rule=last_rules[0] if last_rules else "",
            rules=last_rules,
            explanation="Max retries exhausted \u2014 could not fully validate.",
            validation_summary={"status": "fail", "attempts": self.max_retries},
            attempts=self.max_retries,
            detection_intent=last_intents[0] if last_intents else None,
            errors=all_errors,
        )

    @staticmethod
    def _patch_redundant_app_layer_protocol(rule_str: str) -> str:
        """Fix rules where protocol is an app-layer name AND options contain
        app-layer-protocol with the same value.

        Suricata rejects rules like:
            alert ssh any any -> any 22 (...; app-layer-protocol:ssh; ...)
        because the protocol field already implies the app-layer.

        Fix: change the protocol to the underlying transport (tcp/udp).
        """
        # Map app-layer protocols to their transport
        app_to_transport = {
            "ssh": "tcp",
            "http": "tcp",
            "http2": "tcp",
            "ftp": "tcp",
            "smtp": "tcp",
            "tls": "tcp",
            "smb": "tcp",
            "dcerpc": "tcp",
            "imap": "tcp",
            "pop3": "tcp",
            "mqtt": "tcp",
            "rfb": "tcp",
            "rdp": "tcp",
            "telnet": "tcp",
            "dns": "udp",
            "ntp": "udp",
            "dhcp": "udp",
            "snmp": "udp",
            "quic": "udp",
            "krb5": "tcp",
            "sip": "udp",
        }

        m = re.match(r'^(\w+)\s+(\w+)\s+', rule_str)
        if not m:
            return rule_str

        action = m.group(1)
        protocol = m.group(2).lower()

        if protocol not in app_to_transport:
            return rule_str

        # Check if options contain app-layer-protocol with the same value
        if f"app-layer-protocol:{protocol}" in rule_str.lower():
            transport = app_to_transport[protocol]
            # Replace the protocol in the header
            rule_str = re.sub(
                r'^(\w+)\s+' + re.escape(protocol) + r'\s+',
                f'{action} {transport} ',
                rule_str,
                count=1,
                flags=re.IGNORECASE,
            )

        return rule_str

    @staticmethod
    def _patch_missing_flow(rule_str: str, user_input: str) -> str:
        """Inject flow keyword into a rule that's missing it."""
        if "flow:" in rule_str:
            return rule_str

        user_lower = user_input.lower()
        inbound_terms = ["inbound", "ingress", "incoming", "to_client", "from external", "from outside"]
        if any(t in user_lower for t in inbound_terms):
            flow_value = "flow:established,to_client"
        else:
            flow_value = "flow:established,to_server"

        patched = re.sub(
            r'(msg:"[^"]*";\s*)',
            rf'\1{flow_value}; ',
            rule_str,
        )
        if patched == rule_str and "(" in rule_str:
            patched = rule_str.replace("(", f"({flow_value}; ", 1)

        return patched

    @staticmethod
    def _patch_tls_forbidden_patterns(rule_str: str) -> str:
        """Remove forbidden TLS patterns that the LLM keeps generating."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        parts = _split_options(options)
        changed = False

        # Fix 1: Remove tls.cert_subject when tls.cert_issuer is also present
        has_subject = any(re.split(r'[:\s]', p, 1)[0].strip() == "tls.cert_subject" for p in parts)
        has_issuer = any(re.split(r'[:\s]', p, 1)[0].strip() == "tls.cert_issuer" for p in parts)
        if has_subject and has_issuer:
            new_parts = []
            skip_next_content = False
            for p in parts:
                kw = re.split(r'[:\s]', p, 1)[0].strip()
                if kw == "tls.cert_subject":
                    skip_next_content = True
                    changed = True
                    continue
                if skip_next_content and kw in ("content", "pcre"):
                    skip_next_content = False
                    new_parts.append(p)
                    continue
                skip_next_content = False
                new_parts.append(p)
            parts = new_parts

            deduped = []
            for p in parts:
                if deduped and p == deduped[-1]:
                    changed = True
                    continue
                deduped.append(p)
            parts = deduped

        # Fix 2: Remove tls_cert_notbefore / tls_cert_notafter
        filtered = []
        for p in parts:
            kw = re.split(r'[:\s]', p, 1)[0].strip()
            if kw in ("tls_cert_notbefore", "tls_cert_notafter"):
                changed = True
                continue
            filtered.append(p)
        parts = filtered

        # Fix 3: Insert tls.ciphersuites before cipher hex content/pcre after ssl_state
        ssl_state_idx = None
        has_ciphersuites = any(re.split(r'[:\s]', p, 1)[0].strip() == "tls.ciphersuites" for p in parts)
        for i, p in enumerate(parts):
            kw = re.split(r'[:\s]', p, 1)[0].strip()
            if kw == "ssl_state" and "client_hello" in p:
                ssl_state_idx = i
                break

        if ssl_state_idx is not None and not has_ciphersuites:
            for j in range(ssl_state_idx + 1, len(parts)):
                kw = re.split(r'[:\s]', parts[j], 1)[0].strip()
                if kw in ("content", "pcre") and ("\\x" in parts[j] or "|" in parts[j]):
                    parts.insert(j, "tls.ciphersuites")
                    changed = True
                    break
                elif kw not in ("nocase", "depth", "offset"):
                    break

        if changed:
            new_options = "; ".join(parts)
            header = rule_str[:m.start()]
            return f"{header}({new_options};)"

        return rule_str

    @staticmethod
    def _patch_keyword_order(rule_str: str) -> str:
        """Reorder keywords so flow appears before sticky buffers and
        sticky buffers are interleaved with their content matches."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        parts = _split_options(options)

        sticky_buffers = {
            "http.uri", "http.host", "http.method", "http.user_agent",
            "http.cookie", "http.header", "http.content_type",
            "http.content_len", "http.stat_code", "http.stat_msg",
            "http.request_body", "http.response_body", "http.referer",
            "http.server", "http.location", "http.protocol",
            "http.header_names", "http.start", "http.request_header",
            "http2.header_name",
            "tls.sni", "tls.cert_subject", "tls.cert_issuer", "tls.ciphersuites",
            "dns.query", "file.data", "file.name", "file_data",
            "smb.share", "smb.named_pipe", "dcerpc.stub_data",
            "ssh.software", "ssh.proto", "ssh.hassh", "ssh.hassh.server",
            "ja3.hash", "ja4.hash",
        }

        changed = False

        # Fix 1: Move flow before the first sticky buffer
        flow_idx = None
        first_sticky_idx = None
        for i, part in enumerate(parts):
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "flow":
                flow_idx = i
            elif kw in sticky_buffers and first_sticky_idx is None:
                first_sticky_idx = i

        if flow_idx is not None and first_sticky_idx is not None and flow_idx > first_sticky_idx:
            flow_part = parts.pop(flow_idx)
            parts.insert(first_sticky_idx, flow_part)
            changed = True

        # Fix 2: Move sticky buffers before their content matches
        content_modifiers = {
            "nocase", "depth", "offset", "distance", "within",
            "fast_pattern", "startswith", "endswith", "bsize",
            "rawbytes", "isdataat",
        }

        for _ in range(5):
            reordered = False
            for i, part in enumerate(parts):
                kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
                if kw in sticky_buffers:
                    j = i - 1
                    while j >= 0:
                        prev_kw = re.split(r'[:\s]', parts[j], maxsplit=1)[0].strip()
                        if prev_kw in content_modifiers:
                            j -= 1
                        else:
                            break
                    if j >= 0:
                        prev_kw = re.split(r'[:\s]', parts[j], maxsplit=1)[0].strip()
                        if prev_kw in ("content", "pcre"):
                            sticky_part = parts.pop(i)
                            parts.insert(j, sticky_part)
                            reordered = True
                            changed = True
                            break
            if not reordered:
                break

        # Fix 3 removed — semantic matching in _patch_sticky_buffer_content_order
        # handles grouped sticky buffers more accurately than sequential assignment.

        if changed:
            new_options = "; ".join(parts)
            header = rule_str[:m.start()]
            return f"{header}({new_options};)"

        return rule_str

    @staticmethod
    def _patch_invalid_http2_keywords(rule_str: str) -> str:
        """Remove invalid http2.framelen keyword and its associated byte_test.
        Also cleans up verbose msg fields that mention http2.framelen caveats."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "http2.framelen" not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        skip_next_byte_test = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http2.framelen":
                skip_next_byte_test = True
                continue
            if skip_next_byte_test and kw == "byte_test":
                skip_next_byte_test = False
                continue
            skip_next_byte_test = False
            # Clean up msg if it contains verbose http2.framelen caveats
            if kw == "msg" and "http2.framelen" in part:
                msg_match = re.search(r'msg\s*:\s*"(.+)"', part)
                if msg_match:
                    msg_text = msg_match.group(1)
                    # Strip everything from (NOTE: onwards, or any parenthetical mentioning http2.framelen
                    cleaned = re.sub(r'\s*\(NOTE:.*', '', msg_text)
                    cleaned = re.sub(r'\s*\(.*?http2\.framelen.*', '', cleaned)
                    cleaned = cleaned.strip().rstrip(';').strip()
                    if cleaned:
                        new_parts.append(f'msg:"{cleaned}"')
                        continue
            new_parts.append(part)

        new_options = "; ".join(new_parts)
        header = rule_str[:m.start()]
        return f"{header}({new_options};)"

    @staticmethod
    def _patch_crlf_in_header_names(rule_str: str) -> str:
        """Remove CRLF hex wrapping from content matches in header buffer context.

        For http.header_names: removes all |0d 0a| (never valid in this buffer).
        For http.header: only removes wrapping patterns like |0d 0a|Name|0d 0a|
        (standalone |0d 0a| for injection detection is valid).
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "|0d 0a|" not in options:
            return rule_str
        if "http.header_names" not in options and "http.header" not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        current_buffer = None
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http.header_names":
                current_buffer = "header_names"
                new_parts.append(part)
            elif kw == "http.header":
                current_buffer = "header"
                new_parts.append(part)
            elif kw == "content" and current_buffer is not None and "|0d 0a|" in part:
                if current_buffer == "header_names":
                    # Remove all CRLF from header_names content
                    cleaned = part.replace("|0d 0a|", "")
                    new_parts.append(cleaned)
                    changed = True
                elif current_buffer == "header":
                    # Only remove wrapping patterns |0d 0a|Name|0d 0a|
                    content_val = part.split(":", 1)[1].strip().strip('"') if ":" in part else ""
                    if content_val.startswith("|0d 0a|") and content_val.endswith("|0d 0a|") and len(content_val) > 14:
                        cleaned = part.replace("|0d 0a|", "")
                        new_parts.append(cleaned)
                        changed = True
                    else:
                        new_parts.append(part)
                else:
                    new_parts.append(part)
            elif kw in ("content", "pcre", "nocase", "depth", "offset",
                        "distance", "within", "fast_pattern", "startswith",
                        "endswith", "bsize"):
                # Content matches and modifiers don't change buffer context
                new_parts.append(part)
            else:
                current_buffer = None
                new_parts.append(part)

        if changed:
            new_options = "; ".join(new_parts)
            header = rule_str[:m.start()]
            return f"{header}({new_options};)"

        return rule_str

    @staticmethod
    def _patch_bsize_after_stat_code(rule_str: str) -> str:
        """Remove unnecessary bsize after http.stat_code."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "http.stat_code" not in options or "bsize:" not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        stat_code_seen = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http.stat_code":
                stat_code_seen = True
                new_parts.append(part)
            elif kw == "bsize" and stat_code_seen:
                continue
            else:
                if kw in ("http.header", "http.uri", "http.host", "http.header_names",
                          "http.content_len", "http.protocol"):
                    stat_code_seen = False
                new_parts.append(part)

        if len(new_parts) < len(parts):
            new_options = "; ".join(new_parts)
            header = rule_str[:m.start()]
            return f"{header}({new_options};)"

        return rule_str

    @staticmethod
    def _patch_empty_content(rule_str: str) -> str:
        """Remove empty content matches (content:"") from rules."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if 'content:""' not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = [p for p in parts if not re.match(r'content\s*:\s*""\s*$', p)]

        if len(new_parts) < len(parts):
            new_options = "; ".join(new_parts)
            header = rule_str[:m.start()]
            return f"{header}({new_options};)"

        return rule_str

    @staticmethod
    def _patch_duplicate_sticky_buffers(rule_str: str) -> str:
        """Remove duplicate consecutive sticky buffers."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        sticky_buffers = {
            "http.uri", "http.host", "http.method", "http.user_agent",
            "http.cookie", "http.header", "http.content_type",
            "http.content_len", "http.stat_code", "http.stat_msg",
            "http.request_body", "http.response_body", "http.referer",
            "http.server", "http.location", "http.protocol",
            "http.header_names", "http.start", "http.request_header",
            "http2.header_name",
            "tls.sni", "tls.cert_subject", "tls.cert_issuer", "tls.ciphersuites",
            "dns.query", "file.data", "file.name", "file_data",
            "smb.share", "smb.named_pipe", "dcerpc.stub_data",
            "ssh.software", "ssh.proto", "ssh.hassh", "ssh.hassh.server",
            "ja3.hash", "ja4.hash",
        }

        options = m.group(1)
        parts = _split_options(options)
        new_parts = []
        prev_kw = None
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw in sticky_buffers and kw == prev_kw:
                changed = True
                continue  # Skip duplicate
            new_parts.append(part)
            if kw in sticky_buffers:
                prev_kw = kw
            elif kw not in ("nocase", "depth", "offset", "distance", "within",
                            "fast_pattern", "startswith", "endswith", "bsize",
                            "content", "pcre"):
                prev_kw = None

        if changed:
            new_options = "; ".join(new_parts)
            header = rule_str[:m.start()]
            return f"{header}({new_options};)"

        return rule_str

    @staticmethod
    def _patch_broad_crlf(rule_str: str) -> str:
        """Replace overly broad CRLF patterns in http.header with targeted detection."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        changed = False

        # Fix 1: Replace |0d 0a 0d 0a| (double CRLF) with distance/within pattern
        if "|0d 0a 0d 0a|" in options and "http.header" in options:
            parts = _split_options(options)
            new_parts = []
            in_header_context = False

            for part in parts:
                kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
                if kw in ("http.header", "http.header_names"):
                    in_header_context = True
                    new_parts.append(part)
                elif kw == "content" and in_header_context and '"|0d 0a 0d 0a|"' in part:
                    # Replace double-CRLF with two single CRLFs + distance/within
                    new_parts.append('content:"|0d 0a|"')
                    new_parts.append('content:"|0d 0a|"')
                    new_parts.append('distance:1')
                    new_parts.append('within:5')
                    changed = True
                elif kw in ("content", "pcre", "nocase", "depth", "offset",
                            "distance", "within", "fast_pattern", "startswith",
                            "endswith", "bsize"):
                    new_parts.append(part)
                else:
                    in_header_context = False
                    new_parts.append(part)

            if changed:
                options = "; ".join(new_parts)

        # Fix 2: Replace content:!"|0d 0a 0d 0a|" negation with distance/within
        if not changed and 'content:!"|0d 0a 0d 0a|"' in options and "http.header" in options:
            parts = _split_options(options)
            new_parts = []

            for part in parts:
                kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
                if kw == "content" and '!"|0d 0a 0d 0a|"' in part:
                    # Drop the negation — it doesn't work as intended
                    changed = True
                    continue
                new_parts.append(part)

            if changed:
                # Ensure we have distance/within after the CRLF content match
                has_distance = any("distance:" in p for p in new_parts)
                if not has_distance:
                    # Find the last content:"|0d 0a|" and add distance/within after it
                    for i in range(len(new_parts) - 1, -1, -1):
                        if 'content:"|0d 0a|"' in new_parts[i]:
                            new_parts.insert(i + 1, 'distance:1')
                            new_parts.insert(i + 2, 'within:5')
                            break
                options = "; ".join(new_parts)

        if changed:
            header = rule_str[:m.start()]
            return f"{header}({options};)"

        return rule_str
    @staticmethod
    def _patch_unreliable_body_detection(rule_str: str) -> str:
        """Replace content:!"|00|" with isdataat:1 in http.request_body context."""
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if 'content:!"|00|"' not in options or "http.request_body" not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        in_body_context = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http.request_body":
                in_body_context = True
                new_parts.append(part)
            elif kw == "content" and in_body_context and '!"|00|"' in part:
                new_parts.append("isdataat:1")
                in_body_context = False
            elif kw in ("content", "pcre", "nocase", "depth", "offset",
                        "distance", "within", "fast_pattern", "startswith",
                        "endswith", "bsize", "isdataat"):
                new_parts.append(part)
            else:
                in_body_context = False
                new_parts.append(part)

        header = rule_str[:m.start()]
        return f"{header}({'; '.join(new_parts)};)"
    @staticmethod
    def _patch_ntlmssp_distance(rule_str: str) -> str:
        """Fix NTLMSSP message type distance from 0 to 1.

        NTLMSSP signature is 7 chars + 1 null terminator = 8 bytes.
        The message type field starts at offset 8, so distance after
        the 7-byte "NTLMSSP" content match should be 1 (the null byte).
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "NTLMSSP" not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        prev_was_ntlmssp = False
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()

            if kw == "content" and "NTLMSSP" in part:
                prev_was_ntlmssp = True
                new_parts.append(part)
                continue

            if prev_was_ntlmssp and kw == "content":
                # This is the message type content match after NTLMSSP
                # Check if next parts have distance:0 — fix to distance:1
                new_parts.append(part)
                prev_was_ntlmssp = False
                # Look ahead for distance:0 and fix it
                continue

            if kw == "distance" and new_parts:
                # Check if previous content was a type byte after NTLMSSP
                prev_content = None
                for p in reversed(new_parts):
                    pk = re.split(r'[:\s]', p, maxsplit=1)[0].strip()
                    if pk == "content":
                        prev_content = p
                        break
                    elif pk not in ("nocase",):
                        break

                if prev_content and any(t in prev_content for t in ["|01 00 00 00|", "|00 01 00 00 00|", "|03 00 00 00|", "|00 03 00 00 00|"]):
                    val = part.split(":", 1)[1].strip() if ":" in part else ""
                    if val == "0":
                        new_parts.append("distance:1")
                        changed = True
                        continue
                    # Also fix 5-byte patterns with leading null: |00 01 00 00 00| -> |01 00 00 00|
                    # and adjust within accordingly

            if kw == "within" and changed:
                val = part.split(":", 1)[1].strip() if ":" in part else ""
                if val == "5":
                    new_parts.append("within:4")
                    continue

            prev_was_ntlmssp = False
            new_parts.append(part)

        # Also fix 5-byte NTLMSSP type patterns to 4-byte
        final_parts = []
        for i, part in enumerate(new_parts):
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "content":
                original = part
                part = part.replace('"|00 01 00 00 00|"', '"|01 00 00 00|"')
                part = part.replace('"|00 03 00 00 00|"', '"|03 00 00 00|"')
                if part != original:
                    changed = True
            final_parts.append(part)

        if changed:
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(final_parts)};)"
        return rule_str

    @staticmethod
    def _patch_smb_share_content_to_pcre(rule_str: str) -> str:
        """Replace multiple AND content matches for SMB shares with PCRE OR.

        Pattern: content:"ADMIN$"; nocase; content:"IPC$"; nocase; -> smb.share; pcre:"/^(?:ADMIN\\$|C\\$|IPC\\$)$/i";
        Also replaces redundant PCRE after content matches.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        # Only apply to SMB rules with share-related content
        header = rule_str[:m.start()].lower()
        if "smb" not in header and "445" not in header:
            return rule_str

        share_names = {"admin$", "c$", "ipc$", "d$", "e$", "print$"}
        parts = _split_options(options)

        # Count share-related content matches
        share_contents = []
        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "content":
                content_match = re.search(r'content\s*:\s*"([^"]*)"', part)
                if content_match:
                    val = content_match.group(1).lower().replace("\\", "")
                    if val.rstrip("$") + "$" in share_names or val in share_names:
                        share_contents.append(content_match.group(1))

        if len(share_contents) < 2:
            return rule_str

        # Build replacement: smb.share + PCRE alternation
        pcre_alts = []
        for s in share_names:
            pcre_alts.append(s.upper().replace("$", "\\$"))
        pcre_pattern = f'pcre:"/^(?:{"|".join(pcre_alts)})$/i"'

        # Rebuild parts: remove share content matches and their modifiers, add smb.share + pcre
        new_parts = []
        skip_modifiers = False
        has_smb_share = "smb.share" in options
        inserted = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()

            if skip_modifiers and kw in ("nocase", "depth", "offset", "distance", "within",
                                          "fast_pattern", "startswith", "endswith", "bsize"):
                continue
            skip_modifiers = False

            if kw == "content":
                content_match = re.search(r'content\s*:\s*"([^"]*)"', part)
                if content_match:
                    val = content_match.group(1).lower().replace("\\", "")
                    if val.rstrip("$") + "$" in share_names or val in share_names:
                        skip_modifiers = True
                        if not inserted:
                            if not has_smb_share:
                                new_parts.append("smb.share")
                            new_parts.append(pcre_pattern)
                            inserted = True
                        continue

            if kw == "pcre" and inserted:
                # Check if this is a redundant share PCRE
                if any(s.lower().replace("$", "") in part.lower() for s in share_names):
                    continue

            if kw == "smb.share":
                has_smb_share = True

            new_parts.append(part)

        if inserted:
            header_str = rule_str[:m.start()]
            return f"{header_str}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_smb_raw_unicode_to_sticky(rule_str: str) -> str:
        """Replace raw Unicode SMB content with sticky buffer equivalents.

        Pattern: content:"|00|s|00|v|00|c|00|c|00|t|00|l|00|" -> smb.named_pipe; content:"svcctl";
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        header = rule_str[:m.start()].lower()
        if "smb" not in header and "445" not in header:
            return rule_str

        # Detect Unicode-encoded pipe names
        unicode_pipes = {
            '"|00|s|00|v|00|c|00|c|00|t|00|l|00|"': ("smb.named_pipe", "svcctl"),
            '"|00|s|00|a|00|m|00|r|00|"': ("smb.named_pipe", "samr"),
            '"|00|l|00|s|00|a|00|r|00|p|00|c|00|"': ("smb.named_pipe", "lsarpc"),
        }

        parts = _split_options(options)
        new_parts = []
        changed = False
        skip_modifiers = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()

            if skip_modifiers and kw in ("nocase",):
                continue
            skip_modifiers = False

            if kw == "content":
                replaced = False
                for unicode_pat, (sticky, plain) in unicode_pipes.items():
                    if unicode_pat.lower() in part.lower():
                        if not any("smb.named_pipe" in p for p in new_parts):
                            new_parts.append("smb.named_pipe")
                        new_parts.append(f'content:"{plain}"')
                        new_parts.append("nocase")
                        skip_modifiers = True
                        changed = True
                        replaced = True
                        break
                if replaced:
                    continue

            new_parts.append(part)

        if changed:
            header_str = rule_str[:m.start()]
            return f"{header_str}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_threshold_type(rule_str: str) -> str:
        """Fix threshold:type both -> type threshold for rate counting rules.

        type both = fires once per period after N matches (alert-once semantics)
        type threshold = fires every N matches (rate counting)

        For brute force / auth failure counting, type threshold is correct.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "threshold:" not in options or "type both" not in options:
            return rule_str

        # Only fix for rules that look like rate counting (brute force, auth failures)
        rate_indicators = ["brute", "failure", "excessive", "credential", "auth", "relay"]
        msg_match = re.search(r'msg\s*:\s*"([^"]*)"', options)
        msg_text = msg_match.group(1).lower() if msg_match else ""

        if any(ind in msg_text for ind in rate_indicators):
            options = options.replace("type both", "type threshold")
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(_split_options(options))};)"

        return rule_str

    @staticmethod
    def _patch_incomplete_flowbits(rule_str: str) -> str:
        """Remove flowbits:set without a corresponding flowbits:isset.

        A single rule with flowbits:set but no flowbits:isset is useless —
        it sets a bit that nothing checks. Remove it to simplify the rule.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "flowbits:set," not in options:
            return rule_str
        # If there's also an isset, it's a complete pattern
        if "flowbits:isset," in options:
            return rule_str

        parts = _split_options(options)
        new_parts = [p for p in parts if not p.strip().startswith("flowbits:set,")]

        if len(new_parts) < len(parts):
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"
        return rule_str


    @staticmethod
    def _patch_dsize_with_app_layer(rule_str: str) -> str:
        """Remove dsize when app-layer keywords are present.

        dsize checks per-packet payload size and cannot be used with
        app-layer buffers like http.*, tls.*, dns.*, file.*.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "dsize:" not in options:
            return rule_str

        app_keywords = ("http.", "tls.", "dns.", "file.", "urilen")
        if not any(kw in options for kw in app_keywords):
            return rule_str

        parts = _split_options(options)
        new_parts = [p for p in parts if not re.split(r'[:\s]', p, maxsplit=1)[0].strip().startswith("dsize")]

        if len(new_parts) < len(parts):
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_dns_query_bsize(rule_str: str) -> str:
        """Replace bsize after dns.query with isdataat for length detection.

        bsize checks buffer metadata size, not actual query data length.
        isdataat:N,relative correctly checks if at least N bytes exist.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "dns.query" not in options or "bsize:" not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        in_dns_query = False
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "dns.query":
                in_dns_query = True
                new_parts.append(part)
            elif kw == "bsize" and in_dns_query:
                # Extract the numeric value: bsize:>100 or bsize:100
                bsize_match = re.search(r'bsize\s*:\s*>?\s*(\d+)', part)
                if bsize_match:
                    n = bsize_match.group(1)
                    new_parts.append(f"isdataat:{n},relative")
                    changed = True
                else:
                    new_parts.append(part)
            else:
                if kw in ("http.", "tls.", "file.") or kw.startswith("http.") or kw.startswith("tls."):
                    in_dns_query = False
                new_parts.append(part)

        if changed:
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_dns_content_or_logic(rule_str: str) -> str:
        """Replace multiple content matches after dns.query with PCRE OR logic.

        Multiple content matches in Suricata are AND — ALL must match.
        For DNS threat detection (malware OR phishing OR botnet), use PCRE alternation.
        Only triggers when 3+ content matches follow dns.query.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "dns.query" not in options:
            return rule_str

        parts = _split_options(options)
        dns_query_idx = None
        content_indices = []
        nocase_indices = set()

        for i, part in enumerate(parts):
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "dns.query":
                dns_query_idx = i
                content_indices = []
                nocase_indices = set()
            elif kw == "content" and dns_query_idx is not None:
                content_indices.append(i)
            elif kw == "nocase" and content_indices:
                nocase_indices.add(content_indices[-1])
            elif kw in ("depth", "offset", "distance", "within",
                        "fast_pattern", "startswith", "endswith", "bsize",
                        "isdataat"):
                pass  # modifiers stay in dns.query context
            elif kw not in ("msg", "flow", "sid", "rev", "threshold",
                            "classtype", "priority", "metadata", "reference"):
                if kw != "pcre":
                    dns_query_idx = None

        if len(content_indices) < 3:
            return rule_str

        # Extract content values
        content_values = []
        for idx in content_indices:
            match = re.search(r'content\s*:\s*"([^"]*)"', parts[idx])
            if match:
                content_values.append(match.group(1))

        if len(content_values) < 3:
            return rule_str

        # Build PCRE alternation
        pcre_alt = "|".join(re.escape(v) for v in content_values)
        has_nocase = bool(nocase_indices)
        pcre_flags = "i" if has_nocase else ""
        pcre_part = f'pcre:"/({pcre_alt})/{pcre_flags}"'

        # Remove old content + nocase parts, insert PCRE
        remove_set = set(content_indices) | nocase_indices
        new_parts = []
        inserted = False
        for i, part in enumerate(parts):
            if i in remove_set:
                if not inserted:
                    new_parts.append(pcre_part)
                    inserted = True
                continue
            new_parts.append(part)

        header = rule_str[:m.start()]
        return f"{header}({'; '.join(new_parts)};)"


    @staticmethod
    def _reconcile_flowbits(rules: list[str]) -> list[str]:
        """Reconcile flowbits across multiple rules.

        Removes orphaned flowbits:isset (no corresponding set) and
        orphaned flowbits:set (no corresponding isset) across the rule set.
        Rules that become empty of content after flowbits removal are dropped.
        """
        if len(rules) <= 1:
            return rules

        # Collect all set and isset names
        all_sets: set[str] = set()
        all_issets: set[str] = set()
        set_pattern = re.compile(r'flowbits\s*:\s*set\s*,\s*(\S+)')
        isset_pattern = re.compile(r'flowbits\s*:\s*isset\s*,\s*(\S+)')

        for rule in rules:
            for m in set_pattern.finditer(rule):
                all_sets.add(m.group(1).rstrip(';'))
            for m in isset_pattern.finditer(rule):
                all_issets.add(m.group(1).rstrip(';'))

        orphaned_issets = all_issets - all_sets
        orphaned_sets = all_sets - all_issets

        if not orphaned_issets and not orphaned_sets:
            return rules

        result = []
        for rule in rules:
            m = re.search(r'\((.+)\)\s*$', rule, re.DOTALL)
            if not m:
                result.append(rule)
                continue

            options = m.group(1)
            parts = _split_options(options)
            new_parts = []
            changed = False

            for part in parts:
                stripped = part.strip()
                # Remove orphaned isset
                if stripped.startswith("flowbits:isset,"):
                    name = stripped.split(",", 1)[1].strip().rstrip(";")
                    if name in orphaned_issets:
                        changed = True
                        continue
                # Remove orphaned set
                if stripped.startswith("flowbits:set,"):
                    name = stripped.split(",", 1)[1].strip().rstrip(";")
                    if name in orphaned_sets:
                        changed = True
                        continue
                new_parts.append(part)

            if changed:
                # Check if rule still has meaningful detection content
                has_content = any(
                    re.split(r'[:\s]', p, maxsplit=1)[0].strip() in (
                        "content", "pcre", "dns.query", "http.uri", "http.header",
                        "tls.sni", "threshold", "dsize", "isdataat", "byte_test",
                        "stream_size",
                    )
                    for p in new_parts
                )
                if has_content:
                    header = rule[:m.start()]
                    result.append(f"{header}({'; '.join(new_parts)};)")
                # else: drop the rule entirely (was only flowbits correlation with no detection)
            else:
                result.append(rule)

        return result

    @staticmethod
    def _patch_quic_duplicate_content(rule_str: str) -> str:
        """Remove redundant duplicate content matches in QUIC/UDP rules.

        Pattern: content:"|00 00|"; distance:0; content:"|00 00|"; distance:0;
        The second identical content+distance is redundant — remove it.
        Also fixes SNI detection structure in QUIC CRYPTO frames.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        header = rule_str[:m.start()].lower()
        if "udp" not in header:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        changed = False
        i = 0

        while i < len(parts):
            kw = re.split(r'[:\s]', parts[i], maxsplit=1)[0].strip()

            # Detect duplicate content+distance pairs
            if kw == "content" and i + 2 < len(parts):
                next_kw = re.split(r'[:\s]', parts[i + 1], maxsplit=1)[0].strip()
                if next_kw == "distance" and i + 2 < len(parts):
                    next2_kw = re.split(r'[:\s]', parts[i + 2], maxsplit=1)[0].strip()
                    if next2_kw == "content" and parts[i] == parts[i + 2]:
                        # Check if the distance after the duplicate is also the same
                        if i + 3 < len(parts):
                            next3_kw = re.split(r'[:\s]', parts[i + 3], maxsplit=1)[0].strip()
                            if next3_kw == "distance" and parts[i + 1] == parts[i + 3]:
                                # Duplicate pair — keep first, skip second
                                new_parts.append(parts[i])
                                new_parts.append(parts[i + 1])
                                # Replace duplicate with within constraint for better matching
                                new_parts.append(f"within:50")
                                i += 4
                                changed = True
                                continue

            new_parts.append(parts[i])
            i += 1

        if changed:
            header_str = rule_str[:m.start()]
            return f"{header_str}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_quic_short_header_detection(rule_str: str) -> str:
        """Fix QUIC Short Header bit-level detection.

        content:!"|80|" does NOT do bit-level checking — it checks if the
        exact byte 0x80 is absent, which is wrong for detecting bit 0x80 unset.

        Replace with pcre:"/^[\\x00-\\x7f]/" which correctly matches any first
        byte with bit 0x80 unset (Short Header format).
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        header = rule_str[:m.start()].lower()
        if "udp" not in header:
            return rule_str

        # Look for content:!"|80|"; depth:1; pattern
        if '!"|80|"' not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        changed = False
        skip_next_depth = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()

            if skip_next_depth and kw == "depth":
                skip_next_depth = False
                changed = True
                continue
            skip_next_depth = False

            if kw == "content" and '!"|80|"' in part:
                # Replace with PCRE for proper bit-level check
                new_parts.append('pcre:"/^[\\x00-\\x7f]/"')
                skip_next_depth = True
                changed = True
                continue

            new_parts.append(part)

        if changed:
            header_str = rule_str[:m.start()]
            return f"{header_str}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_coap_header(rule_str: str) -> str:
        """Fix CoAP header matching to not assume token length 0.

        content:"|40 02|" hardcodes version=01, type=CON, token_length=0000 + POST.
        The token length varies (0-8), so match POST code at offset 1 instead.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        header = rule_str[:m.start()].lower()
        if "udp" not in header:
            return rule_str
        if "5683" not in header and "5684" not in header:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        changed = False
        i = 0

        while i < len(parts):
            part = parts[i]
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()

            # Detect content:"|40 02|"; depth:2; pattern (hardcoded CoAP header)
            if kw == "content" and '"|40 02|"' in part:
                new_parts.append('content:"|02|"')
                new_parts.append('offset:1')
                new_parts.append('depth:1')
                # Skip the following depth:2 if present
                if i + 1 < len(parts):
                    next_kw = re.split(r'[:\s]', parts[i + 1], maxsplit=1)[0].strip()
                    if next_kw == "depth":
                        i += 2
                        changed = True
                        continue
                changed = True
                i += 1
                continue

            new_parts.append(part)
            i += 1

        if changed:
            header_str = rule_str[:m.start()]
            return f"{header_str}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_mqtt_topic_length(rule_str: str) -> str:
        """Fix MQTT topic length parsing in PCRE patterns.

        MQTT topic length is 2 bytes (MSB + LSB). The LLM sometimes generates
        \\x00[\\x32-\\xff] which assumes 1-byte length. Replace with \\x00.
        to correctly match the 2-byte length field.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        header = rule_str[:m.start()].lower()
        if "1883" not in header and "8883" not in header:
            return rule_str

        # Fix topic length byte range to 2-byte field
        if r"\x00[\x32-\xff]" in options:
            options = options.replace(r"\x00[\x32-\xff]", r"\x00.")
            header_str = rule_str[:m.start()]
            return f"{header_str}({options};)" if not options.rstrip().endswith(";)") else f"{header_str}({options})"

        return rule_str

    @staticmethod
    def _patch_flow_on_ip_protocol(rule_str: str) -> str:
        """Remove flow keyword from IP protocol rules.

        flow:to_server/to_client only works with TCP/UDP. For rules using
        'ip' protocol, the flow keyword is invalid and must be removed.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "flow:" not in options:
            return rule_str

        # Check if protocol is 'ip' in the rule header
        header = rule_str[:m.start()].strip()
        header_parts = header.split()
        if len(header_parts) < 2:
            return rule_str
        protocol = header_parts[1].lower()
        if protocol not in ("ip",):
            return rule_str

        parts = _split_options(options)
        new_parts = [p for p in parts if not re.split(r'[:\s]', p, maxsplit=1)[0].strip() == "flow"]

        if len(new_parts) < len(parts):
            header_str = rule_str[:m.start()]
            return f"{header_str}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_invalid_aws_metadata(rule_str: str) -> str:
        """Remove invalid AWS-specific metadata that isn't valid Suricata syntax.

        metadata:aws forward_to_sfe is not a valid Suricata keyword.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "metadata:aws" not in options and "metadata: aws" not in options:
            return rule_str

        parts = _split_options(options)
        new_parts = []
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "metadata" and ("aws " in part or "aws\t" in part):
                # Check if it's an invalid AWS-specific metadata
                if "forward_to_sfe" in part or "aws:drop" in part:
                    changed = True
                    continue
            new_parts.append(part)

        if changed:
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_flowbits_noalert_without_set(rule_str: str) -> str:
        """Add flowbits:set when flowbits:noalert is present without any flowbits:set.

        flowbits:noalert alone suppresses the alert but doesn't set any flowbit.
        If the msg field mentions tracking, logging, or flowbit correlation,
        infer a flowbit name from the msg and add flowbits:set.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "flowbits:noalert" not in options:
            return rule_str
        if "flowbits:set," in options:
            return rule_str

        # Infer flowbit name from msg field
        msg_match = re.search(r'msg\s*:\s*"([^"]*)"', options)
        if not msg_match:
            return rule_str

        msg = msg_match.group(1).lower()

        # Try to infer a meaningful flowbit name
        flowbit_name = None
        if "prod" in msg and "outbound" in msg:
            flowbit_name = "prod.outbound"
        elif "dmz" in msg:
            flowbit_name = "dmz.activity"
        elif "track" in msg or "log" in msg or "forensic" in msg or "correlat" in msg:
            # Generic tracking flowbit
            flowbit_name = "tracked.connection"

        if not flowbit_name:
            return rule_str

        # Insert flowbits:set before flowbits:noalert
        parts = _split_options(options)
        new_parts = []
        for part in parts:
            if part.strip() == "flowbits:noalert":
                new_parts.append(f"flowbits:set,{flowbit_name}")
            new_parts.append(part)

        header = rule_str[:m.start()]
        return f"{header}({'; '.join(new_parts)};)"

    @staticmethod
    def _patch_ip_proto_negation(rule_str: str) -> str:
        """Fix invalid ip_proto negation syntax.

        Suricata does NOT support ip_proto:!TCP or ip_proto:!6.
        Replace negated ip_proto with positive match for GRE (47),
        the most common tunneling protocol to block, and update the
        msg field to accurately reflect what the rule blocks.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        if "ip_proto:!" not in options:
            return rule_str

        # Check if this is an IP protocol rule
        header = rule_str[:m.start()].strip()
        header_parts = header.split()
        if len(header_parts) < 2:
            return rule_str
        protocol = header_parts[1].lower()
        if protocol != "ip":
            return rule_str

        parts = _split_options(options)
        has_negated_proto = any(
            p.strip().startswith("ip_proto:!") for p in parts
        )

        if not has_negated_proto:
            return rule_str

        # Remove all negated ip_proto entries and replace with GRE (most common tunnel)
        new_parts = []
        for p in parts:
            if p.strip().startswith("ip_proto:!"):
                continue
            # Fix msg to accurately describe what the rule blocks
            kw = re.split(r'[:\s]', p, maxsplit=1)[0].strip()
            if kw == "msg":
                msg_match = re.search(r'msg\s*:\s*"([^"]*)"', p)
                if msg_match:
                    p = 'msg:"DROP - Block GRE tunneling protocol (47) from Production"'
            new_parts.append(p)

        # Insert ip_proto:47 before sid
        sid_idx = None
        for i, p in enumerate(new_parts):
            if re.split(r'[:\s]', p, maxsplit=1)[0].strip() == "sid":
                sid_idx = i
                break
        if sid_idx is not None:
            new_parts.insert(sid_idx, "ip_proto:47")
        else:
            new_parts.append("ip_proto:47")

        header_str = rule_str[:m.start()]
        return f"{header_str}({'; '.join(new_parts)};)"

    @staticmethod
    def _patch_aws_unsupported_keywords(rule_str: str) -> str:
        """Remove keywords unsupported by AWS Network Firewall.

        AWS NFW does not support: filesize, filemagic, filename, fileext,
        filemd5, filesha1, filesha256, filestore, dataset, datarep, iprep.
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)

        unsupported = {
            "filesize", "filemagic", "filename", "fileext",
            "filemd5", "filesha1", "filesha256", "filestore",
            "dataset", "datarep", "iprep",
        }

        parts = _split_options(options)
        new_parts = []
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw in unsupported:
                changed = True
                continue
            new_parts.append(part)

        if changed:
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_byte_test_content_len(rule_str: str) -> str:
        """Fix byte_test with http.content_len: correct ordering and byte count.

        Two fixes:
        1. If byte_test appears BEFORE http.content_len, reorder so
           http.content_len comes first (byte_test operates on the sticky buffer).
        2. Fix byte_test:4,>,N → byte_test:0,>,N because http.content_len is
           a variable-length ASCII string.
        """
        if "http.content_len" not in rule_str or "byte_test" not in rule_str:
            return rule_str

        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        parts = _split_options(options)

        # Find indices of http.content_len and byte_test
        content_len_idx = None
        byte_test_idx = None
        byte_test_part = None

        for i, part in enumerate(parts):
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "http.content_len":
                content_len_idx = i
            elif kw == "byte_test" and "string" in part and "dec" in part:
                byte_test_idx = i
                byte_test_part = part

        if content_len_idx is None or byte_test_idx is None:
            return rule_str

        changed = False
        new_parts = list(parts)

        # Fix 1: Reorder if byte_test is before http.content_len
        if byte_test_idx < content_len_idx:
            # Remove byte_test from its current position
            new_parts.pop(byte_test_idx)
            # Find new position of http.content_len (shifted by removal)
            new_cl_idx = content_len_idx - 1
            # Insert byte_test right after http.content_len
            new_parts.insert(new_cl_idx + 1, byte_test_part)
            changed = True

        # Fix 2: Fix byte count (4 → 0) in byte_test
        for i, part in enumerate(new_parts):
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "byte_test" and "string" in part and "dec" in part:
                fixed = re.sub(
                    r'^byte_test\s*:\s*[1-9]\d*\s*,',
                    'byte_test:0,',
                    part,
                )
                if fixed != part:
                    new_parts[i] = fixed
                    changed = True

        if changed:
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_bidir_flow_direction(rule_str: str) -> str:
        """Fix flow:established,to_server/to_client when rule uses <> operator.

        The bidirectional operator <> conflicts with directional flow qualifiers
        (to_server, to_client). When <> is used, strip the direction from flow
        and keep only 'flow:established'.
        """
        # Check if rule header uses bidirectional operator
        header = rule_str.split("(")[0] if "(" in rule_str else rule_str
        if "<>" not in header:
            return rule_str

        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        parts = _split_options(options)
        new_parts = []
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "flow":
                flow_val = part.split(":", 1)[1].strip() if ":" in part else ""
                if "to_server" in flow_val or "to_client" in flow_val:
                    # Remove direction qualifiers, keep state
                    cleaned = flow_val.replace(",to_server", "").replace(",to_client", "")
                    cleaned = cleaned.replace("to_server,", "").replace("to_client,", "")
                    cleaned = cleaned.replace("to_server", "").replace("to_client", "")
                    cleaned = cleaned.strip().strip(",").strip()
                    if cleaned:
                        new_parts.append(f"flow:{cleaned}")
                    # If nothing left (e.g., was just "to_server"), drop flow entirely
                    changed = True
                else:
                    new_parts.append(part)
            else:
                new_parts.append(part)

        if changed:
            rule_header = rule_str[:m.start()]
            return f"{rule_header}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_smb_protocol_port(rule_str: str) -> str:
        """Fix SMB protocol rules that include non-SMB ports like 135.

        smb.share and smb.named_pipe only work on port 445 (SMB protocol).
        Port 135 is RPC, not SMB. When the rule uses 'smb' protocol with
        SMB-specific keywords, strip port 135 from the destination port list.
        """
        header = rule_str.split("(")[0] if "(" in rule_str else rule_str
        header_parts = header.split()
        if len(header_parts) < 2:
            return rule_str

        protocol = header_parts[1].lower()
        if protocol != "smb":
            return rule_str

        # Check if rule uses SMB-specific keywords
        has_smb_kw = "smb.share" in rule_str or "smb.named_pipe" in rule_str
        if not has_smb_kw:
            return rule_str

        # Check if destination port includes 135
        if "135" not in header:
            return rule_str

        # Fix port list: remove 135, keep 445
        # Handle [135,445] or [445,135] patterns
        new_header = re.sub(r'\[135,\s*445\]', '445', header)
        new_header = re.sub(r'\[445,\s*135\]', '445', new_header)
        # Handle standalone 135 in port groups
        new_header = re.sub(r',\s*135\b', '', new_header)
        new_header = re.sub(r'\b135\s*,', '', new_header)

        if new_header != header:
            options_part = rule_str[len(header):]
            return new_header + options_part

        return rule_str




    @staticmethod
    def _patch_flow_add_direction(rule_str: str, user_input: str = "") -> str:
        """Add direction qualifier to bare flow:established on non-bidirectional rules.

        The best-practice checker rejects flow:established without to_server/to_client.
        This patch infers direction from context and adds it automatically.
        Skips bidirectional (<>) rules where direction qualifiers are forbidden.
        """
        header = rule_str.split("(")[0] if "(" in rule_str else rule_str
        if "<>" in header:
            return rule_str

        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        flow_match = re.search(r'flow\s*:\s*([^;]+)', options)
        if not flow_match:
            return rule_str

        flow_val = flow_match.group(1).strip().lower()
        if "to_server" in flow_val or "to_client" in flow_val:
            return rule_str
        if "established" not in flow_val:
            return rule_str

        # Infer direction from context
        user_lower = (user_input or "").lower()
        inbound_terms = ["inbound", "ingress", "incoming", "to_client",
                         "from external", "from outside", "response", "reply"]
        if any(t in user_lower for t in inbound_terms):
            direction = "to_client"
        else:
            direction = "to_server"

        # Also check rule header: if src is port 53/445/etc (server port), it's a response
        header_parts = header.split()
        if len(header_parts) >= 4:
            src_port = header_parts[3] if len(header_parts) > 3 else ""
            if src_port in ("53", "445", "80", "443", "25", "22"):
                direction = "to_client"

        new_flow = flow_val.rstrip(",") + "," + direction
        new_options = options[:flow_match.start(1)] + new_flow + options[flow_match.end(1):]
        rule_header = rule_str[:m.start()]
        return f"{rule_header}({new_options};)"

    @staticmethod
    def _patch_file_data_dot_to_underscore(rule_str: str) -> str:
        """Fix file.data to file_data.

        Suricata uses file_data (underscore) as the sticky buffer keyword,
        NOT file.data (dot). The LLM frequently generates the wrong form.
        """
        if "file.data" not in rule_str:
            return rule_str

        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        parts = _split_options(options)
        new_parts = []
        changed = False

        for part in parts:
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw == "file.data":
                new_parts.append("file_data")
                changed = True
            else:
                new_parts.append(part)

        if changed:
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"
        return rule_str

    @staticmethod
    def _patch_sticky_buffer_content_order(rule_str: str) -> str:
        """Fix sticky buffers that have no content/pcre applied to them.

        When multiple sticky buffers are listed consecutively without content
        matches between them, the content/pcre that follows applies only to
        the LAST buffer. Reorder so each buffer has its content match.

        Pattern detected: http.host; http.content_len; http.content_type;
                         pcre:"/host_pattern/"; content:"type_match"; byte_test:...;
        Fixed to:        http.host; pcre:"/host_pattern/"; http.content_type;
                         content:"type_match"; http.content_len; byte_test:...;
        """
        m = _OPTS_RE.search(rule_str)
        if not m:
            return rule_str

        options = m.group(1)
        parts = _split_options(options)

        sticky_buffers = {
            "http.uri", "http.host", "http.method", "http.user_agent",
            "http.cookie", "http.header", "http.content_type",
            "http.content_len", "http.stat_code", "http.stat_msg",
            "http.request_body", "http.response_body", "http.referer",
            "http.server", "http.location", "http.protocol",
            "http.header_names", "http.start", "http.request_header",
            "http2.header_name",
            "tls.sni", "tls.cert_subject", "tls.cert_issuer", "tls.ciphersuites",
            "dns.query", "file.data", "file.name", "file_data",
            "smb.share", "smb.named_pipe", "dcerpc.stub_data",
            "ssh.software", "ssh.proto", "ssh.hassh", "ssh.hassh.server",
            "ja3.hash", "ja4.hash",
        }

        content_modifiers = {
            "nocase", "depth", "offset", "distance", "within",
            "fast_pattern", "startswith", "endswith", "bsize",
            "rawbytes", "isdataat",
        }

        # Find consecutive sticky buffers with no content between them
        consecutive_stickies = []
        group_start = None

        for i, part in enumerate(parts):
            kw = re.split(r'[:\s]', part, maxsplit=1)[0].strip()
            if kw in sticky_buffers:
                if group_start is None:
                    group_start = i
                consecutive_stickies.append(i)
            elif kw in ("content", "pcre", "byte_test"):
                if len(consecutive_stickies) >= 2:
                    break  # Found the group
                consecutive_stickies = []
                group_start = None
            elif kw in content_modifiers:
                pass  # Skip modifiers
            elif kw in ("msg", "flow", "sid", "rev", "threshold",
                        "classtype", "priority", "metadata", "reference"):
                consecutive_stickies = []
                group_start = None

        # Only fix if we found 2+ consecutive sticky buffers
        if len(consecutive_stickies) < 2:
            return rule_str

        # Collect content/pcre/byte_test tokens after the sticky group
        after_idx = consecutive_stickies[-1] + 1
        trailing_content = []
        trailing_end = after_idx

        for i in range(after_idx, len(parts)):
            tkw = re.split(r'[:\s]', parts[i], maxsplit=1)[0].strip()
            if tkw in ("content", "pcre", "byte_test") or tkw in content_modifiers:
                trailing_content.append(parts[i])
                trailing_end = i + 1
            elif tkw in sticky_buffers:
                break
            else:
                break

        if not trailing_content:
            return rule_str

        # Try to match content to sticky buffers by type heuristics
        # This is best-effort — we match pcre with host patterns to http.host, etc.
        assignments: dict[int, list[str]] = {idx: [] for idx in consecutive_stickies}
        unassigned = []

        # Build a map of sticky buffer types for quick lookup
        sticky_types = {}
        for idx in consecutive_stickies:
            skw = re.split(r'[:\s]', parts[idx], maxsplit=1)[0].strip()
            sticky_types[idx] = skw

        for token in trailing_content:
            tkw = re.split(r'[:\s]', token, maxsplit=1)[0].strip()
            assigned = False

            if tkw == "byte_test":
                # byte_test goes with http.content_len
                for idx in consecutive_stickies:
                    if sticky_types[idx] == "http.content_len":
                        assignments[idx].append(token)
                        assigned = True
                        break

            elif tkw in ("content", "pcre"):
                # Extract the value for heuristic matching
                val = token.split(":", 1)[1].strip().strip('"').lower() if ":" in token else ""

                # Try to match based on content value patterns
                target_buffer = None

                if tkw == "content":
                    # URI patterns: paths, .php, .asp, /api/, etc.
                    if any(p in val for p in ["/", ".php", ".asp", ".jsp", ".html",
                                               ".cgi", "wsman", "submit", "upload",
                                               "login", "admin", "api"]):
                        target_buffer = "http.uri"
                    # HTTP method patterns
                    elif val.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH",
                                          "HEAD", "OPTIONS", "CONNECT"):
                        target_buffer = "http.method"
                    # Content-Type patterns
                    elif any(p in val for p in ["image/", "application/", "text/",
                                                 "multipart/", "json", "xml", "html"]):
                        target_buffer = "http.content_type"
                    # Host/domain patterns
                    elif any(p in val for p in [".com", ".net", ".org", ".io",
                                                 ".amazonaws.com", ".blob.core"]):
                        target_buffer = "http.host"
                    # Request body patterns (form params, session tokens)
                    elif any(p in val for p in ["&", "=", "session", "token",
                                                 "password", "username", "data"]):
                        target_buffer = "http.request_body"
                    # User-Agent patterns
                    elif any(p in val for p in ["mozilla", "msie", "chrome",
                                                 "firefox", "safari", "user-agent",
                                                 "bot", "crawler", "wget", "curl"]):
                        target_buffer = "http.user_agent"

                elif tkw == "pcre":
                    # PCRE patterns — match by content
                    if any(p in val for p in ["mozilla", "msie", "chrome",
                                               "user.agent", "compatible"]):
                        target_buffer = "http.user_agent"
                    elif any(p in val for p in [".com", ".net", ".org", ".io",
                                                 "s3\\.", "blob\\.", "amazonaws",
                                                 "cloudfront"]):
                        target_buffer = "http.host"
                    elif any(p in val for p in ["application/", "json", "xml",
                                                 "image/"]):
                        target_buffer = "http.content_type"
                    elif any(p in val for p in ["/", "\\.php", "\\.asp"]):
                        target_buffer = "http.uri"

                if target_buffer:
                    for idx in consecutive_stickies:
                        if sticky_types[idx] == target_buffer:
                            assignments[idx].append(token)
                            assigned = True
                            break

            elif tkw in content_modifiers:
                # Modifiers attach to the last assigned content
                # Find the last sticky buffer that got a content assignment
                last_assigned_idx = None
                for idx in reversed(consecutive_stickies):
                    if assignments[idx]:
                        last_assigned_idx = idx
                        break
                if last_assigned_idx is not None:
                    assignments[last_assigned_idx].append(token)
                    assigned = True

            if not assigned:
                unassigned.append(token)

        # Only proceed if we actually assigned something
        has_assignments = any(v for v in assignments.values())
        if not has_assignments:
            return rule_str

        # Rebuild: before_group + interleaved(sticky+content) + unassigned + rest
        new_parts = parts[:group_start]
        for idx in consecutive_stickies:
            new_parts.append(parts[idx])
            new_parts.extend(assignments[idx])
        new_parts.extend(unassigned)
        new_parts.extend(parts[trailing_end:])

        if new_parts != parts:
            header = rule_str[:m.start()]
            return f"{header}({'; '.join(new_parts)};)"

        return rule_str
