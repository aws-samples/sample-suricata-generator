"""
AI-powered semantic analysis of Suricata rulesets via Amazon Bedrock.

This module provides the AIRuleAnalyzer class which sends the full ruleset
plus static findings to an LLM to reason about security posture, coverage
gaps, policy coherence, optimization opportunities, and AWS Network
Firewall-specific advice.
"""

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable

from src.agent.models import AnalysisFinding, StructuredAnalysisResponse

# Guard boto3 import — module loads successfully without boto3
HAS_BOTO3 = False
try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    boto3 = None


# Section key to ID prefix mapping
_SECTION_PREFIXES = {
    "coverage_gaps": "cg",
    "policy_coherence": "pc",
    "optimizations": "opt",
    "aws_advice": "aws",
}

# Valid values for constrained fields
_VALID_SEVERITIES = {"critical", "warning", "info"}
_VALID_CONFIDENCES = {"high", "medium", "low"}
_SECTION_KEYS = list(_SECTION_PREFIXES.keys())


class AIRuleAnalyzer:
    """AI-powered semantic analysis of Suricata rulesets via Amazon Bedrock."""

    def __init__(
        self,
        knowledge_base,
        bedrock_client,
        model_id: str,
        rule_analyzer,
        best_practice_checker,
    ):
        self._kb = knowledge_base
        self._client = bedrock_client
        self._model_id = model_id
        self._rule_analyzer = rule_analyzer
        self._bp_checker = best_practice_checker
        self._cache: dict[str, StructuredAnalysisResponse] = {}

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_cache_key(rules: list, variables: dict[str, Any]) -> str:
        """Compute a SHA-256 cache key from the ruleset and variables.

        The key is derived from the sorted serialized rule strings joined
        together, concatenated with the JSON-serialized variables (with
        sorted keys for determinism).
        """
        sorted_rule_strings = sorted(rule.to_string() for rule in rules)
        rules_part = "".join(sorted_rule_strings)
        variables_part = json.dumps(variables, sort_keys=True)
        combined = rules_part + variables_part
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def get_cached(
        self, rules: list, variables: dict[str, Any]
    ) -> StructuredAnalysisResponse | None:
        """Return cached results if the ruleset state matches, else None.

        Returns a copy of the cached response with ``is_cached=True``.
        """
        key = self._compute_cache_key(rules, variables)
        cached = self._cache.get(key)
        if cached is None:
            return None
        return replace(cached, is_cached=True)

    def invalidate_cache(self) -> None:
        """Clear the analysis cache.

        Called from ``SuricataRuleGenerator`` whenever rules or variables
        are modified.
        """
        self._cache.clear()

    # ------------------------------------------------------------------
    # Public orchestration
    # ------------------------------------------------------------------

    def analyze(
        self,
        rules: list,
        variables: dict[str, Any],
        static_findings: dict[str, list[dict]],
        on_progress: Callable[[str], None] | None = None,
    ) -> StructuredAnalysisResponse:
        """Run AI analysis on the ruleset.

        Orchestrates the full analysis pipeline: cache check, prompt
        assembly, Bedrock invocation, response parsing, and caching.

        This method performs *analysis only* — it does not generate new
        Suricata rules (Req 10.1) and is only called on explicit user
        action (Req 10.2).

        Args:
            rules: All SuricataRule objects in the editor.
            variables: Rule variables with definitions.
            static_findings: Raw output from
                ``RuleAnalyzer.analyze_rule_conflicts()``.
            on_progress: Optional callback for progress updates.

        Returns:
            StructuredAnalysisResponse with parsed findings.

        Raises:
            RuntimeError: On any Bedrock API or network error, with a
                descriptive message for the UI layer to display.
        """
        # 1. Check cache — return immediately on hit (Req 14.1)
        cached = self.get_cached(rules, variables)
        if cached is not None:
            return cached

        # 2. Assemble ruleset context
        if on_progress is not None:
            on_progress("Assembling ruleset context...")

        # Summarize large rulesets (>500 rules) — Req 9.1
        rules_to_send = rules
        was_summarized = False
        if len(rules) > self._LARGE_RULESET_THRESHOLD:
            rules_to_send, was_summarized = self._summarize_for_large_rulesets(
                rules, static_findings
            )

        prompt_data = self._assemble_prompt_data(
            rules_to_send, variables, static_findings
        )

        # 3. Build prompts
        if on_progress is not None:
            on_progress("Running best practice checks...")

        system_prompt = self._build_system_prompt(prompt_data)
        user_message = self._build_user_message(prompt_data)

        # 4. Invoke Bedrock
        if on_progress is not None:
            on_progress("Invoking AI model...")

        try:
            raw_response = self._invoke_bedrock(system_prompt, user_message)
        except Exception as exc:
            raise self._wrap_bedrock_error(exc) from exc

        # 5. Parse response
        if on_progress is not None:
            on_progress("Parsing response...")

        response = self._parse_response(raw_response)

        # 6. Stamp metadata on the response
        response.timestamp = datetime.now(timezone.utc).isoformat()
        response.model_id = self._model_id
        response.was_summarized = was_summarized

        # 7. Store in cache (Req 14.1)
        cache_key = self._compute_cache_key(rules, variables)
        self._cache[cache_key] = response

        return response

    @staticmethod
    def _wrap_bedrock_error(exc: Exception) -> RuntimeError:
        """Wrap a Bedrock-related exception in a descriptive RuntimeError.

        Handles ClientError (credentials/permissions), ThrottlingException,
        network timeouts, ModelNotReadyException, and unexpected errors.
        """
        exc_type_name = type(exc).__name__

        # botocore ClientError subtypes
        if HAS_BOTO3 and isinstance(exc, ClientError):
            error_code = exc.response.get("Error", {}).get("Code", "")
            error_message = exc.response.get("Error", {}).get("Message", str(exc))

            if error_code == "ThrottlingException":
                return RuntimeError(
                    f"Request throttled by Bedrock. Please wait a moment and try again. "
                    f"Details: {error_message}"
                )
            if error_code == "ModelNotReadyException":
                return RuntimeError(
                    f"The selected model is not available in this region. "
                    f"Please select a different model or region. "
                    f"Details: {error_message}"
                )
            # General ClientError (credentials, permissions, etc.)
            return RuntimeError(
                f"Bedrock access error: {error_message}"
            )

        # Network / connection timeouts
        if "timeout" in exc_type_name.lower() or "timeout" in str(exc).lower():
            return RuntimeError(
                "The Bedrock request timed out. This may be due to a large "
                "ruleset or network issues. Please try again."
            )

        # ModelNotReadyException may also appear as a standalone exception
        if exc_type_name == "ModelNotReadyException":
            return RuntimeError(
                f"The selected model is not available in this region. "
                f"Please select a different model or region. Details: {exc}"
            )

        # Unexpected error
        return RuntimeError(
            f"AI analysis failed: {exc_type_name}: {exc}"
        )

    # ------------------------------------------------------------------
    # Bedrock invocation
    # ------------------------------------------------------------------

    def _invoke_bedrock(self, system_prompt: str, user_message: str) -> str:
        """Invoke Amazon Bedrock via the Converse API.

        Sends the system prompt and user message to the configured model
        and returns the raw text response.

        Args:
            system_prompt: The system prompt with analysis instructions.
            user_message: The user message containing the ruleset context.

        Returns:
            The raw text content from the model response.
        """
        response = self._client.converse(
            modelId=self._model_id,
            messages=[
                {
                    "role": "user",
                    "content": [{"text": user_message}],
                }
            ],
            system=[{"text": system_prompt}],
            inferenceConfig={"maxTokens": 8192, "temperature": 0.0},
        )
        return response["output"]["message"]["content"][0]["text"]

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, raw_text: str) -> StructuredAnalysisResponse:
        """Parse a JSON response string into a StructuredAnalysisResponse.

        Attempts to parse *raw_text* as JSON conforming to the expected
        schema.  If parsing fails, falls back to a free-form text
        extraction that stores the original text in ``raw_text``.

        Each finding is assigned a unique id (e.g. ``cg-1``, ``pc-2``)
        and missing optional fields are filled with safe defaults.
        """
        try:
            data = self._extract_json(raw_text)
            return self._build_response_from_json(data, raw_text)
        except (json.JSONDecodeError, TypeError, KeyError, ValueError):
            # Fallback: return a response with the raw text preserved
            return self._fallback_parse(raw_text)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(raw_text: str) -> dict:
        """Extract a JSON object from *raw_text*.

        Handles both plain JSON and JSON wrapped in markdown code fences.
        """
        text = raw_text.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            # Remove opening fence (possibly with language tag)
            first_newline = text.index("\n")
            text = text[first_newline + 1:]
            # Remove closing fence
            if text.rstrip().endswith("```"):
                text = text.rstrip()[:-3].rstrip()

        return json.loads(text)

    def _build_response_from_json(
        self, data: dict, raw_text: str
    ) -> StructuredAnalysisResponse:
        """Build a StructuredAnalysisResponse from parsed JSON *data*."""
        response = StructuredAnalysisResponse(raw_text=raw_text)

        for section_key in _SECTION_KEYS:
            findings_data = data.get(section_key, [])
            if not isinstance(findings_data, list):
                findings_data = []

            prefix = _SECTION_PREFIXES[section_key]
            parsed_findings: list[AnalysisFinding] = []

            for idx, item in enumerate(findings_data, start=1):
                if not isinstance(item, dict):
                    continue
                finding = self._parse_single_finding(item, section_key, prefix, idx)
                parsed_findings.append(finding)

            setattr(response, section_key, parsed_findings)

        return response

    @staticmethod
    def _parse_single_finding(
        item: dict, section: str, prefix: str, index: int
    ) -> AnalysisFinding:
        """Parse a single finding dict into an AnalysisFinding."""
        severity = item.get("severity", "info")
        if severity not in _VALID_SEVERITIES:
            severity = "info"

        confidence = item.get("confidence", "low")
        if confidence not in _VALID_CONFIDENCES:
            confidence = "low"

        affected_sids = item.get("affected_sids", [])
        if not isinstance(affected_sids, list):
            affected_sids = []
        # Ensure all SIDs are integers
        affected_sids = [
            int(s) for s in affected_sids if isinstance(s, (int, float))
        ]

        return AnalysisFinding(
            id=f"{prefix}-{index}",
            section=section,
            severity=severity,
            confidence=confidence,
            description=item.get("description", ""),
            affected_sids=affected_sids,
            recommendation=item.get("recommendation", ""),
            caveat=item.get("caveat", ""),
            reference=item.get("reference", ""),
        )

    @staticmethod
    def _fallback_parse(raw_text: str) -> StructuredAnalysisResponse:
        """Fallback parser for non-JSON responses.

        Returns a valid StructuredAnalysisResponse with the original text
        preserved in raw_text and empty finding lists.
        """
        return StructuredAnalysisResponse(raw_text=raw_text)

    # ------------------------------------------------------------------
    # Prompt data assembly
    # ------------------------------------------------------------------

    def _assemble_prompt_data(
        self,
        rules: list,
        variables: dict,
        static_findings: dict,
    ) -> dict:
        """Gather all context needed for the AI analysis prompt.

        Serializes the ruleset, summarizes static and best-practice
        findings, computes metadata, loads the AWS best practices
        document, and annotates each rule with its type classification.

        Args:
            rules: All SuricataRule objects in the editor.
            variables: Rule variables with definitions.
            static_findings: Raw output from
                ``RuleAnalyzer.analyze_rule_conflicts()``.

        Returns:
            A dict with keys:
            - ``serialized_rules``: list of rule strings preserving order
            - ``static_findings_summary``: summary of static findings by
              severity and type
            - ``best_practice_findings``: list of per-rule best practice
              findings (dicts with ``sid``, ``rule``, ``issues``)
            - ``rule_type_annotations``: dict mapping SID to rule type
              classification string
            - ``metadata``: dict with ``total_count``,
              ``action_distribution``, ``protocol_distribution``,
              ``rule_type_distribution``
            - ``aws_best_practices_doc``: content of the AWS best
              practices document (empty string if unavailable)
            - ``variables``: the rule variables dict
        """
        # 1. Serialize all rules preserving order
        serialized_rules: list[str] = []
        for rule in rules:
            serialized_rules.append(rule.to_string())

        # 2. Identify active (non-comment, non-blank) rules for metadata
        active_rules = [
            r for r in rules
            if not getattr(r, "is_comment", False)
            and not getattr(r, "is_blank", False)
        ]

        # 3. Summarize static findings by severity and type
        static_findings_summary: dict[str, dict[str, int]] = {}
        for category, findings_list in static_findings.items():
            if not isinstance(findings_list, list):
                continue
            count = len(findings_list)
            if count > 0:
                static_findings_summary[category] = {"count": count}

        # 4. Run BestPracticeChecker against each active rule
        best_practice_findings: list[dict] = []
        for rule in active_rules:
            rule_str = rule.to_string()
            result = self._bp_checker.check(rule_str)
            if result.issues:
                issues_data = []
                for issue in result.issues:
                    issues_data.append({
                        "category": issue.category,
                        "severity": issue.severity,
                        "message": issue.message,
                        "fix_hint": issue.fix_hint,
                    })
                best_practice_findings.append({
                    "sid": rule.sid,
                    "rule": rule_str,
                    "issues": issues_data,
                })

        # 5. Run get_detailed_suricata_rule_type per active rule
        rule_type_annotations: dict[int, str] = {}
        for rule in active_rules:
            rule_type = self._rule_analyzer.get_detailed_suricata_rule_type(rule)
            rule_type_annotations[rule.sid] = rule_type

        # 6. Compute ruleset metadata from active rules
        action_distribution: dict[str, int] = {}
        protocol_distribution: dict[str, int] = {}
        rule_type_distribution: dict[str, int] = {}

        for rule in active_rules:
            action = rule.action
            action_distribution[action] = action_distribution.get(action, 0) + 1

            protocol = rule.protocol
            protocol_distribution[protocol] = (
                protocol_distribution.get(protocol, 0) + 1
            )

            rule_type = rule_type_annotations.get(rule.sid, "SIG_TYPE_NOT_SET")
            rule_type_distribution[rule_type] = (
                rule_type_distribution.get(rule_type, 0) + 1
            )

        metadata = {
            "total_count": len(active_rules),
            "action_distribution": action_distribution,
            "protocol_distribution": protocol_distribution,
            "rule_type_distribution": rule_type_distribution,
        }

        # 7. Load AWS best practices document (proceed without if unavailable)
        aws_best_practices_doc = ""
        try:
            aws_best_practices_doc = self._kb.get_doc(
                "aws_network_firewall_best_practices.md"
            )
        except Exception:
            pass

        return {
            "serialized_rules": serialized_rules,
            "static_findings_summary": static_findings_summary,
            "best_practice_findings": best_practice_findings,
            "rule_type_annotations": rule_type_annotations,
            "metadata": metadata,
            "aws_best_practices_doc": aws_best_practices_doc,
            "variables": variables,
        }

    # ------------------------------------------------------------------
    # Large ruleset summarization
    # ------------------------------------------------------------------

    # Character budget for sampled rule text (~100K characters)
    _CHAR_BUDGET = 100_000

    # Threshold above which summarization is applied
    _LARGE_RULESET_THRESHOLD = 500

    @staticmethod
    def _extract_flagged_sids(static_findings: dict) -> set[int]:
        """Extract all SIDs referenced by static analysis findings.

        Scans every finding in *static_findings* for ``sid``, ``sids``,
        ``upper_rule``, ``lower_rule``, and ``rule`` keys to collect the
        full set of SIDs that the static analyzer flagged.

        Args:
            static_findings: Raw output from
                ``RuleAnalyzer.analyze_rule_conflicts()``.

        Returns:
            A set of integer SIDs referenced by at least one finding.
        """
        flagged: set[int] = set()
        for _category, findings_list in static_findings.items():
            if not isinstance(findings_list, list):
                continue
            for finding in findings_list:
                if not isinstance(finding, dict):
                    continue
                # Conflict findings have upper_rule / lower_rule
                for key in ("upper_rule", "lower_rule", "rule"):
                    rule_obj = finding.get(key)
                    if rule_obj is not None and hasattr(rule_obj, "sid"):
                        flagged.add(rule_obj.sid)
                # Some findings may carry explicit sid / sids fields
                sid_val = finding.get("sid")
                if isinstance(sid_val, int):
                    flagged.add(sid_val)
                sids_val = finding.get("sids")
                if isinstance(sids_val, list):
                    for s in sids_val:
                        if isinstance(s, int):
                            flagged.add(s)
        return flagged

    def _summarize_for_large_rulesets(
        self,
        rules: list,
        static_findings: dict,
    ) -> tuple[list, bool]:
        """Summarize a large ruleset to fit within the LLM context budget.

        For rulesets with 500 or fewer rules the full list is returned
        unchanged.  For larger rulesets:

        1. All rules whose SID appears in any static analysis finding
           are included unconditionally.
        2. The remaining (unflagged) rules are sampled in order until
           the cumulative serialized text reaches ~100K characters.
        3. ``was_summarized`` is set to ``True`` so the caller can
           record it on the response and the UI can display a notice.

        Metadata and distributions should still be computed from the
        **full** ruleset by the caller — this method only selects which
        rules to send to the LLM.

        Args:
            rules: All SuricataRule objects in the editor.
            static_findings: Raw output from
                ``RuleAnalyzer.analyze_rule_conflicts()``.

        Returns:
            A tuple ``(rules_to_send, was_summarized)`` where
            *rules_to_send* is the (possibly reduced) list and
            *was_summarized* is ``True`` when the ruleset was trimmed.
        """
        if len(rules) <= self._LARGE_RULESET_THRESHOLD:
            return (rules, False)

        flagged_sids = self._extract_flagged_sids(static_findings)

        # Partition into flagged (priority) and remaining rules
        flagged_rules: list = []
        remaining_rules: list = []
        for rule in rules:
            if hasattr(rule, "sid") and rule.sid in flagged_sids:
                flagged_rules.append(rule)
            else:
                remaining_rules.append(rule)

        # Compute character usage of flagged rules
        char_used = sum(len(r.to_string()) for r in flagged_rules)

        # Sample remaining rules in order until budget is exhausted
        sampled_remaining: list = []
        budget_remaining = max(0, self._CHAR_BUDGET - char_used)
        for rule in remaining_rules:
            rule_text = rule.to_string()
            rule_len = len(rule_text)
            if rule_len <= budget_remaining:
                sampled_remaining.append(rule)
                budget_remaining -= rule_len
            else:
                # Budget exhausted — stop sampling
                break

        # Combine: flagged rules first, then sampled remaining
        rules_to_send = flagged_rules + sampled_remaining
        return (rules_to_send, True)

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_system_prompt(self, prompt_data: dict) -> str:
        """Construct the analysis system prompt.

        The prompt is structured with a clear role, task description,
        grounding context from the AWS best practices document, summaries
        of already-identified static and best-practice findings (so the
        LLM avoids re-reporting them), output format instructions with
        the JSON schema, analysis focus areas, and rule type processing
        order context.

        This prompt is intentionally distinct from the NLParser
        generation prompt — it focuses on *analysis* of an existing
        ruleset rather than *generation* of new rules.

        Args:
            prompt_data: The dict returned by ``_assemble_prompt_data()``.

        Returns:
            The complete system prompt string.
        """
        parts: list[str] = []

        # --- Role ---
        parts.append(
            "ROLE: You are an expert Suricata IDS/IPS security analyst "
            "specializing in AWS Network Firewall deployments."
        )

        # --- Task ---
        parts.append(
            "\nTASK: Analyze the provided ruleset for security posture "
            "issues. Focus on semantic insights that go beyond what "
            "static analysis can detect."
        )

        # --- Grounding context (AWS best practices doc) ---
        aws_doc = prompt_data.get("aws_best_practices_doc", "")
        if aws_doc:
            parts.append(
                "\nGROUNDING CONTEXT:\n"
                "<aws_best_practices>\n"
                f"{aws_doc}\n"
                "</aws_best_practices>"
            )

        # --- Static analysis findings (do NOT re-report) ---
        static_summary = prompt_data.get("static_findings_summary", {})
        parts.append(
            "\nSTATIC ANALYSIS FINDINGS "
            "(already identified \u2014 do NOT re-report these):"
        )
        if static_summary:
            for category, info in static_summary.items():
                count = info.get("count", 0)
                parts.append(f"- {category}: {count} finding(s)")
        else:
            parts.append("(none)")

        # --- Best practice checker findings (do NOT re-report) ---
        bp_findings = prompt_data.get("best_practice_findings", [])
        parts.append(
            "\nBEST PRACTICE CHECKER FINDINGS "
            "(per-rule quality issues \u2014 do NOT re-report):"
        )
        if bp_findings:
            for bp in bp_findings:
                sid = bp.get("sid", "?")
                issues = bp.get("issues", [])
                issue_msgs = [
                    iss.get("message", "") for iss in issues if iss.get("message")
                ]
                parts.append(
                    f"- SID {sid}: {'; '.join(issue_msgs)}"
                )
        else:
            parts.append("(none)")

        # --- Output format ---
        parts.append(
            "\nOUTPUT FORMAT:\n"
            "Return a JSON object with exactly these keys: "
            "coverage_gaps, policy_coherence, optimizations, aws_advice. "
            "Each key maps to an array of finding objects.\n"
            "\n"
            "Each finding object MUST have:\n"
            '- severity: "critical" | "warning" | "info"\n'
            "  (critical = security bypass or rule failure,\n"
            "   warning = suboptimal behavior or potential issue,\n"
            "   info = suggestion or observation)\n"
            '- confidence: "high" | "medium" | "low"\n'
            "- description: Clear explanation of the finding\n"
            "- affected_sids: Array of SID numbers involved "
            "(empty array if N/A)\n"
            "- recommendation: Actionable fix or improvement\n"
            "- caveat: Contextual note if the recommendation may not "
            "apply universally\n"
            '  (e.g., "This may be intentional if you have a separate '
            'rule group for DNS")\n'
            "- reference: Reference to specific AWS best practices "
            "section if applicable"
        )

        # --- Analysis focus areas ---
        parts.append(
            "\nANALYSIS FOCUS AREAS:\n"
            "1. Coverage Gaps: Missing detection categories, blind spots, "
            "unmonitored protocols\n"
            "2. Policy Coherence: Contradictory actions, misaligned intent, "
            "unmonitored channels\n"
            "3. Optimizations: Rule consolidation, performance improvements, "
            "threshold usage\n"
            "4. AWS NFW Advice: Strict ordering assumptions, HOME_NET scope, "
            "flowbits coordination, TCP handshake pass rule, rule type "
            "processing order interactions"
        )

        # --- Rule type processing order context ---
        parts.append(
            "\nRULE TYPE PROCESSING ORDER CONTEXT:\n"
            "Suricata processes rules in this internal order regardless "
            "of file position:\n"
            "DEONLY \u2192 IPONLY \u2192 LIKE_IPONLY \u2192 PDONLY \u2192 PKT "
            "\u2192 PKT_STREAM \u2192 STREAM \u2192 APPLAYER \u2192 APP_TX\n"
            "An IPONLY pass rule will execute before an APP_TX reject rule "
            "even if the pass rule appears later in the file. Evaluate "
            "whether the rule type distribution creates unintended "
            "processing order interactions."
        )

        # --- AWS Network Firewall engine clarifications ---
        parts.append(
            "\nAWS NETWORK FIREWALL ENGINE CLARIFICATIONS:\n"
            "The following patterns are VALID in AWS Network Firewall's "
            "Suricata engine and must NOT be flagged as errors:\n"
            "- 'flow:to_server' is valid with 'ip' protocol rules. AWS "
            "Network Firewall's stateful engine tracks flow state for all "
            "protocols including IP. Rules like "
            "'alert ip $HOME_NET any -> any any (noalert; flowbits:set,"
            "egress_from_home_net; flow:to_server; sid:X;)' are a "
            "documented best practice for HOME_NET validation.\n"
            "- 'flow:to_server' is valid with 'icmp' protocol rules.\n"
            "- 'flowbits' combined with 'flow:to_server' on 'ip' protocol "
            "is a standard pattern for cross-rule state tracking.\n"
            "- GeoIP rules using 'ip' protocol with 'flow:to_server' are "
            "valid and documented.\n"
            "Do NOT report these as errors, warnings, or issues. They are "
            "correct AWS Network Firewall patterns shown in the grounding "
            "context above."
        )

        # --- Closing instruction ---
        parts.append(
            "\nReturn ONLY valid JSON. No markdown, no commentary "
            "outside the JSON."
        )

        return "\n".join(parts)

    def build_handoff_prompt(
        self,
        selected_findings: list,
        rules: list,
    ) -> str:
        """Build a focused prompt for the AI Rule Assistant from selected findings.

        Constructs a Finding_Handoff_Prompt containing only the selected
        findings and the specific rules they reference via ``affected_sids``.
        Unselected findings and unreferenced rules are excluded to stay
        within the AI Rule Assistant's context window limits.

        Args:
            selected_findings: The AnalysisFinding objects the user
                selected for handoff.
            rules: All SuricataRule objects in the editor.

        Returns:
            A human-readable prompt string for the AI Rule Assistant.
        """
        parts: list[str] = []

        # --- Header ---
        parts.append(
            "The following findings were identified by AI Deep Analysis of "
            "the user's Suricata ruleset. Please use these findings to "
            "generate or modify rules that address the issues described."
        )

        # --- Collect all unique SIDs referenced by selected findings ---
        referenced_sids: set[int] = set()
        for finding in selected_findings:
            for sid in finding.affected_sids:
                referenced_sids.add(sid)

        # --- Selected findings ---
        parts.append("\nSELECTED FINDINGS:")
        for finding in selected_findings:
            parts.append(f"\n[{finding.severity.upper()}] {finding.description}")
            if finding.affected_sids:
                sid_strs = [str(s) for s in finding.affected_sids]
                parts.append(f"  Affected SIDs: {', '.join(sid_strs)}")
            parts.append(f"  Recommendation: {finding.recommendation}")

        # --- Referenced rules ---
        # Build a SID-to-rule lookup from the full rule list
        sid_to_rule: dict[int, object] = {}
        for rule in rules:
            if hasattr(rule, "sid"):
                sid_to_rule[rule.sid] = rule

        referenced_rules = [
            sid_to_rule[sid]
            for sid in sorted(referenced_sids)
            if sid in sid_to_rule
        ]

        if referenced_rules:
            parts.append("\nREFERENCED RULES:")
            for rule in referenced_rules:
                parts.append(rule.to_string())

        # --- Placement guidance ---
        # Help the AI and the user understand where new rules should go
        # relative to the affected rules for correct evaluation order.
        if referenced_sids and referenced_rules:
            # Find the position of the last affected rule in the file
            last_sid = max(referenced_sids)
            last_rule_pos = None
            for i, rule in enumerate(rules):
                if hasattr(rule, "sid") and rule.sid == last_sid:
                    last_rule_pos = i + 1  # 1-based line number
                    break

            parts.append("\nPLACEMENT GUIDANCE:")
            parts.append(
                "IMPORTANT: In AWS Network Firewall strict evaluation order, "
                "rule position matters. New rules should be placed near the "
                "affected rules listed above for correct evaluation order."
            )
            if last_rule_pos is not None:
                parts.append(
                    f"The last affected rule (SID {last_sid}) is at line "
                    f"{last_rule_pos} in the ruleset. Consider placing new "
                    f"rules immediately after it."
                )

        return "\n".join(parts)

    def _build_user_message(self, prompt_data: dict) -> str:
        """Construct the user message containing the ruleset and context.

        The message includes the serialized rules with line numbers, rule
        variables, ruleset metadata (counts and distributions), and
        per-rule type annotations.

        Args:
            prompt_data: The dict returned by ``_assemble_prompt_data()``.

        Returns:
            The complete user message string.
        """
        parts: list[str] = []

        # --- Serialized rules with line numbers ---
        serialized_rules = prompt_data.get("serialized_rules", [])
        rule_count = len(serialized_rules)
        parts.append(f"RULESET ({rule_count} rules):")
        for line_num, rule_str in enumerate(serialized_rules, start=1):
            parts.append(f"{line_num}: {rule_str}")

        # --- Rule variables ---
        variables = prompt_data.get("variables", {})
        parts.append("\nRULE VARIABLES:")
        if variables:
            for var_name, var_def in variables.items():
                parts.append(f"{var_name}: {var_def}")
        else:
            parts.append("(none defined)")

        # --- Ruleset metadata ---
        metadata = prompt_data.get("metadata", {})
        total_count = metadata.get("total_count", 0)
        action_dist = metadata.get("action_distribution", {})
        protocol_dist = metadata.get("protocol_distribution", {})
        rule_type_dist = metadata.get("rule_type_distribution", {})

        parts.append("\nRULESET METADATA:")
        parts.append(f"- Total rules: {total_count}")

        # Action distribution
        action_parts = [f"{action}={count}" for action, count in action_dist.items()]
        parts.append(f"- Actions: {', '.join(action_parts) if action_parts else 'none'}")

        # Protocol distribution
        proto_parts = [f"{proto}={count}" for proto, count in protocol_dist.items()]
        parts.append(
            f"- Protocols: {', '.join(proto_parts) if proto_parts else 'none'}"
        )

        # Rule type distribution
        type_parts = [f"{rtype}={count}" for rtype, count in rule_type_dist.items()]
        parts.append(
            f"- Rule type distribution: "
            f"{', '.join(type_parts) if type_parts else 'none'}"
        )

        # --- Rule type annotations ---
        annotations = prompt_data.get("rule_type_annotations", {})
        if annotations:
            parts.append("\nRULE TYPE ANNOTATIONS:")
            for sid, rule_type in annotations.items():
                parts.append(f"Rule SID {sid}: {rule_type}")

        return "\n".join(parts)
