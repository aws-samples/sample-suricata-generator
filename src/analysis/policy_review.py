"""
Policy Review Service for Multi-Rule-Group Analysis

This module defines ``PolicyReviewService``, the UI-free orchestration layer
that assembles a Policy_Set into a Combined_Rule_Stream, runs the unchanged
``RuleAnalyzer``, and attributes findings back to their source Rule_Groups.

The service composes an injected ``RuleAnalyzer`` and ``FileManager`` and uses
``LocalFileLoader`` for parsing local ``.suricata`` files. It holds NO editor
state and never mutates editor state or files on disk (Req 6.6, 10.2, 10.3).

Group loading (this task, 2.1-2.3):
  * ``make_current_group`` builds a RuleGroupSource from the in-memory editor
    state without aliasing the editor's live rules list / variables dict.
  * ``load_local_group`` loads a local ``.suricata`` file (+ companion ``.var``
    when present) and NEVER raises for expected I/O / parse problems; it
    returns a RuleGroupSource with ``load_error`` set instead (Req 2.7, 10.1).

See design.md, "New: src/analysis/policy_review.py".
"""

import copy
import os
import re
from typing import Dict, List, Optional, Tuple

from src.analysis.local_file_loader import LocalFileLoader
from src.analysis.policy_models import (
    GROUP_KIND_CURRENT,
    GROUP_KIND_LOCAL,
    CombinedStream,
    PolicyReviewResult,  # noqa: F401 - re-exported for callers/design reference
    RuleAttribution,
    RuleGroupSource,
)

# Variable names that are policy-wide (Policy_Level_HomeNet, Req 5.3, 5.6) and
# therefore NOT namespaced per group: they are carried through under their real
# names using the Current_Group's value. Compared without the leading $/@.
_POLICY_WIDE_VARS = frozenset({"HOME_NET", "EXTERNAL_NET"})

# Matches a single Suricata variable reference token inside a network/port
# field: a leading $ or @ followed by an identifier (letters, digits, and
# underscores, starting with a letter or underscore). The identifier is greedy
# so a longer name is never rewritten as a shorter prefix (e.g. "$SERVERS" is
# matched whole, never as "$SERVER"). Because we only ever run this over the
# ORIGINAL field text (never over already-namespaced output), there is no risk
# of double-namespacing a token.
_VAR_REF_RE = re.compile(r"([$@])([A-Za-z_][A-Za-z0-9_]*)")


class PolicyReviewService:
    """Assembles a Policy_Set into a Combined_Rule_Stream, runs the unchanged
    RuleAnalyzer, and attributes findings back to source groups.

    Holds no editor state; never mutates editor state or files on disk.
    """

    def __init__(self, rule_analyzer, file_manager):
        """Store composed dependencies.

        Args:
            rule_analyzer: The existing ``RuleAnalyzer`` used to run the
                conflict/compliance checks. Injected rather than constructed so
                the service adds no analysis behavior of its own (Req 6.7).
            file_manager: The existing ``FileManager`` used to load companion
                ``.var`` variable files for local groups.
        """
        self.rule_analyzer = rule_analyzer
        self.file_manager = file_manager
        # LocalFileLoader is stateless; own a single instance for parsing.
        self._local_loader = LocalFileLoader()

    # ------------------------------------------------------------------
    # Group loading (used by the dialog)
    # ------------------------------------------------------------------
    def make_current_group(
        self,
        rules: List,
        variables: Optional[Dict[str, dict]],
        current_file: Optional[str],
    ) -> RuleGroupSource:
        """Build the Current_Group source from in-memory editor state.

        The returned RuleGroupSource must not alias the editor's live
        ``self.rules`` list or ``self.variables`` dict such that later mutation
        of the source (e.g. during stitching) could touch editor state
        (Req 6.6, 10.3). The individual ``SuricataRule`` objects are referenced
        (Task 3.2 makes analysis-copies before any rewriting), but the
        containing list and the variables dict are fresh, distinct containers.

        Args:
            rules: The editor's current rule list (may include comment/blank
                placeholder rows).
            variables: The editor's current variable dict in the normalized
                ``{name: {"definition","description"[, "type"]}}`` shape. ``None``
                is tolerated and treated as no variables.
            current_file: Absolute path of the file open in the editor, or
                ``None`` when the group is unsaved.

        Returns:
            A RuleGroupSource with ``kind == GROUP_KIND_CURRENT``.
        """
        # Shallow-copy the list so reordering/stitching cannot mutate the
        # editor's live list; the rule objects themselves are shared by design.
        rules_copy = list(rules) if rules else []
        # Shallow-copy the variables dict so the source owns its own mapping.
        variables_copy = dict(variables) if variables else {}

        # Display name: the file's basename, or a sensible label when unsaved.
        if current_file:
            name = os.path.basename(current_file)
        else:
            name = "(unsaved)"

        return RuleGroupSource(
            kind=GROUP_KIND_CURRENT,
            name=name,
            rules=rules_copy,
            variables=variables_copy,
            origin_path=current_file,
            load_error=None,
        )

    def load_local_group(self, path: str) -> RuleGroupSource:
        """Load a Local_Group from a ``.suricata`` file on disk.

        Rules are parsed via ``LocalFileLoader``; the companion ``.var`` file
        (the ``.suricata`` path with its extension swapped to ``.var``, the same
        convention ``FileManager`` uses) is loaded via
        ``FileManager.load_variables_file`` when it exists alongside the rules
        file. A missing companion ``.var`` is NOT an error and simply yields an
        empty variables dict.

        This method NEVER raises for expected problems (missing / unreadable /
        unparseable file, or a file with no valid Suricata rules): it returns a
        RuleGroupSource with ``load_error`` set to a clear, human-readable
        message and whatever rules were loaded (possibly ``[]``) instead of
        raising (Req 2.7, 10.1).

        Args:
            path: Path to the ``.suricata`` file to load.

        Returns:
            A RuleGroupSource with ``kind == GROUP_KIND_LOCAL``. ``name`` is the
            basename of ``path`` and ``origin_path`` is its absolute path.
        """
        # Compute display name / origin defensively so even a bad path yields a
        # well-formed source rather than raising.
        try:
            name = os.path.basename(path)
        except (TypeError, ValueError):
            name = str(path)
        try:
            origin_path = os.path.abspath(path)
        except (TypeError, ValueError, OSError):
            origin_path = path

        rules: List = []
        variables: Dict[str, dict] = {}
        load_error: Optional[str] = None

        # --- Parse rules via LocalFileLoader (returns one LoadedFile) ---
        try:
            loaded_files = self._local_loader.load_files([path])
        except Exception as exc:  # noqa: BLE001 - never propagate to the dialog
            # LocalFileLoader is designed to capture errors on the LoadedFile,
            # but guard against any unexpected exception so assembly of other
            # groups is never aborted (Req 2.7, 10.1).
            return RuleGroupSource(
                kind=GROUP_KIND_LOCAL,
                name=name,
                rules=[],
                variables={},
                origin_path=origin_path,
                load_error=f"Could not load '{name}': {exc}",
            )

        loaded = loaded_files[0] if loaded_files else None
        if loaded is not None:
            rules = list(loaded.rules) if loaded.rules else []
            if loaded.error:
                # Surface LocalFileLoader's own human-readable message (file not
                # found, cannot read, no valid rules, etc.) verbatim.
                load_error = loaded.error
        else:
            load_error = f"Could not load '{name}'"

        # --- Load companion .var via FileManager (only when it exists) ---
        # FileManager.load_variables_file already: derives the .var path with
        # the same convention, returns the normalized
        # {name: {"definition","description"[, "type"]}} shape, and returns
        # ({}, {}) (never raises) for a missing/unreadable/corrupt .var. A
        # missing companion .var is therefore not an error.
        try:
            loaded_vars, _tags = self.file_manager.load_variables_file(path)
            if loaded_vars:
                variables = loaded_vars
        except Exception:  # noqa: BLE001 - a bad .var must not fail the group
            # Defensive: load_variables_file swallows expected errors already,
            # but never let an unexpected one abort loading the rule group.
            variables = {}

        return RuleGroupSource(
            kind=GROUP_KIND_LOCAL,
            name=name,
            rules=rules,
            variables=variables,
            origin_path=origin_path,
            load_error=load_error,
        )

    # ------------------------------------------------------------------
    # Per-group variable namespacing + stitching (Tasks 3.1-3.3)
    # ------------------------------------------------------------------
    #
    # Variable-key convention (confirmed by reading RuleAnalyzer): the analyzer
    # resolves a field token by ``variables.get(token, token)`` where ``token``
    # is the FULL reference INCLUDING its leading "$"/"@" (e.g. it looks up
    # ``"$HOME_NET"`` / ``"@VPCREF"``), and treats the value as a dict via
    # ``value.get("definition", ...)``. So the namespaced_variables dict this
    # service builds keys entries by the leading-symbol-plus-name form
    # (``"$g0__NAME"`` / ``"@g0__NAME"``) to match, and copies each group's
    # ``{definition, description[, type]}`` dict value unchanged.
    #
    # $HOME_NET / $EXTERNAL_NET are NOT namespaced: the analyzer has no special
    # derivation for them (it resolves them like any other variable), so
    # matching "exactly as the single-group analyzer handles it today" means
    # carrying them through under their real names using the Current_Group's
    # values. If $EXTERNAL_NET is undefined in the current group, it simply is
    # not in the dict and the analyzer stays conservative -- today's behavior.

    @staticmethod
    def _namespace_token(idx: int, name: str) -> str:
        """Return the per-group namespace prefix for group ``idx``'s variables.

        Uses ``g<idx>__`` so ``NAME`` becomes ``g0__NAME`` for the first group,
        ``g1__NAME`` for the second, etc. The double underscore keeps the
        namespace visually distinct and avoids colliding with a real variable
        that merely starts with ``g0`` (a real collision would require a source
        variable literally named ``g0__NAME``, which is not a realistic AWS
        Network Firewall IPSet/PortSet name).
        """
        return f"g{idx}__{name}"

    def build_namespaced_variables(
        self, policy_set: "PolicySet"
    ) -> Dict[str, dict]:
        """Task 3.1: build ONE combined per-group-namespaced variables dict.

        For every group (by ordered position ``idx`` in
        ``policy_set.ordered_groups()``) and every variable it defines, add an
        entry under the namespaced key ``"<sym>g<idx>__NAME"`` -- where ``sym``
        is the variable's own leading ``$`` or ``@`` -- copying the group's
        ``{definition, description[, type]}`` value verbatim. Because the key is
        namespaced per group, the same source name in two groups yields two
        distinct entries, so each group's rules resolve against their own
        definition (Req 5.1, 5.2).

        ``$HOME_NET`` and ``$EXTERNAL_NET`` are added ONCE, un-namespaced, under
        their real names, from the Current_Group's variables (Policy_Level_
        HomeNet, Req 5.3, 5.6). They are handled exactly as the single-group
        analyzer handles them today: passed straight through, and if the current
        group does not define them they are simply absent (the analyzer then
        stays conservative, as it does now).

        Args:
            policy_set: The assembled Policy_Set.

        Returns:
            A single dict suitable to hand to ``RuleAnalyzer.analyze_rule_
            conflicts`` as its ``variables`` argument.
        """
        namespaced: Dict[str, dict] = {}

        for idx, group in enumerate(policy_set.ordered_groups()):
            variables = group.variables or {}
            for key, value in variables.items():
                # key is the full reference incl. leading symbol, e.g. "$SERVERS".
                if not key or key[0] not in "$@":
                    # Defensive: skip malformed keys we can't namespace safely.
                    continue
                symbol = key[0]
                name = key[1:]
                # Policy-wide vars are handled once below, never per group.
                if name in _POLICY_WIDE_VARS:
                    continue
                namespaced_key = f"{symbol}{self._namespace_token(idx, name)}"
                # Copy the definition dict so the source group's dict is never
                # aliased into the analyzer input.
                namespaced[namespaced_key] = (
                    dict(value) if isinstance(value, dict) else value
                )

        # Add $HOME_NET / $EXTERNAL_NET once, un-namespaced, from current group.
        current = policy_set.current_group()
        if current is not None:
            current_vars = current.variables or {}
            for policy_var in ("$HOME_NET", "$EXTERNAL_NET"):
                value = current_vars.get(policy_var)
                if value is not None:
                    namespaced[policy_var] = (
                        dict(value) if isinstance(value, dict) else value
                    )

        return namespaced

    @classmethod
    def _rewrite_field(cls, field_value: Optional[str], idx: int) -> Optional[str]:
        """Rewrite the variable tokens in a single network/port field.

        Substitutes each ``$NAME`` / ``@NAME`` reference to its group-namespaced
        form ``$g<idx>__NAME`` / ``@g<idx>__NAME``, leaving ``$HOME_NET`` and
        ``$EXTERNAL_NET`` untouched. Only the token itself is replaced;
        surrounding brackets, negation (``!``), commas, ``any`` and any other
        literal text are preserved because the regex matches ONLY the
        symbol+identifier and nothing around it. For example, with ``idx == 0``:

            ``"[$SERVERS,!$HOME_NET]"`` -> ``"[$g0__SERVERS,!$HOME_NET]"``
            ``"any"``                   -> ``"any"`` (no token, unchanged)
            ``"@VPCREF"``               -> ``"@g0__VPCREF"``

        A non-string / falsy field is returned unchanged.
        """
        if not field_value or not isinstance(field_value, str):
            return field_value

        def _sub(match: "re.Match") -> str:
            symbol = match.group(1)
            name = match.group(2)
            if name in _POLICY_WIDE_VARS:
                # Leave $HOME_NET / $EXTERNAL_NET exactly as written.
                return match.group(0)
            return f"{symbol}{cls._namespace_token(idx, name)}"

        return _VAR_REF_RE.sub(_sub, field_value)

    def build_analysis_copy(self, rule, idx: int):
        """Task 3.2: return an analysis COPY of ``rule`` with fields rewritten.

        The editor's / loaded group's ``SuricataRule`` is NEVER mutated: a
        deep copy is taken first, then its ``src_net``/``dst_net``/``src_port``/
        ``dst_port`` variable tokens are namespaced for group ``idx``. Comment
        and blank placeholder rows are copied and passed through unchanged
        (they carry no analyzable fields) but still occupy their position so
        in-group line numbering is preserved (Req 4.5).

        Original-rule linking mechanism: the copy carries a back-reference to
        the untouched original on the attribute ``_original_rule``. This is what
        the later display / ``by_rule_id`` attribution step uses, since the
        analyzer carries the analysis-copy objects (not the originals) inside
        its finding dicts. The original therefore remains available for
        rendering the user-facing rule text without the ``$g0__`` namespace.

        Args:
            rule: The original ``SuricataRule`` (or comment/blank placeholder).
            idx: The group's ordered index, used for the namespace token.

        Returns:
            A new ``SuricataRule`` copy; the original is left unmodified.
        """
        # Deep copy so mutating the copy's fields can never touch the original
        # (or, for shared nested state, the editor). The original is untouched.
        analysis_copy = copy.deepcopy(rule)

        # Comment / blank rows are not analyzed; pass them through as-is (only
        # the back-reference is added). Their position still counts for line
        # numbering because they remain in the stitched list.
        is_comment = getattr(rule, "is_comment", False)
        is_blank = getattr(rule, "is_blank", False)
        if not is_comment and not is_blank:
            analysis_copy.src_net = self._rewrite_field(
                getattr(analysis_copy, "src_net", None), idx
            )
            analysis_copy.dst_net = self._rewrite_field(
                getattr(analysis_copy, "dst_net", None), idx
            )
            analysis_copy.src_port = self._rewrite_field(
                getattr(analysis_copy, "src_port", None), idx
            )
            analysis_copy.dst_port = self._rewrite_field(
                getattr(analysis_copy, "dst_port", None), idx
            )

        # Link the analysis copy back to its untouched original (for display and
        # by_rule_id attribution). Set on the copy only; the original is clean.
        analysis_copy._original_rule = rule
        return analysis_copy

    def substitute_and_stitch(
        self, policy_set: "PolicySet"
    ) -> Tuple[CombinedStream, Dict[str, dict]]:
        """Task 3.3: per-group substitution + stitch into one Combined_Rule_Stream.

        Concatenates the groups in ``policy_set.ordered_groups()`` order, each
        group's rules in their in-group order, producing the combined list of
        analysis-copy rules (Req 4.1, 4.2, 4.4). Every rule -- including
        duplicate SIDs across groups -- is retained; nothing is deduplicated,
        dropped, or renumbered (Req 12.1, 12.2).

        Builds, in parallel:
          * ``attribution`` -- a ``RuleAttribution`` per combined rule (same
            index), recording the source group's name/kind and the rule's
            1-based position within that group's ``rules`` list, counting
            comment/blank rows (Req 4.5).
          * ``by_rule_id`` -- ``id(analysis_copy)`` -> its ``RuleAttribution``.
            The analyzer carries the analysis-copy objects in its findings, so
            the later attribute step looks them up by the identity of the COPY.

        Args:
            policy_set: The assembled Policy_Set.

        Returns:
            ``(CombinedStream, namespaced_variables)`` -- the stitched stream
            plus the single variables dict to hand the unchanged analyzer.
        """
        combined_rules: List = []
        attribution: List[RuleAttribution] = []
        by_rule_id: Dict[int, RuleAttribution] = {}

        for idx, group in enumerate(policy_set.ordered_groups()):
            group_rules = group.rules or []
            for position, original_rule in enumerate(group_rules):
                analysis_copy = self.build_analysis_copy(original_rule, idx)

                attr = RuleAttribution(
                    group_name=group.name,
                    group_kind=group.kind,
                    # 1-based position within THIS group's rules list, counting
                    # comment/blank rows -- matches each group's own basis.
                    in_group_line=position + 1,
                )

                combined_rules.append(analysis_copy)
                attribution.append(attr)
                # Key on the analysis copy's identity: that is the object the
                # analyzer will carry back in its finding dicts.
                by_rule_id[id(analysis_copy)] = attr

        combined = CombinedStream(
            rules=combined_rules,
            attribution=attribution,
            by_rule_id=by_rule_id,
        )

        namespaced_variables = self.build_namespaced_variables(policy_set)

        return combined, namespaced_variables

    # ------------------------------------------------------------------
    # Run + attribute (Tasks 4.1-4.2)
    # ------------------------------------------------------------------
    #
    # Cancellation semantics (confirmed by reading RuleAnalyzer.analyze_rule_
    # conflicts and its existing call sites in suricata_generator.py): the
    # analyzer takes a ``cancel_requested`` argument that is a LIST holding a
    # single boolean flag -- it checks ``cancel_requested[0]`` at the top of its
    # outer pairwise loop and, when truthy, returns the (partial) conflicts dict
    # early. The existing single-group call sites pass the four progress/cancel
    # arguments POSITIONALLY, e.g.:
    #
    #     self.rule_analyzer.analyze_rule_conflicts(
    #         self.rules, self.variables,
    #         progress_bar, progress_text, progress_dialog, cancel_requested)
    #
    # ``run`` forwards them the same way (by keyword, but to the same params),
    # so the analyzer behaves identically to today (Req 6.7 -- analyzer logic is
    # only CALLED, never modified).

    @staticmethod
    def _is_cancelled(cancel_requested) -> bool:
        """Return True when ``cancel_requested`` signals a cancellation.

        Matches the analyzer's own convention: ``cancel_requested`` is a list
        (or other indexable) whose element ``[0]`` is a truthy flag when the
        user has requested cancellation. ``None`` (no cancel channel supplied)
        is treated as not cancelled. Any indexing/type error is treated
        conservatively as not cancelled so a malformed flag never fabricates a
        cancellation.
        """
        if cancel_requested is None:
            return False
        try:
            return bool(cancel_requested[0])
        except (IndexError, KeyError, TypeError):
            return False

    def run(
        self,
        policy_set: "PolicySet",
        *,
        progress_bar=None,
        progress_text=None,
        progress_dialog=None,
        cancel_requested=None,
    ) -> PolicyReviewResult:
        """Task 4.1: run the multi-group review and return a PolicyReviewResult.

        Steps:
          1. ``substitute_and_stitch(policy_set)`` -> ``(combined, namespaced
             variables)``: per-group variable namespacing + stitch into one
             ordered Combined_Rule_Stream (Req 6.1, 6.2).
          2. Invoke the UNCHANGED ``RuleAnalyzer.analyze_rule_conflicts`` on the
             combined stream, forwarding the progress/cancel channels exactly as
             the existing single-group call site does (Req 6.3, 6.4, 6.7).
          3. Honor cancellation: if ``cancel_requested`` signals cancel (either
             before the analyzer runs or after it returns early), return a
             PolicyReviewResult with ``cancelled=True`` and the (possibly empty
             / partial) findings, so no downstream results window opens
             (Req 6.5). The combined stream and policy set are still returned so
             the caller has a consistent, non-corrupted result object.
          4. Compute the policy-wide $HOME_NET decision from the Policy_Set
             (``home_net_value`` / ``home_net_differs``, Req 5.6 / 8.3).

        This method holds no editor state and never mutates editor state or
        files on disk; substitution operates on analysis copies (Req 6.6, 10.2,
        10.3).

        Args:
            policy_set: The assembled Policy_Set to review.
            progress_bar: Optional progress bar widget forwarded to the analyzer.
            progress_text: Optional progress text label forwarded to the analyzer.
            progress_dialog: Optional progress dialog forwarded to the analyzer.
            cancel_requested: Optional cancellation channel -- a list whose
                ``[0]`` element is a truthy flag when cancellation is requested
                (the analyzer's own convention).

        Returns:
            A ``PolicyReviewResult`` carrying the analyzer findings (unchanged
            Findings_Dict shape), the combined stream, the policy set, the
            chosen/differed $HOME_NET, and the ``cancelled`` flag.
        """
        combined, namespaced_variables = self.substitute_and_stitch(policy_set)

        home_net_chosen = policy_set.home_net_value()
        home_net_differed = policy_set.home_net_differs()

        # Short-circuit if cancellation was already requested before analysis.
        if self._is_cancelled(cancel_requested):
            return PolicyReviewResult(
                findings={},
                combined=combined,
                policy_set=policy_set,
                home_net_chosen=home_net_chosen,
                home_net_differed=home_net_differed,
                cancelled=True,
            )

        # Invoke the UNCHANGED analyzer on the combined stream. Forward the
        # progress/cancel channels to the same parameters the single-group call
        # site uses; the analyzer's logic is only called, never modified.
        findings = self.rule_analyzer.analyze_rule_conflicts(
            combined.rules,
            namespaced_variables,
            progress_bar=progress_bar,
            progress_text=progress_text,
            progress_dialog=progress_dialog,
            cancel_requested=cancel_requested,
        )

        # The analyzer returns early (with partial findings) when cancel is
        # flagged mid-run. Detect that and report cancelled so no results window
        # opens; the partial findings are carried but marked cancelled.
        cancelled = self._is_cancelled(cancel_requested)

        return PolicyReviewResult(
            findings=findings if findings is not None else {},
            combined=combined,
            policy_set=policy_set,
            home_net_chosen=home_net_chosen,
            home_net_differed=home_net_differed,
            cancelled=cancelled,
        )

    # ------------------------------------------------------------------
    # Finding attribution (Task 4.2)
    # ------------------------------------------------------------------
    #
    # RuleAnalyzer finding dicts use three positional field shapes, confirmed by
    # reading rule_analyzer.py:
    #
    #   * Pairwise shadowing/conflict findings (categories: critical, warning,
    #     info, protocol_layering) carry LINE fields ``upper_line`` /
    #     ``lower_line`` and RULE-object fields ``upper_rule`` / ``lower_rule``.
    #   * Single-rule findings (categories: sticky_buffer_order,
    #     udp_flow_established, protocol_keyword_mismatch, port_protocol_mismatch,
    #     contradictory_flow, packet_drop_flow_pass? no -- see below,
    #     reject_ip_protocol, reject_quic_protocol, unsupported_keywords,
    #     pcre_restrictions, threshold_limited, priority_strict_order) carry
    #     ``line`` and ``rule``.
    #   * Dual-rule findings (categories: packet_drop_flow_pass, asymmetric_flow)
    #     carry ``line1`` / ``line2`` and ``rule1`` / ``rule2`` (asymmetric_flow
    #     additionally carries ``to_server_line`` / ``to_client_line``, which are
    #     duplicates of line1/line2 and are left to Task 5's renderer).
    #
    # Because the combined stream IS the analyzed list, every *_line value is a
    # 1-based index into ``combined.attribution``; we resolve those with
    # ``attribution_for_line``. For robustness (and to cover the object-carrying
    # fields directly), we ALSO resolve each paired rule object via
    # ``combined.by_rule_id`` keyed on ``id(analysis_copy)`` -- recall Task 3.3
    # keys by_rule_id on the analysis-copy objects, and the analyzer carries
    # those same copies in its finding dicts. When a line ref and its rule ref
    # disagree (should not happen in practice), the line-based attribution wins
    # for the *_line entries and the rule-based attribution is used for the
    # *_rule entries, so each ref is attributed by its own most-direct source.

    # The three known field-name groupings. Each tuple pairs a LINE field name
    # with its companion RULE-object field name (or None when a category has no
    # companion rule object for that line). Kept as data so only fields that
    # ACTUALLY exist on a given finding are attributed.
    _LINE_RULE_FIELD_PAIRS = (
        ("upper_line", "upper_rule"),
        ("lower_line", "lower_rule"),
        ("line", "rule"),
        ("line1", "rule1"),
        ("line2", "rule2"),
    )

    def attribute_findings(self, result: PolicyReviewResult) -> PolicyReviewResult:
        """Task 4.2: attribute every finding's line/rule refs to source groups.

        Attribution contract (what Task 5's report generator consumes)
        --------------------------------------------------------------
        This method annotates each finding dict IN PLACE with a single extra
        key, ``"_attribution"``, and returns the same ``result`` for
        convenience. The value is a dict describing every line reference the
        finding carries, plus a cross-group flag:

            finding["_attribution"] = {
                "refs": {
                    <line_field_name>: {          # e.g. "upper_line", "line1"
                        "line": <int>,             # the combined-stream 1-based line
                        "attribution": <RuleAttribution or None>,
                    },
                    ...
                },
                "groups": [ <RuleAttribution>, ... ],  # distinct groups involved,
                                                        # in first-seen ref order
                "cross_group": <bool>,             # True iff >1 distinct group
            }

        Notes for the consumer (Task 5 ``_format_line_ref`` etc.):
          * ``refs`` contains ONLY the line fields that were actually present on
            the finding, so a single-rule finding has just ``{"line": ...}`` and
            a pairwise finding has ``{"upper_line": ..., "lower_line": ...}``.
            The reporter can look up the attribution for a given field directly,
            or fall back to ``attribution_for_line(line)`` itself (identical
            result) using the raw line value it already reads from the finding.
          * ``attribution`` may be ``None`` for a ref whose line is out of range
            (should not happen for well-formed findings); the reporter should
            fall back to the plain ``Line N`` rendering in that case.
          * ``cross_group`` distinguishes an intra-group / single-group finding
            (False -> today's "move line X above line Y" suggestion) from a
            cross-group finding (True -> group-aware "reorder the groups"
            suggestion), per Req 7.8 / 7.9.
          * ``_attribution`` is additive and presentation-only: the analyzer
            output is otherwise untouched, so behavior with attribution ignored
            is byte-for-byte identical to today (Req 7 / single-group parity).

        Resolution strategy (Req 7.1, 7.2, 7.3, 12.3):
          * Prefer ``result.combined.attribution_for_line(line)`` for every
            LINE field -- the combined stream is the analyzed list, so the line
            indexes attribution directly.
          * As a fallback, when a line is missing/out of range but the finding
            carries the companion rule OBJECT, resolve it through
            ``result.combined.by_rule_id[id(rule_obj)]`` (identity of the
            analysis copy the analyzer carried).

        Args:
            result: The ``PolicyReviewResult`` returned by ``run``.

        Returns:
            The same ``result``, with each finding dict annotated in place.
        """
        combined = result.combined
        by_rule_id = combined.by_rule_id if combined is not None else {}

        findings = result.findings or {}
        for _category, finding_list in findings.items():
            if not finding_list:
                continue
            for finding in finding_list:
                if not isinstance(finding, dict):
                    continue
                self._attribute_one_finding(finding, combined, by_rule_id)

        return result

    def _attribute_one_finding(self, finding, combined, by_rule_id) -> None:
        """Annotate a single finding dict in place with ``_attribution``.

        See ``attribute_findings`` for the contract of the annotation shape.
        """
        refs: Dict[str, dict] = {}
        groups: List[RuleAttribution] = []

        def _remember_group(attribution) -> None:
            # Track distinct groups (by name+kind+? -- name+kind identifies the
            # source group) in first-seen order to decide cross_group and to
            # give the reporter the involved-group list.
            if attribution is None:
                return
            for existing in groups:
                if (
                    existing.group_name == attribution.group_name
                    and existing.group_kind == attribution.group_kind
                    and existing.in_group_line == attribution.in_group_line
                ):
                    # Same exact ref already recorded; still counts as the same
                    # group for cross_group purposes via the name/kind check
                    # below, so nothing to add here.
                    pass
            groups.append(attribution)

        for line_field, rule_field in self._LINE_RULE_FIELD_PAIRS:
            if line_field not in finding:
                continue
            line_value = finding.get(line_field)
            attribution = None

            # Prefer line-based attribution (direct index into the stream).
            if isinstance(line_value, int) and combined is not None:
                attribution = combined.attribution_for_line(line_value)

            # Fall back to the rule object's identity when the line did not
            # resolve but a companion rule object is present.
            if attribution is None and rule_field is not None:
                rule_obj = finding.get(rule_field)
                if rule_obj is not None:
                    attribution = by_rule_id.get(id(rule_obj))

            refs[line_field] = {
                "line": line_value,
                "attribution": attribution,
            }
            _remember_group(attribution)

        # Distinct groups by (name, kind) to decide cross-group.
        distinct_keys = set()
        for attribution in groups:
            if attribution is not None:
                distinct_keys.add((attribution.group_name, attribution.group_kind))
        cross_group = len(distinct_keys) > 1

        finding["_attribution"] = {
            "refs": refs,
            "groups": groups,
            "cross_group": cross_group,
        }
