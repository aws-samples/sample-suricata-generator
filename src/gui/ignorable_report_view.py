"""Master-detail Static Analysis report view with a session-only ignore filter.

``IgnorableReportView`` replaces the former read-only ``tk.Text`` block in the
Static Analysis tab with a master-detail layout:

* a read-only Report Header as the top, user-resizable pane (draggable sash),
* a compact, capped ignored-rules section (shown only while something is
  ignored),
* a ``ttk.Treeview`` Findings Table (one row per finding, stretches), and
* a read-only Detail Pane (fixed height).

All hiding decisions route through the UI-free ``src.analysis.finding_filter``
module; the analyzer is never re-run and no rule/variable/file/AWS state is
touched (Req 9). The ignore set lives only on this view instance for the
lifetime of the open report window and is discarded when the window closes
(Req 5).

Windowing conventions (ui-conventions.md): no ``transient()``; cross-platform
copy (``<Control-c>`` + ``<Command-c>``) and mouse-wheel (``<MouseWheel>`` +
``<Button-4>``/``<Button-5>``) bindings; dark-mode detection via the project's
``AppleInterfaceStyle`` probe.
"""

from __future__ import annotations

import platform as _plat
import subprocess as _sp
import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional, Set

from src.analysis.finding_filter import (
    CategoryIdentity, FindingsDict, JumpTarget, RuleIdentity, compute_visible,
    display_group_name, first_rule_identity, jump_targets,
)
from src.analysis.finding_model import Category


def _detect_dark_mode() -> bool:
    """Return True when macOS is in dark mode (project convention).

    Uses the ``defaults read -g AppleInterfaceStyle`` probe. On Windows/Linux
    (or any failure) this returns False, so the light palette is used.
    """
    is_dark = False
    if _plat.system() == "Darwin":
        try:
            result = _sp.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True, text=True)
            is_dark = "Dark" in result.stdout
        except Exception:
            pass
    return is_dark


# The three Conflicts_Dict storage keys that physically back the single logical
# Rule_Shadowing category (its three Severities). Rows are populated from these
# keys in this order (critical -> warning -> info) so the merged "Rule
# Shadowing" group preserves that ordering within itself.
_RULE_SHADOWING_KEYS = ("critical", "warning", "info")
# The unified user-facing label for every Rule_Shadowing finding, and the
# logical category token (== Category.RULE_SHADOWING == 'rule_shadowing') that
# the view records in _iid_to_category and the filter ignores, so one
# CategoryIdentity hides all three severities in one action.
_RULE_SHADOWING_LABEL = "Rule Shadowing"
_RULE_SHADOWING_TOKEN = Category.RULE_SHADOWING

# Fixed Category_Order (design / Req 13.18): Protocol Layering, then the single
# Rule Shadowing group (populated from the critical/warning/info storage keys in
# that order), then the remaining specialized categories in today's order. Each
# entry maps a storage key to its human label; the three shadowing keys all
# resolve to "Rule Shadowing" via _display_category_label so the Category column
# never shows a severity word (Req 13.16).
_CATEGORY_ORDER = (
    ("protocol_layering", "Protocol Layering"),
    ("critical", "Critical"),
    ("warning", "Warning"),
    ("info", "Informational"),
    ("sticky_buffer_order", "Sticky Buffer Ordering"),
    ("udp_flow_established", "UDP flow:established"),
    ("protocol_keyword_mismatch", "Protocol/Keyword Mismatch"),
    ("port_protocol_mismatch", "Port/Protocol Mismatch"),
    ("port_on_portless_protocol", "Port on Portless Protocol"),
    ("contradictory_flow", "Contradictory Flow"),
    ("packet_drop_flow_pass", "Packet/Flow Action"),
    ("asymmetric_flow", "Asymmetric Flow"),
    ("reject_ip_protocol", "Reject-on-IP"),
    ("reject_quic_protocol", "Reject-on-QUIC"),
    ("unsupported_keywords", "Unsupported Keywords"),
    ("pcre_restrictions", "PCRE Restrictions"),
    ("threshold_limited", "Threshold"),
    ("priority_strict_order", "Priority-strict-order"),
)

# Severity indicator per category (Req 13.17). protocol_keyword_mismatch is
# mixed-severity and resolved per item from the finding's own `severity`.
_CATEGORY_SEV = {
    "protocol_layering": "🔄",
    "critical": "🚨",
    "warning": "⚠️",
    "info": "ℹ️",
    "sticky_buffer_order": "⚠️",
    "udp_flow_established": "⚠️",
    "port_protocol_mismatch": "ℹ️",
    "port_on_portless_protocol": "ℹ️",
    "contradictory_flow": "⚠️",
    "packet_drop_flow_pass": "⚠️",
    "asymmetric_flow": "⚠️",
    # The four AWS-critical categories render Critical body headers; their
    # fallback indicator is 🚨 so it agrees with the new Critical inventory for
    # a finding that lacks `sev` (harmless today only because _sev_indicator
    # reads `sev` first).
    "reject_ip_protocol": "🚨",
    "reject_quic_protocol": "🚨",
    "unsupported_keywords": "🚨",
    "pcre_restrictions": "🚨",
    "threshold_limited": "⚠️",
    "priority_strict_order": "⚠️",
}

# Map a Severity.value (or legacy severity string) to its Sev-column indicator.
_SEV_INDICATOR = {
    "critical": "🚨",
    "warning": "⚠️",
    "informational": "ℹ️",
    "info": "ℹ️",
}

# The line / rule-object field pairs per finding shape, first-side first.
_FIELD_PAIRS = (
    ("upper_line", "upper_rule"),
    ("lower_line", "lower_rule"),
    ("line", "rule"),
    ("line1", "rule1"),
    ("line2", "rule2"),
)
# First-side and second-side line fields (for Rule A / Rule B columns).
_FIRST_SIDE = ("upper_line", "line1", "line")
_SECOND_SIDE = ("lower_line", "line2")


class IgnorableReportView:
    """Master-detail Static Analysis view owning a per-window ignore set."""

    def __init__(
        self, parent, app,
        findings: FindingsDict, *,
        attribution: Optional[bool] = None,
        single_group_name: Optional[str] = None,
        report_header_text: str = "",
        policy_overview_text: Optional[str] = None,
        policy_findings_text: Optional[str] = None,
        policy_findings=None,
        on_counts_changed=None,
        group_files: Optional[Dict[str, Optional[str]]] = None,
        report_window=None,
    ) -> None:
        """Build the master-detail Static Analysis tab into ``parent``.

        ``app`` is the ``SuricataRuleGenerator`` (used only for dark-mode
        detection here; count helpers and export live in the orchestrator).
        ``findings`` is the analyzer's conflicts dict (never mutated).
        ``attribution`` selects multi-group rendering. ``report_header_text`` is
        today's header+body block (Req 15). ``policy_*`` carry the non-ignorable
        Review Firewall Policy region. ``on_counts_changed(filtered_findings)``
        lets the orchestrator refresh the status bar on every ignore-set change
        (Req 6.6).
        """
        self.parent = parent
        self.app = app
        self._findings = findings if findings is not None else {}
        self._attribution = attribution
        self._single_group_name = single_group_name
        self._report_header_text = report_header_text or ""
        self._policy_overview_text = policy_overview_text
        self._policy_findings_text = policy_findings_text
        self._policy_findings = policy_findings
        self._on_counts_changed = on_counts_changed
        # Jump-to-finding-rule context (jump-to-finding-rule feature). These two
        # are always passed together by show_analysis_report (both set, or both
        # default to None/empty); the menu-build gate also requires
        # self._report_window is not None so the invariant is self-enforcing.
        self._group_files = group_files or {}  # type: Dict[str, Optional[str]]
        self._report_window = report_window

        # Per-window ignore state — empty at construction (Req 5.3). Holds a
        # mix of RuleIdentity and CategoryIdentity markers (Req 20.3).
        self._ignore_set = set()  # type: Set[object]

        # Row bookkeeping for detach/reattach preserving order.
        self._iid_to_finding = {}   # type: Dict[str, Dict[str, object]]
        self._finding_to_iid = {}   # type: Dict[int, str]
        # Each row's analyzer category KEY, so the context menu can name the
        # clicked row's own category (Req 20.1).
        self._iid_to_category = {}  # type: Dict[str, str]
        self._iid_order = {}        # type: Dict[str, int]
        self._ordered_iids = []     # type: List[str]
        # Live hidden counts from the last compute_visible (Req 4.1). Keyed by
        # either kind of ignore entry (Req 20.4).
        self._hidden_counts = {}    # type: Dict[object, int]
        # The finding whose detail is currently shown in the Detail pane, or
        # None when the pane is empty. Tracked independently of the Treeview
        # selection because detaching a hidden row drops it from the selection
        # before _refresh_visibility can inspect it (Req 13.27, 13.28).
        self._detail_finding = None  # type: Optional[Dict[str, object]]

        self._is_dark = _detect_dark_mode()

        # The restore sub-dialog "landing" window (None until opened). Kept for
        # the reparent-children / _focus_landing windowing pattern.
        self._landing = None

        self._build_ui()
        # Prime the status bar once with today's counts (empty ignore set).
        self._notify_counts()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.container = ttk.Frame(self.parent)
        self.container.pack(fill=tk.BOTH, expand=True)
        # A vertical PanedWindow hosts the panes top->bottom: the Report_Header
        # (top), the ignored-rules section (added only while something is
        # ignored), and the findings-table frame (always present). The header
        # and the rest share a draggable sash, so dragging the header taller
        # reduces the findings-table height and vice versa. The detail pane
        # stays packed below the PanedWindow (fixed). It must exist before the
        # header, which is now parented to it.
        self._paned = ttk.PanedWindow(self.container, orient=tk.VERTICAL)
        self._paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True,
                         padx=10, pady=(0, 4))
        # Tracks whether the ignored pane is currently part of the PanedWindow.
        self._ignored_pane_added = False
        self._build_header()
        self._build_ignored_section()
        self._build_table()
        # The findings table dominates by default (larger weight), matching
        # today's look where the table absorbs the remaining space.
        try:
            self._paned.add(self._table_frame, weight=4)
        except tk.TclError:
            pass
        self._build_detail()
        self._populate_rows()
        self._apply_empty_state()

    def _build_header(self) -> None:
        """Render the Report_Header as the top, user-resizable pane of the
        vertical PanedWindow (Req 15, 16.4).

        The header no longer has a fixed height: it is the first pane, sharing a
        draggable sash with the rest, with its own vertical scrollbar and
        cross-platform mouse-wheel scrolling. The ``height`` below is only the
        INITIAL request — larger when the Review Firewall Policy overview/
        findings are present, modest otherwise — after which the sash governs
        the actual size.
        """
        # Use a plain tk.Frame (not ttk.Frame) for the header container so its
        # background can be set to the header tint explicitly; this keeps the
        # padding/scrollbar gutter the same shade as the Text, and renders
        # identically on Windows and macOS (ttk.Frame has no reliable cross-
        # platform bg option).
        bg, fg = self._header_palette()
        header_frame = tk.Frame(self._paned, bg=bg)
        # Initial height from the full assembled text (what the Text shows).
        # Policy path gets a taller default so the overview/findings are
        # visible without immediate scrolling; floor of 3 either way.
        line_count = self._header_full_text().count("\n") + 1
        if self._policy_overview_text or self._policy_findings_text:
            height = max(3, min(line_count, 17))
        else:
            height = max(3, min(line_count, 11))
        self._header_text = tk.Text(
            header_frame, wrap=tk.WORD, height=height,
            font=("Consolas", 9), bg=bg, fg=fg,
            relief=tk.FLAT, highlightthickness=0,
            padx=8, pady=6)
        hscroll = ttk.Scrollbar(header_frame, orient=tk.VERTICAL,
                                command=self._header_text.yview)
        self._header_text.configure(yscrollcommand=hscroll.set)
        self._header_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._header_text.insert(tk.END, self._header_full_text())
        self._make_read_only(self._header_text)
        self._bind_mousewheel(self._header_text, self._header_text)
        # Add the header as the FIRST (top) pane with a small weight so window
        # growth favors the findings table unless the user drags the sash.
        try:
            self._paned.add(header_frame, weight=1)
        except tk.TclError:
            pass

    def _header_full_text(self) -> str:
        """The header text, with the policy overview/findings prepended when
        this is the Review Firewall Policy path (Req 14.5)."""
        parts = []  # type: List[str]
        if self._policy_overview_text:
            parts.append(self._policy_overview_text)
        if self._policy_findings_text:
            parts.append(self._policy_findings_text)
        if parts:
            parts.append("=" * 70)
        parts.append(self._report_header_text)
        return "\n\n".join(p for p in parts if p)

    def _build_ignored_section(self) -> None:
        """Build the compact, capped ignored-rules section (Req 4, 16.6).

        Shown only while the ignore set is non-empty. It is rebuilt by
        ``_refresh_ignored_section`` on every ignore-set change.
        """
        self._ignored_frame = ttk.LabelFrame(self._paned, text="Ignored rules")
        # Not added to the PanedWindow yet — added/removed as a pane by
        # _refresh_ignored_section depending on the ignore set.
        self._ignored_inner = None

    def _refresh_ignored_section(self) -> None:
        """Repopulate the ignored-rules section from the current ignore set."""
        # Tear down any previous inner content.
        for child in list(self._ignored_frame.winfo_children()):
            try:
                child.destroy()
            except tk.TclError:
                pass

        if not self._ignore_set:
            # Remove the ignored pane while nothing is ignored (Req 4.6) so the
            # findings table occupies the full PanedWindow area as today. This
            # is idempotent: only forget it when it is currently present.
            if self._ignored_pane_added:
                try:
                    self._paned.forget(self._ignored_frame)
                except tk.TclError:
                    pass
                self._ignored_pane_added = False
            return

        # Add the ignored pane ABOVE the table pane but BELOW the header pane
        # (header, ignored, table, detail order). Index 1 keeps it below the
        # header pane at index 0. Idempotent: only add when not already present.
        # This pane gets a small weight so the table keeps dominating by
        # default; the sash can be dragged to reveal more ignored rows.
        self._ignored_frame.configure(
            text="Ignored rules ({count})".format(count=len(self._ignore_set)))
        if not self._ignored_pane_added:
            try:
                self._paned.insert(1, self._ignored_frame, weight=1)
            except tk.TclError:
                try:
                    self._paned.add(self._ignored_frame, weight=1)
                except tk.TclError:
                    pass
            self._ignored_pane_added = True

        # A capped, scrollable area. Use a Canvas + inner Frame so the list can
        # scroll past a modest maximum height (Req 4.8, 16.6).
        top_bar = ttk.Frame(self._ignored_frame)
        top_bar.pack(side=tk.TOP, fill=tk.X)
        restore_all = ttk.Button(top_bar, text="Restore all",
                                 command=self._restore_all)
        restore_all.pack(side=tk.RIGHT, padx=4, pady=2)

        canvas_holder = ttk.Frame(self._ignored_frame)
        # Fill the pane so dragging the sash down reveals more rows; the pane
        # height (not a fixed cap) now governs how much shows.
        canvas_holder.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        # A modest starting height so the sash begins near where the capped
        # section used to end; the canvas grows with the pane beyond this.
        start_height = 96
        canvas = tk.Canvas(canvas_holder, height=start_height,
                           highlightthickness=0)
        vscroll = ttk.Scrollbar(canvas_holder, orient=tk.VERTICAL,
                                command=canvas.yview)
        canvas.configure(yscrollcommand=vscroll.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)

        inner = ttk.Frame(canvas)
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_configure(_event=None):
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
                # Match inner width to the canvas so rows fill horizontally.
                canvas.itemconfig(inner_id, width=canvas.winfo_width())
            except tk.TclError:
                pass

        inner.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", _on_configure)
        self._bind_mousewheel(canvas, canvas)

        # Order both kinds of ignore entry for stable display: rule entries
        # first (today's ordering), then category entries sorted by human label
        # (Req 20.5).
        rule_entries = sorted(
            (e for e in self._ignore_set if isinstance(e, RuleIdentity)),
            key=lambda i: (display_group_name(i.group_name), i.in_group_line))
        category_entries = sorted(
            (e for e in self._ignore_set if isinstance(e, CategoryIdentity)),
            key=lambda e: self._display_category_label(e.category))
        ordered = list(rule_entries) + list(category_entries)
        multi = self._is_multi_group()
        for entry in ordered:
            row = ttk.Frame(inner)
            row.pack(side=tk.TOP, fill=tk.X, pady=1)
            count = self._hidden_counts.get(entry, 0)
            if isinstance(entry, CategoryIdentity):
                human_label = self._display_category_label(entry.category)
                label = "Category: {label}".format(label=human_label)
            elif multi:
                label = "{group} line {line}".format(
                    group=display_group_name(entry.group_name),
                    line=entry.in_group_line)
            else:
                label = "line {line}".format(line=entry.in_group_line)
            text = "{label}  \u2014  {count} findings hidden".format(
                label=label, count=count)
            ttk.Label(row, text=text, anchor=tk.W).pack(
                side=tk.LEFT, padx=(4, 0))
            # Bind entry via default arg to avoid late-binding closure bug.
            btn = ttk.Button(
                row, text="Restore",
                command=lambda ent=entry: self._restore_identity(ent))
            btn.pack(side=tk.RIGHT, padx=4)

    def _build_table(self) -> None:
        """Build the Findings_Table (ttk.Treeview) that stretches (Req 16.2)."""
        # Parented to the PanedWindow; added as the bottom pane in _build_ui.
        self._table_frame = ttk.Frame(self._paned)

        columns = ("category", "sev", "rule_a", "rule_b", "issue")
        self.tree = ttk.Treeview(
            self._table_frame, columns=columns, show="headings",
            selectmode="browse")
        self.tree.heading("category", text="Category")
        self.tree.heading("sev", text="Sev")
        self.tree.heading("rule_a", text="Rule A")
        self.tree.heading("rule_b", text="Rule B")
        self.tree.heading("issue", text="Issue")
        self.tree.column("category", width=140, stretch=False)
        self.tree.column("sev", width=40, anchor=tk.CENTER, stretch=False)
        self.tree.column("rule_a", width=130, stretch=False)
        self.tree.column("rule_b", width=130, stretch=False)
        self.tree.column("issue", width=360, stretch=True)

        vscroll = ttk.Scrollbar(self._table_frame, orient=tk.VERTICAL,
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=vscroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._apply_tree_dark_style()

        # Selection updates the detail pane.
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        # Clicking the already-selected row toggles it off (deselect), which
        # clears the Detail pane. A ttk.Treeview does not do this natively, so
        # we intercept the press, and only when it lands on the currently
        # selected row we deselect and swallow the event so the default handler
        # does not immediately re-select it.
        self.tree.bind("<Button-1>", self._on_tree_click)
        # Scrollbar + cross-platform mouse wheel.
        self._bind_mousewheel(self.tree, self.tree)
        # Context menu + keyboard ignore.
        self.tree.bind("<Button-3>", self._on_context_menu)
        self.tree.bind("<App>", self._on_context_menu_key)        # Windows menu key
        self.tree.bind("<Menu>", self._on_context_menu_key)       # some platforms
        self.tree.bind("<Shift-F10>", self._on_context_menu_key)
        self.tree.bind("<Delete>", self._on_delete_key)
        # Home / End jump to the first / last VISIBLE finding, select it, and
        # update the Detail pane (via the <<TreeviewSelect>> handler).
        self.tree.bind("<Home>", self._on_home_key)
        self.tree.bind("<End>", self._on_end_key)
        # Hover tooltip advertising the ignore action (Req 1.8).
        self._tooltip_state = {"window": None}
        self.tree.bind("<Motion>", self._on_row_hover, add="+")
        self.tree.bind("<Leave>", lambda e: self._hide_tooltip(), add="+")

        # Empty-state message label (shown instead of rows when appropriate).
        self._empty_label = ttk.Label(
            self._table_frame, anchor=tk.CENTER, justify=tk.CENTER,
            font=("TkDefaultFont", 11))

    def _build_detail(self) -> None:
        """Build the fixed-height read-only Detail_Pane (Req 13.2, 16.5)."""
        detail_frame = ttk.LabelFrame(self.container, text="Detail")
        detail_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0, 10))
        bg, fg = self._text_palette()
        self._detail_text_widget = tk.Text(
            detail_frame, wrap=tk.WORD, height=8, font=("Consolas", 9),
            bg=bg, fg=fg, relief=tk.FLAT, highlightthickness=0)
        dscroll = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL,
                                command=self._detail_text_widget.yview)
        self._detail_text_widget.configure(yscrollcommand=dscroll.set)
        self._detail_text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._make_read_only(self._detail_text_widget)
        self._bind_mousewheel(self._detail_text_widget, self._detail_text_widget)

    # ------------------------------------------------------------------
    # Row population + mapping
    # ------------------------------------------------------------------
    def _ordered_categories(self):
        """Yield (category_key, human_label) in Category_Order, for categories
        that actually have findings in this dataset."""
        for key, label in _CATEGORY_ORDER:
            items = self._findings.get(key)
            if items:
                yield key, label

    def _populate_rows(self) -> None:
        """Insert one row per finding, grouped by Category_Order, analyzer
        order within category (Req 13.18). Records each row ordinal.

        The three ``critical``/``warning``/``info`` storage keys are iterated in
        that order and rendered under the single "Rule Shadowing" label; each
        shadowing row records the unified ``rule_shadowing`` token in
        ``_iid_to_category`` so the context menu and category-ignore act on all
        three severities as one category. The other 14 keys record their own key
        unchanged."""
        ordinal = 0
        for key, label in self._ordered_categories():
            for finding in self._findings.get(key) or []:
                values = self._row_values(key, finding)
                iid = "f{index}".format(index=ordinal)
                self.tree.insert("", tk.END, iid=iid, values=values)
                self._iid_to_finding[iid] = finding
                self._finding_to_iid[id(finding)] = iid
                self._iid_to_category[iid] = self._category_token_for_key(key)
                self._iid_order[iid] = ordinal
                self._ordered_iids.append(iid)
                ordinal += 1

    @staticmethod
    def _category_token_for_key(key: str) -> str:
        """The logical category token recorded for a row stored under ``key``.

        The three shadowing storage keys collapse to the unified
        ``rule_shadowing`` token; every other key is its own token."""
        if key in _RULE_SHADOWING_KEYS:
            return _RULE_SHADOWING_TOKEN
        return key

    @staticmethod
    def _display_category_label(key_or_token: str) -> str:
        """Human Category label for a storage key OR the unified token.

        The three shadowing storage keys and the unified ``rule_shadowing``
        token all render as "Rule Shadowing" so the Category column (and the
        context menu + ignored-section) never shows a severity word for a
        shadowing finding. Every other key resolves via ``_CATEGORY_ORDER``."""
        if (key_or_token in _RULE_SHADOWING_KEYS
                or key_or_token == _RULE_SHADOWING_TOKEN):
            return _RULE_SHADOWING_LABEL
        return dict(_CATEGORY_ORDER).get(key_or_token, key_or_token)

    def _row_values(self, category: str, finding: dict) -> tuple:
        """Map a finding to the (Category, Sev, Rule A, Rule B, Issue) row."""
        label = self._display_category_label(category)
        sev = self._sev_indicator(category, finding)
        rule_a = self._field_ref(finding, _FIRST_SIDE)
        rule_b = self._field_ref(finding, _SECOND_SIDE)
        issue = ""
        if hasattr(finding, "get"):
            issue = str(finding.get("issue", "") or "")
        return (label, sev, rule_a, rule_b, issue)

    def _sev_indicator(self, category: str, finding: dict) -> str:
        """Return the severity/category indicator.

        Reads the Finding's per-Finding Severity (`sev`) FIRST so the Sev column
        reflects the two-axis model (e.g. a Protocol_Layering Informational row
        shows ℹ️, not 🔄). Falls back to the per-category `_CATEGORY_SEV` map (and
        the legacy per-item `protocol_keyword_mismatch` branch) only when a
        finding carries no `sev`.
        """
        if hasattr(finding, "get"):
            sev = finding.get("sev")
            value = getattr(sev, "value", None)
            if value is not None:
                return _SEV_INDICATOR.get(value, "ℹ️")
            # No `sev`: fall back to the legacy per-item/category indicators.
            if category == "protocol_keyword_mismatch":
                return "⚠️" if finding.get("severity") == "warning" else "ℹ️"
        return _CATEGORY_SEV.get(category, "ℹ️")

    def _field_ref(self, finding: dict, fields) -> str:
        """Group-qualified line reference for the first present field in
        ``fields``, using Display_Group_Name (Req 13.8-13.13). Blank when no
        such field is present (e.g. Rule B on a single-rule finding, Req 13.10).
        """
        if not hasattr(finding, "get"):
            return ""
        for field in fields:
            if field in finding and finding.get(field) is not None:
                return self._line_ref(finding, field)
        return ""

    def _line_ref(self, finding: dict, field: str) -> str:
        """Render one field as ``{DisplayGroup} line {N}`` (multi-group) or
        ``Line {N}`` (single-group), mirroring today's report phrasing."""
        line_value = finding.get(field)
        attr = self._attribution_for(finding, field)
        if attr is not None:
            group = getattr(attr, "group_name", None)
            in_group_line = getattr(attr, "in_group_line", line_value)
            if group is not None:
                return "{group} line {line}".format(
                    group=display_group_name(group), line=in_group_line)
        return "Line {line}".format(line=line_value)

    @staticmethod
    def _attribution_for(finding: dict, field: str):
        """Return the RuleAttribution for ``field`` from the finding's
        ``_attribution`` annotation, or None."""
        if not hasattr(finding, "get"):
            return None
        attr_data = finding.get("_attribution")
        if isinstance(attr_data, dict):
            refs = attr_data.get("refs")
            if isinstance(refs, dict):
                ref = refs.get(field)
                if isinstance(ref, dict):
                    return ref.get("attribution")
        return None

    # ------------------------------------------------------------------
    # Detail pane
    # ------------------------------------------------------------------
    def _on_tree_click(self, event):
        """Toggle selection: clicking the already-selected row deselects it and
        clears the Detail pane. Clicks on a different row or on empty space fall
        through to the native select behavior."""
        # Only a click on the row cell toggles; clicks on the heading or
        # separators are not row hits.
        try:
            region = self.tree.identify_region(event.x, event.y)
        except tk.TclError:
            region = "cell"
        if region not in ("cell", "tree"):
            return None
        iid = self.tree.identify_row(event.y)
        if not iid:
            return None
        if iid in self.tree.selection():
            # Deselect; <<TreeviewSelect>> fires and _on_select clears the
            # detail pane and _detail_finding. Swallow the event so the default
            # handler does not re-select the row.
            try:
                self.tree.selection_remove(iid)
            except tk.TclError:
                pass
            return "break"
        return None

    def _on_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            self._detail_finding = None
            self._set_detail("")
            return
        iid = selection[0]
        finding = self._iid_to_finding.get(iid)
        if finding is None:
            self._detail_finding = None
            self._set_detail("")
            return
        self._detail_finding = finding
        self._set_detail(self._detail_text(finding))

    def _detail_text(self, finding: dict) -> str:
        """Full, untruncated Issue / Rule A (or Rule) / Rule B / Action
        (Req 13.2-13.7). Rule text from ``_original_rule`` when present, else
        the finding's own rule object; never truncated; never the
        ``$g<idx>__`` form."""
        if not hasattr(finding, "get"):
            return ""
        lines = []  # type: List[str]
        issue = str(finding.get("issue", "") or "")
        lines.append("Issue:  {issue}".format(issue=issue))

        is_pairwise = ("upper_line" in finding or "line1" in finding)
        first_rule = self._rule_text(finding, ("upper_rule", "rule1", "rule"))
        if is_pairwise:
            lines.append("Rule A: {rule}".format(rule=first_rule))
            second_rule = self._rule_text(finding, ("lower_rule", "rule2"))
            lines.append("Rule B: {rule}".format(rule=second_rule))
        else:
            lines.append("Rule:   {rule}".format(rule=first_rule))

        lines.append("Action: {action}".format(action=self._action_text(finding)))
        return "\n".join(lines)

    def _rule_text(self, finding: dict, fields) -> str:
        """Resolve a rule's full text for the detail pane.

        Prefers the rule object's ``_original_rule`` back-reference (user-authored
        variables, no ``$g<idx>__`` namespace); falls back to the finding's own
        rule object; renders empty when neither is present (Req 13.5)."""
        rule_obj = None
        for field in fields:
            if hasattr(finding, "get") and finding.get(field) is not None:
                rule_obj = finding.get(field)
                break
        if rule_obj is None:
            return ""
        # Prefer the original (un-namespaced) rule when the analysis copy
        # carries the back-reference.
        original = getattr(rule_obj, "_original_rule", None)
        source = original if original is not None else rule_obj
        to_string = getattr(source, "to_string", None)
        if callable(to_string):
            try:
                return to_string()
            except Exception:
                return str(source)
        return str(source)

    def _action_text(self, finding: dict) -> str:
        """Group-aware action text for cross-group findings, else the stored
        suggestion verbatim (mirrors rule_analyzer._suggestion_text /
        _cross_group_suggestion, including the protocol-layering carve-out)."""
        if self._attribution and hasattr(finding, "get"):
            attr_data = finding.get("_attribution")
            if isinstance(attr_data, dict) and attr_data.get("cross_group"):
                severity = finding.get("severity")
                return self._cross_group_action(attr_data, severity)
        return str(finding.get("suggestion", "") or "") if hasattr(finding, "get") else ""

    @staticmethod
    def _cross_group_action(attr_data, severity=None) -> str:
        """Cross-group action text, matching rule_analyzer._cross_group_suggestion.

        For a protocol-layering (inter-type) finding, reordering the rule groups
        cannot change Suricata's type-based processing order, so advise
        constraining the higher-priority rule rather than a futile group move.
        For a shadowing finding (same rule-type) the group order genuinely
        decides, so keep the reorder advice."""
        refs = attr_data.get("refs", {}) if isinstance(attr_data, dict) else {}
        upper_attr = (refs.get("upper_line") or refs.get("line1") or {}).get("attribution")
        lower_attr = (refs.get("lower_line") or refs.get("line2") or {}).get("attribution")
        upper_name = getattr(upper_attr, "group_name", None) or "the earlier group"
        lower_name = getattr(lower_attr, "group_name", None) or "the later group"
        if severity == "protocol_layering":
            return (
                "Reordering the rule groups will not change this (Suricata "
                "processes rules by type, not group or file position); "
                "constrain the higher-priority rule in {upper} (add flow "
                "keywords, tighten its scope, or use a port-bearing protocol so "
                "it is no longer processed as IP-only ahead of the rule in "
                "{lower}), or leave as-is if the pre-emption is intended.".format(
                    upper=upper_name, lower=lower_name))
        return (
            "Ensure {lower} is evaluated before {upper} "
            "(move it higher in the list), or move the affected rule into an "
            "earlier group, so the intended rule takes effect.".format(
                lower=lower_name, upper=upper_name))

    def _set_detail(self, text: str) -> None:
        widget = self._detail_text_widget
        try:
            widget.config(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            if text:
                widget.insert(tk.END, text)
            self._lock_text(widget)
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Ignore / restore mechanics
    # ------------------------------------------------------------------
    def _ignore_identity(self, identity: RuleIdentity) -> None:
        """Add an identity to the ignore set and refresh (Req 1.4, 1.5).

        Re-ignoring an existing identity is a no-op (Req 1.7)."""
        if identity is None or identity in self._ignore_set:
            return
        self._ignore_set.add(identity)
        self._refresh_visibility()

    def _ignore_category(self, category_key: str) -> None:
        """Add a whole category to the ignore set and refresh (Req 20.1-20.3).

        Mirrors :meth:`_ignore_identity`: a ``CategoryIdentity`` is its own
        marker (adds no rules), and re-ignoring an already-ignored category is a
        no-op (Req 20.2)."""
        if category_key is None:
            return
        entry = CategoryIdentity(category_key)
        if entry in self._ignore_set:
            return
        self._ignore_set.add(entry)
        self._refresh_visibility()

    def _restore_identity(self, entry) -> None:
        """Remove one ignore entry (a RuleIdentity or CategoryIdentity) and
        reattach findings no longer matched (Req 4.4, 20.5)."""
        if entry not in self._ignore_set:
            return
        self._ignore_set.discard(entry)
        self._refresh_visibility()

    def _restore_all(self) -> None:
        """Empty the ignore set and reattach everything (Req 4.7)."""
        if not self._ignore_set:
            return
        self._ignore_set.clear()
        self._refresh_visibility()

    def _refresh_visibility(self) -> None:
        """Recompute visibility and detach/reattach rows preserving order.

        The analyzer is never invoked and the AI tab is never touched
        (Req 7.4, 9.4)."""
        visible, hidden_counts = compute_visible(
            self._findings, self._ignore_set, self._single_group_name)
        self._hidden_counts = hidden_counts

        # Build the set of currently-visible finding object ids.
        visible_ids = set()
        for items in visible.values():
            for finding in items:
                visible_ids.add(id(finding))

        # Detach hidden rows; reattach visible ones at their recorded ordinal.
        # We reattach in ascending ordinal order so relative order is preserved
        # (Req 13.19-13.21).
        for iid in self._ordered_iids:
            finding = self._iid_to_finding.get(iid)
            if finding is None:
                continue
            should_be_visible = id(finding) in visible_ids
            if should_be_visible:
                # Reattach at the correct position among currently-attached rows.
                self._reattach_in_order(iid)
            else:
                try:
                    self.tree.detach(iid)
                except tk.TclError:
                    pass

        # Clear the detail pane whenever the finding it is showing is no longer
        # visible (Req 13.27, 13.28). Keyed off the tracked displayed finding,
        # not the Treeview selection: detaching a hidden row already dropped it
        # from the selection, so an empty selection here does not mean the pane
        # is stale-free. Also drop any lingering selection on a now-hidden row.
        selection = self.tree.selection()
        for sel_iid in selection:
            sel_finding = self._iid_to_finding.get(sel_iid)
            if sel_finding is not None and id(sel_finding) not in visible_ids:
                try:
                    self.tree.selection_remove(sel_iid)
                except tk.TclError:
                    pass
        if (self._detail_finding is not None
                and id(self._detail_finding) not in visible_ids):
            self._detail_finding = None
            self._set_detail("")

        self._refresh_ignored_section()
        self._apply_empty_state()
        self._notify_counts()

    def _reattach_in_order(self, iid: str) -> None:
        """Move ``iid`` to its correct index among currently-attached rows so
        Category_Order + analyzer order is preserved."""
        target_ordinal = self._iid_order.get(iid, 0)
        # Find the insertion index: number of attached rows whose ordinal is
        # less than this row's ordinal.
        attached = self.tree.get_children("")
        index = 0
        for other in attached:
            if other == iid:
                continue
            if self._iid_order.get(other, 0) < target_ordinal:
                index += 1
        try:
            self.tree.move(iid, "", index)
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Empty states (Req 13.25, 13.26)
    # ------------------------------------------------------------------
    def _apply_empty_state(self) -> None:
        total_findings = sum(
            len(self._findings.get(k) or []) for k, _ in _CATEGORY_ORDER)
        visible_rows = len(self.tree.get_children(""))
        if visible_rows > 0:
            self._hide_empty_state()
            return
        if total_findings == 0:
            # Empty-state (a): no findings at all (matches today's text).
            message = ("\u2713 No rule conflicts detected. "
                       "Your rule ordering looks good!")
        else:
            # Empty-state (b): everything hidden by ignores (distinct message).
            message = ("All findings are currently hidden by ignored rules.\n"
                       "Use Restore above to bring findings back.")
        self._show_empty_state(message)

    def _show_empty_state(self, message: str) -> None:
        try:
            self.tree.pack_forget()
        except tk.TclError:
            pass
        self._empty_label.config(text=message)
        self._empty_label.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=20)

    def _hide_empty_state(self) -> None:
        try:
            self._empty_label.pack_forget()
        except tk.TclError:
            pass
        if not self.tree.winfo_ismapped():
            self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # ------------------------------------------------------------------
    # Context menu + keyboard
    # ------------------------------------------------------------------
    def _selected_finding(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self._iid_to_finding.get(selection[0])

    def _on_context_menu(self, event):
        # Select the row under the pointer first so the action targets it.
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
        self._show_context_menu(event.x_root, event.y_root)
        return "break"

    def _on_context_menu_key(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return "break"
        iid = selection[0]
        try:
            bbox = self.tree.bbox(iid)
            x = self.tree.winfo_rootx() + (bbox[0] + 10 if bbox else 10)
            y = self.tree.winfo_rooty() + (bbox[1] + 10 if bbox else 10)
        except tk.TclError:
            x = self.tree.winfo_rootx() + 10
            y = self.tree.winfo_rooty() + 10
        self._show_context_menu(x, y)
        return "break"

    def _show_context_menu(self, x_root, y_root):
        selection = self.tree.selection()
        if not selection:
            return
        iid = selection[0]
        finding = self._iid_to_finding.get(iid)
        if finding is None:
            return

        menu = tk.Menu(self.tree, tearoff=0)

        # Edit items first (navigation before acknowledgement, Req 2.4): one
        # per referenced rule whose group resolves to an on-disk file. The
        # two-part gate (file_path is not None AND report_window is not None)
        # enforces the "group_files and report_window always passed together"
        # invariant, so a non-actionable Edit item is never shown. Enumerating
        # ALL line fields means a second-side-only finding still gets its Edit
        # item even when first_rule_identity is None (Req 1.6).
        multi = self._is_multi_group()
        edit_added = False
        for target in jump_targets(
                finding, self._single_group_name, self._group_files):
            if target.file_path is None or self._report_window is None:
                continue
            if multi:
                label = "Edit {group} line {line}".format(
                    group=display_group_name(target.group_name),
                    line=target.in_group_line)
            else:
                label = "Edit line {line}".format(line=target.in_group_line)
            menu.add_command(
                label=label,
                command=lambda t=target: self._on_edit(t))
            edit_added = True

        # The existing rule-ignore of this row's First_Rule — still gated on a
        # resolvable first-side identity (unchanged behavior for that item), but
        # no longer an early return that would suppress the whole menu.
        identity = first_rule_identity(finding, self._single_group_name)
        category_key = self._iid_to_category.get(iid)
        ignore_items = identity is not None or category_key is not None

        if edit_added and ignore_items:
            menu.add_separator()

        if identity is not None:
            rule_label = "Ignore rule at {group} line {line}".format(
                group=display_group_name(identity.group_name),
                line=identity.in_group_line)
            menu.add_command(
                label=rule_label,
                command=lambda ident=identity: self._ignore_identity(ident))
        # Ignore the whole category — ONLY the clicked row's own category
        # (Req 20.1). Never lists other categories.
        if category_key is not None:
            category_label = self._display_category_label(category_key)
            cat_label = "Ignore all \"{label}\" findings".format(
                label=category_label)
            menu.add_command(
                label=cat_label,
                command=lambda key=category_key: self._ignore_category(key))

        # Nothing eligible at all -> do not pop up an empty menu.
        if not edit_added and not ignore_items:
            return

        try:
            menu.tk_popup(x_root, y_root)
        finally:
            menu.grab_release()

    def _on_edit(self, target) -> None:
        """Ask the app to jump to ``target``'s rule in the main editor.

        Guards the app / report-window references and swallows ``tk.TclError``
        so a destroyed widget never raises (jump-to-finding-rule feature)."""
        if not getattr(self, "app", None) or self._report_window is None:
            return
        try:
            self.app.jump_to_finding_rule(
                target.file_path, target.in_group_line, target.sid,
                self._report_window)
        except tk.TclError:
            pass

    def _on_delete_key(self, _event=None):
        """Delete ignores the selected row's First_Rule; no-op with no
        selection (Req 18.3, 18.4)."""
        finding = self._selected_finding()
        if finding is None:
            return "break"
        identity = first_rule_identity(finding, self._single_group_name)
        if identity is not None:
            self._ignore_identity(identity)
        return "break"

    # ------------------------------------------------------------------
    # Home / End navigation to first / last visible finding
    # ------------------------------------------------------------------
    def _on_home_key(self, _event=None):
        """Select the FIRST visible finding and update the Detail pane."""
        self._select_visible_edge("first")
        return "break"

    def _on_end_key(self, _event=None):
        """Select the LAST visible finding and update the Detail pane."""
        self._select_visible_edge("last")
        return "break"

    def _select_visible_edge(self, which):
        """Select the first or last currently-attached (visible) row, scroll it
        into view, and refresh the Detail pane. ``tree.get_children('')`` lists
        only attached rows, so ignored/hidden findings are skipped. A no-op when
        no rows are visible (e.g. an empty state)."""
        try:
            items = self.tree.get_children("")
        except tk.TclError:
            return
        if not items:
            return
        target = items[0] if which == "first" else items[-1]
        try:
            self.tree.selection_set(target)
            self.tree.focus(target)
            self.tree.see(target)
        except tk.TclError:
            return
        # Update the Detail pane directly; a programmatic selection_set may not
        # always emit <<TreeviewSelect>>, so drive _on_select explicitly.
        self._on_select()

    # ------------------------------------------------------------------
    # Hover tooltip (Req 1.8)
    # ------------------------------------------------------------------
    def _on_row_hover(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            self._hide_tooltip()
            return
        if self._tooltip_state["window"] is not None:
            return
        try:
            if not self.tree.winfo_exists():
                return
            x = self.tree.winfo_rootx() + event.x + 12
            y = self.tree.winfo_rooty() + event.y + 16
            tw = tk.Toplevel(self.tree)
            tw.wm_overrideredirect(True)
            tw.wm_geometry("+{x}+{y}".format(x=x, y=y))
            tk.Label(
                tw,
                text="Right-click a finding to ignore the rule it references",
                justify=tk.LEFT, background="#ffffe0",
                relief=tk.SOLID, borderwidth=1,
                font=("TkDefaultFont", 8)).pack()
            self._tooltip_state["window"] = tw
        except tk.TclError:
            self._tooltip_state["window"] = None

    def _hide_tooltip(self):
        tw = self._tooltip_state.get("window")
        if tw is not None:
            try:
                tw.destroy()
            except tk.TclError:
                pass
            self._tooltip_state["window"] = None

    # ------------------------------------------------------------------
    # Status-bar callback + exports
    # ------------------------------------------------------------------
    def _notify_counts(self) -> None:
        """Invoke the orchestrator's on_counts_changed with the visible set."""
        if self._on_counts_changed is None:
            return
        try:
            self._on_counts_changed(self.filtered_findings())
        except Exception:
            # Status-bar refresh must never break the view.
            pass

    def filtered_findings(self) -> FindingsDict:
        """Return conflicts with hidden findings removed.

        Returns the SAME object when the ignore set is empty so single-group
        exports stay byte-for-byte identical (Req 8.1). Otherwise a filtered
        copy."""
        if not self._ignore_set:
            return self._findings
        visible, _ = compute_visible(
            self._findings, self._ignore_set, self._single_group_name)
        return visible

    # ------------------------------------------------------------------
    # Helpers: dark mode, read-only, copy, mouse wheel
    # ------------------------------------------------------------------
    def _is_multi_group(self) -> bool:
        return bool(self._attribution)

    def _text_palette(self):
        if self._is_dark:
            return "#1E1E1E", "#E0E0E0"
        return "#FFFFFF", "#000000"

    def _header_palette(self):
        """(background, foreground) for the Report_Header region.

        The header is given a subtle background tint, distinct from the white
        (light) / near-black (dark) body used elsewhere, so the header reads as
        its own region instead of blending into the findings table and detail
        pane. Explicit hex values (not platform/theme color names) are used so
        the shade is byte-identical on Windows and macOS. In light mode this is
        a very light blue; in dark mode a slate slightly lighter than the body
        so the tint is visible without hurting contrast with the text.
        """
        if self._is_dark:
            return "#26303A", "#E0E0E0"
        return "#EAF2FB", "#000000"

    def _apply_tree_dark_style(self) -> None:
        """Apply the app's dark Treeview styling when in dark mode (Req 13.29)."""
        if not self._is_dark:
            return
        try:
            style = ttk.Style()
            style.configure(
                "Treeview", background="#1E1E1E", fieldbackground="#1E1E1E",
                foreground="#E0E0E0")
            style.configure(
                "Treeview.Heading", background="#333333", foreground="#E0E0E0")
        except tk.TclError:
            pass

    def _make_read_only(self, widget) -> None:
        """Make a Text widget read-only but selectable + copyable (Req 19)."""
        self._lock_text(widget)
        widget.bind("<Key>", lambda e: "break")
        widget.bind("<Button-1>", lambda e: widget.focus_set())
        self._bind_copy(widget)

    def _lock_text(self, widget) -> None:
        try:
            widget.config(state=tk.DISABLED)
        except tk.TclError:
            pass

    def _bind_copy(self, widget) -> None:
        def _copy(_event=None):
            try:
                sel = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                widget.clipboard_clear()
                widget.clipboard_append(sel)
            except tk.TclError:
                pass
            return "break"
        widget.bind("<Control-c>", _copy)
        widget.bind("<Command-c>", _copy)

    def _bind_mousewheel(self, widget, scrollable) -> None:
        """Bind cross-platform vertical mouse-wheel scrolling (ui-conventions)."""
        def _on_wheel(event):
            try:
                if event.num == 4:
                    scrollable.yview_scroll(-3, "units")
                elif event.num == 5:
                    scrollable.yview_scroll(3, "units")
                else:
                    scrollable.yview_scroll(
                        int(-1 * (event.delta / 120)), "units")
            except tk.TclError:
                pass
        widget.bind("<MouseWheel>", _on_wheel)
        widget.bind("<Button-4>", _on_wheel)
        widget.bind("<Button-5>", _on_wheel)

    # ------------------------------------------------------------------
    # Restore sub-dialog windowing helpers (reparent + focus, no transient)
    # ------------------------------------------------------------------
    def _dialog_parent(self):
        """Return the landing window if it exists, else the report window."""
        if self._landing is not None:
            try:
                if self._landing.winfo_exists():
                    return self._landing
            except tk.TclError:
                pass
        return self.parent

    def _focus_landing(self) -> None:
        """Return focus to the landing (or report) window after a child closes."""
        target = self._dialog_parent()
        try:
            target.lift()
            target.focus_force()
        except tk.TclError:
            pass
