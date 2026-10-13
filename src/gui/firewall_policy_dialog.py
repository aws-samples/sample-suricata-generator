"""
Review Firewall Policy dialog for the "Review Firewall Policy" feature.

This module defines ``FirewallPolicyDialog``, the tkinter window that lets a user
pick a live AWS Network Firewall firewall policy, review its overview, evaluate
the analyzability gates, fetch the customer-owned Suricata rule groups, and
return ``(PolicyFacts, PolicySet)`` on Analyze. It is a THIN driver over the
UI-free AWS ingestion layer (``src/aws/firewall_policy_api.py``): all AWS logic
(``list_firewall_policies``, ``describe_policy_facts``, ``fetch_customer_group``,
``FirewallPolicyApiError``) lives there; this dialog only drives it, renders the
facts, applies the gates, and assembles the result. It never mutates editor,
disk, or AWS state.

Testing note (design.md, Testing Strategy): this file is UI (tkinter) and is NOT
unit-tested headlessly. The testable core lives in the UI-free
``firewall_policy_api`` / ``policy_facts`` / ``policy_models`` modules. All Tk
objects are created only in ``__init__`` / instance methods, so importing this
module never initializes Tk and needs no display.

Cross_Platform_UI_Guidelines followed (see .kiro/steering/ui-conventions.md):
  * No ``transient()`` call anywhere (the app's global macOS monkey-patch makes
    it a no-op on Darwin; we simply never call it).
  * ``resizable(True, True)`` + ``minsize(...)`` so every control stays visible
    at the smallest supported size.
  * Action buttons (Analyze / Close) packed ``side=tk.BOTTOM`` BEFORE the
    content area, so they can never be pushed off-screen (rule 5).
  * The scrollable Treeview containers are packed with ``expand=False``
    (Cross-Platform Layout rule 1) so they cannot consume all vertical space on
    macOS and push the buttons off-screen. Each Treeview is given a sensible
    fixed ``height`` (in rows) instead.
  * Mouse-wheel bindings on the Treeviews for Windows/Linux (<MouseWheel>) and
    macOS (<Button-4>/<Button-5>).
  * Dual Control/Command copy bindings on the Treeviews (copies the selected
    row's text) for Windows and macOS.
  * Dark-mode palette selected via the project's AppleInterfaceStyle detection
    pattern (ai_assistant_panel.py), not hardcoded single-mode colors.

See .kiro/specs/analyze-firewall-policy requirements 2-5, 7, 13.
"""

from __future__ import annotations

import platform as _plat
import subprocess as _sp
import tkinter as tk
from tkinter import messagebox, ttk
from typing import List, Optional, Tuple

from src.aws.firewall_policy_api import (
    FirewallPolicyApiError,
    describe_policy_facts,
    fetch_customer_group,
    list_firewall_policies,
)
from src.analysis.policy_facts import (
    FORMAT_DOMAIN_LIST,
    FORMAT_STANDARD,
    FORMAT_SURICATA,
    FORMAT_UNKNOWN,
    PolicyFacts,
)
from src.analysis.policy_models import PolicySet, RuleGroupSource
from src.gui.policy_findings_render import (
    _default_actions_display,
    _home_net_display,
    _name_cell,
    _owner_label,
    _priority_cell,
    _rule_order_note,
    _rules_cell,
    _stateless_note,
    format_policy_overview_text,
)


# All AWS standard commercial regions (excludes China and GovCloud). Mirrored
# verbatim from stateful_rule_importer.py AWSRuleGroupBrowser.aws_regions.
AWS_REGIONS = [
    # US Regions
    'us-east-1',      # US East (N. Virginia)
    'us-east-2',      # US East (Ohio)
    'us-west-1',      # US West (N. California)
    'us-west-2',      # US West (Oregon)
    # Canada Regions
    'ca-central-1',   # Canada (Central)
    'ca-west-1',      # Canada (Calgary)
    # Europe Regions
    'eu-west-1',      # Europe (Ireland)
    'eu-west-2',      # Europe (London)
    'eu-west-3',      # Europe (Paris)
    'eu-central-1',   # Europe (Frankfurt)
    'eu-central-2',   # Europe (Zurich)
    'eu-north-1',     # Europe (Stockholm)
    'eu-south-1',     # Europe (Milan)
    'eu-south-2',     # Europe (Spain)
    # Asia Pacific Regions
    'ap-south-1',     # Asia Pacific (Mumbai)
    'ap-south-2',     # Asia Pacific (Hyderabad)
    'ap-southeast-1', # Asia Pacific (Singapore)
    'ap-southeast-2', # Asia Pacific (Sydney)
    'ap-southeast-3', # Asia Pacific (Jakarta)
    'ap-southeast-4', # Asia Pacific (Melbourne)
    'ap-northeast-1', # Asia Pacific (Tokyo)
    'ap-northeast-2', # Asia Pacific (Seoul)
    'ap-northeast-3', # Asia Pacific (Osaka)
    'ap-east-1',      # Asia Pacific (Hong Kong)
    # South America Regions
    'sa-east-1',      # South America (São Paulo)
    # Middle East Regions
    'me-south-1',     # Middle East (Bahrain)
    'me-central-1',   # Middle East (UAE)
    # Africa Regions
    'af-south-1',     # Africa (Cape Town)
    # Israel Regions
    'il-central-1',   # Israel (Tel Aviv)
]

# Human-readable labels for the Suricata-format gate's offender messages.
_FORMAT_LABELS = {
    FORMAT_SURICATA: "Suricata",
    FORMAT_DOMAIN_LIST: "Domain allow/deny list",
    FORMAT_STANDARD: "Standard stateful rules",
    FORMAT_UNKNOWN: "Unknown / not fetched",
}


def _detect_dark_mode() -> bool:
    """Return True when macOS is in dark mode.

    Uses the project's established detection pattern (ai_assistant_panel.py):
    only Darwin is probed; any failure falls back to light mode. On Windows and
    Linux this returns False, so the light palette is used.
    """
    is_dark = False
    if _plat.system() == "Darwin":
        try:
            result = _sp.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True,
                text=True,
            )
            is_dark = "Dark" in result.stdout
        except Exception:
            pass
    return is_dark


class FirewallPolicyDialog:
    """Picker + overview + gating dialog for a live firewall policy review.

    Drives ``firewall_policy_api`` to list policies, describe one into
    ``PolicyFacts``, evaluate the analyzability gates, fetch the customer-owned
    Suricata rule groups, and assemble a ``PolicySet``. On Analyze,
    ``self.result`` is set to ``(facts, policy_set)``; on Cancel / window close
    it stays ``None`` and no state is changed.
    """

    def __init__(self, parent, aws_session):
        """Build the dialog.

        Args:
            parent: The parent tk widget (the main application window).
            aws_session: An ``AWSSessionManager`` used (indirectly, through the
                API layer) to create boto3 clients. Its ``display_name`` is
                shown read-only and ``get_default_region()`` seeds the region.
        """
        self.parent = parent
        self.aws_session = aws_session

        # The assembled result: (facts, policy_set) on Analyze, else None.
        self.result: Optional[Tuple[PolicyFacts, PolicySet]] = None

        # Working state.
        self._facts: Optional[PolicyFacts] = None
        self._policies: List[dict] = []
        self._arn_by_iid: dict = {}
        self._loaded_sources: List[RuleGroupSource] = []

        self._is_dark = _detect_dark_mode()
        self._palette = self._make_palette(self._is_dark)

        # Seed the region from the session default, keeping it selectable even
        # if it is not in the standard commercial list.
        default_region = self.aws_session.get_default_region()
        if default_region in AWS_REGIONS:
            self._region_values = list(AWS_REGIONS)
        else:
            self._region_values = [default_region] + list(AWS_REGIONS)

        # --- Toplevel -----------------------------------------------------
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Review Firewall Policy")
        # Cross_Platform_UI_Guidelines: resizable + minsize; NO transient().
        self.dialog.resizable(True, True)
        self.dialog.minsize(760, 520)
        self.dialog.geometry("860x600")
        try:
            self.dialog.configure(bg=self._palette["bg"])
        except tk.TclError:
            pass

        # Closing via the window manager 'X' behaves like Cancel.
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self.region_var = tk.StringVar(value=default_region)

        self._build_ui()
        # Load the policy list for the seeded region on open.
        self._reload_policies()

    # ------------------------------------------------------------------
    # Palette
    # ------------------------------------------------------------------
    @staticmethod
    def _make_palette(is_dark: bool) -> dict:
        """Return the color palette for the current appearance mode.

        Two full palettes are defined; colors are never hardcoded to a single
        mode (Cross_Platform_UI_Guidelines / ui-conventions Dark Mode section).
        """
        if is_dark:
            return {
                "bg": "#1e1e1e",
                "fg": "#e0e0e0",
                "muted": "#9e9e9e",
                "accent": "#64B5F6",
                "warn": "#FFB74D",
            }
        return {
            "bg": "#f0f0f0",
            "fg": "#1a1a1a",
            "muted": "#555555",
            "accent": "#1565C0",
            "warn": "#F57C00",
        }

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        """Construct all widgets.

        Order matters (Cross_Platform_UI_Guidelines rule 5): the action button
        bar is packed FIRST with ``side=tk.BOTTOM``, followed by the status
        strip, so those fixed-height strips are reserved before the content
        areas are added. The scrollable Treeview containers use ``expand=False``
        with fixed ``height`` so they cannot push the buttons off-screen on
        macOS.
        """
        pal = self._palette

        # --- Bottom action bar (packed FIRST) -----------------------------
        ttk.Separator(self.dialog, orient=tk.HORIZONTAL).pack(
            side=tk.BOTTOM, fill=tk.X
        )
        action_bar = ttk.Frame(self.dialog, padding=(14, 8, 14, 12))
        action_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.analyze_btn = ttk.Button(
            action_bar,
            text="Analyze",
            command=self._on_analyze,
            state=tk.DISABLED,
        )
        self.analyze_btn.pack(side=tk.RIGHT)
        self.close_btn = ttk.Button(
            action_bar, text="Close", command=self._on_cancel
        )
        self.close_btn.pack(side=tk.RIGHT, padx=(0, 8))

        # --- Status strip (gate / ready / progress messages) --------------
        self.status_label = tk.Label(
            self.dialog,
            text="",
            justify=tk.LEFT,
            anchor=tk.W,
            bg=pal["bg"],
            fg=pal["muted"],
            wraplength=820,
        )
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=14, pady=(0, 4))

        # --- Header: profile + region -------------------------------------
        header = ttk.Frame(self.dialog, padding=(14, 12, 14, 4))
        header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(
            header,
            text="AWS profile: " + str(self.aws_session.display_name),
            justify=tk.LEFT,
        ).pack(anchor=tk.W)

        region_row = ttk.Frame(header)
        region_row.pack(anchor=tk.W, fill=tk.X, pady=(6, 0))
        ttk.Label(region_row, text="Region:").pack(side=tk.LEFT)
        self.region_combo = ttk.Combobox(
            region_row,
            textvariable=self.region_var,
            values=self._region_values,
            state="readonly",
            width=22,
        )
        self.region_combo.pack(side=tk.LEFT, padx=(6, 0))
        self.region_combo.bind("<<ComboboxSelected>>", self._on_region_change)
        self.refresh_btn = ttk.Button(
            region_row, text="Refresh list", command=self._reload_policies
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=(10, 0))

        # --- Policy list area ---------------------------------------------
        list_frame = ttk.Frame(self.dialog, padding=(14, 4, 14, 4))
        list_frame.pack(side=tk.TOP, fill=tk.X, expand=False)
        ttk.Label(
            list_frame,
            text="Firewall policies:",
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(2, 4))

        # expand=False container (Cross-Platform Layout rule 1).
        policy_container = ttk.Frame(list_frame)
        policy_container.pack(fill=tk.X, expand=False)
        self.policy_tree = ttk.Treeview(
            policy_container,
            columns=("name",),
            show="headings",
            selectmode="browse",
            height=8,
        )
        self.policy_tree.heading("name", text="Policy Name")
        self.policy_tree.column("name", width=760, anchor=tk.W, stretch=True)
        policy_vsb = ttk.Scrollbar(
            policy_container, orient=tk.VERTICAL, command=self.policy_tree.yview
        )
        self.policy_tree.configure(yscrollcommand=policy_vsb.set)
        self.policy_tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
        policy_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.policy_tree.bind("<<TreeviewSelect>>", self._on_policy_select)
        self.policy_tree.bind(
            "<MouseWheel>", lambda e: self._on_mousewheel(e, self.policy_tree)
        )
        self.policy_tree.bind(
            "<Button-4>", lambda e: self._on_mousewheel(e, self.policy_tree)
        )
        self.policy_tree.bind(
            "<Button-5>", lambda e: self._on_mousewheel(e, self.policy_tree)
        )
        self.policy_tree.bind(
            "<Control-c>", lambda e: self._copy_selection(e, self.policy_tree)
        )
        self.policy_tree.bind(
            "<Command-c>", lambda e: self._copy_selection(e, self.policy_tree)
        )

        load_row = ttk.Frame(list_frame)
        load_row.pack(anchor=tk.W, fill=tk.X, pady=(6, 0))
        self.load_btn = ttk.Button(
            load_row,
            text="Load Policy",
            command=self._on_load_policy,
            state=tk.DISABLED,
        )
        self.load_btn.pack(side=tk.LEFT)

        # --- Overview area -------------------------------------------------
        overview_frame = ttk.Frame(self.dialog, padding=(14, 4, 14, 8))
        overview_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        ttk.Label(
            overview_frame,
            text="Policy overview:",
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(2, 4))

        self.overview_meta = tk.Label(
            overview_frame,
            text="",
            justify=tk.LEFT,
            anchor=tk.W,
            bg=pal["bg"],
            fg=pal["fg"],
            wraplength=820,
        )
        self.overview_meta.pack(anchor=tk.W, fill=tk.X, pady=(0, 6))

        # expand=False container with fixed height (Cross-Platform Layout rule 1).
        overview_container = ttk.Frame(overview_frame)
        overview_container.pack(fill=tk.BOTH, expand=False)
        overview_columns = ("priority", "name", "owner", "format", "rules")
        self.overview_tree = ttk.Treeview(
            overview_container,
            columns=overview_columns,
            show="headings",
            selectmode="browse",
            height=10,
        )
        self.overview_tree.heading("priority", text="Priority")
        self.overview_tree.heading("name", text="Name")
        self.overview_tree.heading("owner", text="Owner")
        self.overview_tree.heading("format", text="Format")
        self.overview_tree.heading("rules", text="Rules")
        self.overview_tree.column("priority", width=70, anchor=tk.CENTER, stretch=False)
        self.overview_tree.column("name", width=360, anchor=tk.W, stretch=True)
        self.overview_tree.column("owner", width=90, anchor=tk.CENTER, stretch=False)
        self.overview_tree.column("format", width=160, anchor=tk.W, stretch=False)
        self.overview_tree.column("rules", width=110, anchor=tk.E, stretch=False)
        overview_vsb = ttk.Scrollbar(
            overview_container, orient=tk.VERTICAL, command=self.overview_tree.yview
        )
        self.overview_tree.configure(yscrollcommand=overview_vsb.set)
        self.overview_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        overview_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.overview_tree.bind(
            "<MouseWheel>", lambda e: self._on_mousewheel(e, self.overview_tree)
        )
        self.overview_tree.bind(
            "<Button-4>", lambda e: self._on_mousewheel(e, self.overview_tree)
        )
        self.overview_tree.bind(
            "<Button-5>", lambda e: self._on_mousewheel(e, self.overview_tree)
        )
        self.overview_tree.bind(
            "<Control-c>", lambda e: self._copy_selection(e, self.overview_tree)
        )
        self.overview_tree.bind(
            "<Command-c>", lambda e: self._copy_selection(e, self.overview_tree)
        )

        # Plain-text overview kept available for callers / debugging.
        self._overview_text = ""

    # ------------------------------------------------------------------
    # Status helper
    # ------------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        """Show (or clear) the status / gate / progress line."""
        try:
            self.status_label.config(text=text or "")
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Policy list (task 8.2)
    # ------------------------------------------------------------------
    def _on_region_change(self, event=None) -> None:
        """Handle a region selection: reset state and re-list policies."""
        self._reset_overview_state()
        self._reload_policies()

    def _reset_overview_state(self) -> None:
        """Clear the loaded facts/overview and disable Analyze."""
        self._facts = None
        self._loaded_sources = []
        for item in self.overview_tree.get_children():
            self.overview_tree.delete(item)
        self.overview_meta.config(text="")
        self._overview_text = ""
        self.analyze_btn.config(state=tk.DISABLED)

    def _reload_policies(self) -> None:
        """List firewall policies for the selected region into the tree.

        Surfaces the REAL ``FirewallPolicyApiError`` message with Retry/Cancel,
        and shows a distinct empty-state message when the account/Region has no
        policies.
        """
        region = self.region_var.get()
        try:
            policies = list_firewall_policies(self.aws_session, region)
        except FirewallPolicyApiError as e:
            message = str(e)
            retry = messagebox.askretrycancel(
                "List Firewall Policies", message, parent=self.dialog
            )
            if retry:
                self._reload_policies()
            else:
                self._populate_policy_tree([])
                self._set_status(message)
            return

        self._policies = policies
        self._populate_policy_tree(policies)
        if not policies:
            self._set_status(
                "No firewall policies in this account / Region "
                "({0}).".format(region)
            )
        else:
            self._set_status(
                "Select a policy and choose Load Policy."
            )

    def _populate_policy_tree(self, policies: List[dict]) -> None:
        """Repopulate the policy Treeview and the iid -> ARN map."""
        for item in self.policy_tree.get_children():
            self.policy_tree.delete(item)
        self._arn_by_iid = {}
        for idx, policy in enumerate(policies):
            iid = str(idx)
            name = policy.get("Name", "") or policy.get("Arn", "")
            self.policy_tree.insert("", tk.END, iid=iid, values=(name,))
            self._arn_by_iid[iid] = policy.get("Arn", "")
        # Load Policy stays disabled until a row is selected.
        self.load_btn.config(state=tk.DISABLED)

    def _on_policy_select(self, event=None) -> None:
        """Enable Load Policy only when a row is selected."""
        selection = self.policy_tree.selection()
        self.load_btn.config(
            state=(tk.NORMAL if selection else tk.DISABLED)
        )

    # ------------------------------------------------------------------
    # Load policy + overview + gates (task 8.3)
    # ------------------------------------------------------------------
    def _on_load_policy(self) -> None:
        """Describe the selected policy and render + gate it."""
        selection = self.policy_tree.selection()
        if not selection:
            return
        arn = self._arn_by_iid.get(selection[0], "")
        if not arn:
            return
        region = self.region_var.get()
        try:
            facts = describe_policy_facts(self.aws_session, region, arn)
        except FirewallPolicyApiError as e:
            message = str(e)
            retry = messagebox.askretrycancel(
                "Load Firewall Policy", message, parent=self.dialog
            )
            if retry:
                self._on_load_policy()
            else:
                self._set_status(message)
            return

        self._facts = facts
        self._loaded_sources = []
        self._render_overview(facts)
        self._evaluate_gates(facts)

    def _render_overview(self, facts: PolicyFacts) -> None:
        """Render the scalar facts + the ascending-priority group table."""
        for item in self.overview_tree.get_children():
            self.overview_tree.delete(item)
        for idx, ref in enumerate(facts.stateful_refs):
            self.overview_tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(
                    _priority_cell(ref),
                    _name_cell(ref),
                    _owner_label(ref),
                    (
                        _FORMAT_LABELS.get(ref.rule_format, ref.rule_format)
                        if ref.is_customer_owned
                        else "\u2014"
                    ),
                    _rules_cell(ref),
                ),
            )

        meta_lines = [
            "Policy Name: {0}".format(facts.policy_name),
            "Policy ARN: {0}".format(facts.policy_arn),
            "Region: {0}".format(facts.region),
            "Rule Order: {0}".format(_rule_order_note(facts.rule_order)),
            "Stateful Default Actions: {0}".format(
                _default_actions_display(facts)
            ),
            "Stream Exception Policy: {0}".format(facts.stream_exception_policy),
            "Policy $HOME_NET: {0}".format(_home_net_display(facts)),
            "Stateless Rule Groups: {0}".format(_stateless_note(facts)),
        ]
        self.overview_meta.config(text="\n".join(meta_lines))
        self._overview_text = format_policy_overview_text(facts)

    def _evaluate_gates(self, facts: PolicyFacts) -> None:
        """Apply the analyzability gates in order (task 8.3).

        Each gate leaves Analyze DISABLED and the overview visible, writing its
        distinct message to the status line. If all three pass, proceed to the
        fetch + format/load-error gating.
        """
        self.analyze_btn.config(state=tk.DISABLED)

        if not facts.has_stateful_refs():
            self._set_status(
                "This policy references no stateful rule groups, so there is "
                "nothing to analyze."
            )
            return
        if not facts.has_customer_groups():
            self._set_status(
                "All referenced stateful rule groups are AWS-managed or "
                "shared-in and cannot be analyzed."
            )
            return
        if not facts.is_strict_order():
            self._set_status(
                "This policy uses DEFAULT_ACTION_ORDER. The analyzer models "
                "strict-order evaluation only, so this policy cannot be "
                "analyzed."
            )
            return

        self._fetch_and_gate_groups(facts)

    # ------------------------------------------------------------------
    # Fetch customer groups + format/load-error gates (task 8.4)
    # ------------------------------------------------------------------
    def _fetch_and_gate_groups(self, facts: PolicyFacts) -> None:
        """Fetch each customer group, then apply the load-error + format gates.

        Shows responsive progress feedback. The load-error gate runs first
        (offering Retry / Analyze loaded groups only / Cancel); the Suricata-
        format gate runs on the remaining loaded groups. Analyze is enabled only
        when at least one customer Suricata group loaded cleanly.
        """
        customer_refs = facts.customer_refs()
        total = len(customer_refs)
        pairs: List[Tuple[object, RuleGroupSource]] = []
        region = self.region_var.get()

        for position, ref in enumerate(customer_refs, start=1):
            self._set_status(
                "Fetching rule group {0} of {1}\u2026".format(position, total)
            )
            try:
                self.dialog.update_idletasks()
            except tk.TclError:
                pass
            source = fetch_customer_group(self.aws_session, region, ref)
            pairs.append((ref, source))

        # --- Load-error gate (first) --------------------------------------
        failed = [(ref, src) for ref, src in pairs if src.load_error]
        if failed:
            names = ", ".join(ref.name for ref, _ in failed)
            message = (
                "Could not load the following customer rule group(s): "
                "{0}.".format(names)
            )
            choice = self._ask_retry_loaded_cancel(
                "Rule Group Load Error", message
            )
            if choice == "retry":
                self._fetch_and_gate_groups(facts)
                return
            if choice == "cancel":
                self._set_status(
                    "Fetch cancelled. {0}".format(message)
                )
                self.analyze_btn.config(state=tk.DISABLED)
                return
            # "loaded": drop the failed refs and continue with the rest.
            pairs = [(ref, src) for ref, src in pairs if not src.load_error]

        # --- Suricata-format gate -----------------------------------------
        offenders = [
            (ref, src)
            for ref, src in pairs
            if ref.rule_format != FORMAT_SURICATA
        ]
        if offenders:
            offender_text = "; ".join(
                "{0} \u2014 {1}".format(
                    ref.name,
                    _FORMAT_LABELS.get(ref.rule_format, ref.rule_format),
                )
                for ref, _ in offenders
            )
            self._set_status(
                "These customer rule group(s) are not in Suricata format and "
                "cannot be analyzed: {0}.".format(offender_text)
            )
            self.analyze_btn.config(state=tk.DISABLED)
            return

        # All gates passed: assemble the analyzable Suricata sources in
        # ascending-priority (customer_refs) order.
        self._loaded_sources = [src for _, src in pairs]
        if not self._loaded_sources:
            self._set_status(
                "No customer Suricata rule groups are available to analyze."
            )
            self.analyze_btn.config(state=tk.DISABLED)
            return

        # Re-render the overview table now that the per-group fetch has resolved
        # each customer ref's rule_format / analyzable_rule_count. The table was
        # first populated before the fetch, so its Format/Rules cells were stale;
        # repopulating from the now-enriched facts shows the resolved values.
        # Idempotent: _render_overview clears and re-inserts all rows. Kept in
        # the success path only so a failed/gated load never wipes the table.
        self._render_overview(facts)

        self._set_status(
            "Ready to analyze: {0} customer Suricata group(s).".format(
                len(self._loaded_sources)
            )
        )
        self.analyze_btn.config(state=tk.NORMAL)

    def _ask_retry_loaded_cancel(self, title: str, message: str) -> str:
        """Show a modal 3-choice prompt; return 'retry'/'loaded'/'cancel'.

        ``messagebox`` lacks a 3-way option, so this builds a tiny modal
        ``tk.Toplevel`` parented on the dialog, grabbed and guarded with
        ``winfo_exists`` (Cross_Platform_UI_Guidelines rule 4).
        """
        pal = self._palette
        choice = {"value": "cancel"}

        prompt = tk.Toplevel(self.dialog)
        prompt.title(title)
        prompt.resizable(True, True)
        prompt.minsize(420, 160)
        try:
            prompt.configure(bg=pal["bg"])
        except tk.TclError:
            pass

        def _choose(value: str) -> None:
            choice["value"] = value
            try:
                prompt.grab_release()
            except tk.TclError:
                pass
            if prompt.winfo_exists():
                prompt.destroy()

        prompt.protocol("WM_DELETE_WINDOW", lambda: _choose("cancel"))

        tk.Label(
            prompt,
            text=message,
            justify=tk.LEFT,
            anchor=tk.W,
            bg=pal["bg"],
            fg=pal["fg"],
            wraplength=400,
        ).pack(side=tk.TOP, fill=tk.X, padx=14, pady=(14, 8))

        button_bar = ttk.Frame(prompt, padding=(14, 4, 14, 12))
        button_bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Button(
            button_bar, text="Retry", command=lambda: _choose("retry")
        ).pack(side=tk.RIGHT)
        ttk.Button(
            button_bar,
            text="Analyze loaded groups only",
            command=lambda: _choose("loaded"),
        ).pack(side=tk.RIGHT, padx=(0, 8))
        ttk.Button(
            button_bar, text="Cancel", command=lambda: _choose("cancel")
        ).pack(side=tk.RIGHT, padx=(0, 8))

        try:
            prompt.grab_set()
        except tk.TclError:
            pass
        try:
            prompt.lift()
            prompt.focus_force()
        except tk.TclError:
            pass
        if prompt.winfo_exists():
            prompt.wait_window()
        return choice["value"]

    # ------------------------------------------------------------------
    # Analyze / Cancel / show (task 8.5)
    # ------------------------------------------------------------------
    def _on_analyze(self) -> None:
        """Assemble ``(facts, PolicySet)`` and close.

        Defensive re-check: only proceeds when at least one Suricata source
        loaded and facts are present (Analyze is already disabled otherwise).
        """
        if self._facts is None or not self._loaded_sources:
            return
        policy_set = PolicySet(groups=list(self._loaded_sources))
        self.result = (self._facts, policy_set)
        self._destroy()

    def _on_cancel(self) -> None:
        """Cancel without analyzing: result stays None, close the dialog."""
        self.result = None
        self._destroy()

    def _destroy(self) -> None:
        """Release the grab and destroy the dialog, guarded for macOS."""
        try:
            self.dialog.grab_release()
        except tk.TclError:
            pass
        if self.dialog.winfo_exists():
            self.dialog.destroy()

    def show(self) -> Optional[Tuple[PolicyFacts, PolicySet]]:
        """Display the dialog modally and return the assembled result.

        Returns ``(facts, policy_set)`` on Analyze, or ``None`` on Cancel /
        window close. Uses the project's standard modal pattern: ``grab_set``
        plus ``wait_window`` guarded by ``winfo_exists``
        (Cross_Platform_UI_Guidelines rule 4).
        """
        try:
            self.dialog.grab_set()
        except tk.TclError:
            pass
        try:
            self.dialog.lift()
            self.dialog.focus_force()
        except tk.TclError:
            pass
        if self.dialog.winfo_exists():
            self.dialog.wait_window()
        return self.result

    # ------------------------------------------------------------------
    # Cross-platform bindings
    # ------------------------------------------------------------------
    def _on_mousewheel(self, event, tree):
        """Scroll ``tree``, accounting for platform delta differences."""
        if getattr(event, "num", None) == 4:  # macOS scroll up
            tree.yview_scroll(-3, "units")
        elif getattr(event, "num", None) == 5:  # macOS scroll down
            tree.yview_scroll(3, "units")
        else:  # Windows / Linux
            delta = getattr(event, "delta", 0)
            tree.yview_scroll(int(-1 * (delta / 120)), "units")
        return "break"

    def _copy_selection(self, event, tree) -> str:
        """Copy ``tree``'s selected row text to the clipboard (Control/Command-c).

        Builds a tab-separated line from the selected row's column values and
        catches ``TclError`` for the no-selection case, matching the project's
        copy-handler convention.
        """
        try:
            selection = tree.selection()
            if not selection:
                return "break"
            values = tree.item(selection[0], "values")
            text = "\t".join(str(v) for v in values)
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(text)
        except tk.TclError:
            pass
        return "break"
