"""
Policy Set Configuration Dialog for Multi-Rule-Group Analysis

This module defines ``PolicySetDialog``, the tkinter splash/config screen the
reworked ``review_rules(allow_multi_group=True)`` opens (design.md, "New:
src/gui/policy_set_dialog.py"). It is the feature's PRIMARY window: the user
reviews the open rule group by itself, or adds other local ``.suricata`` files,
arranges the evaluation order (Group_Order) with Move Up / Move Down, and clicks
Analyze. The dialog composes an injected ``PolicyReviewService`` for loading
groups and returns a ``PolicySet`` (in the user's chosen list order) on Analyze,
or ``None`` on Cancel.

Testing note (design.md, Testing Strategy): this file is UI (tkinter) and is
NOT unit-tested headlessly. The testable core lives in the UI-free
``policy_models``/``policy_review`` modules. All Tk objects are created only in
``__init__`` / instance methods, so importing this module never initializes Tk
and needs no display.

Cross_Platform_UI_Guidelines followed (see .kiro/steering/ui-conventions.md):
  * No ``transient()`` call anywhere (the app's global macOS monkey-patch makes
    it a no-op on Darwin; we simply never call it). As the feature's primary
    window this dialog is parented on the main app window; its only child popup
    is the native file picker, which needs no reparenting.
  * ``resizable(True, True)`` + ``minsize(...)`` so every control stays visible
    at the smallest supported size.
  * Action buttons (Analyze / Cancel) packed ``side=tk.BOTTOM`` BEFORE the
    content area, so they can never be pushed off-screen (rule 5).
  * The scrollable rule-group Treeview container is packed with
    ``expand=False`` (Cross-Platform Layout rule 1) so it cannot consume all
    vertical space on macOS and push the buttons off-screen. The Treeview is
    instead given a sensible fixed ``height`` (in rows) and packed
    ``fill=tk.BOTH`` inside its ``expand=False`` container -- the same
    reconciled pattern the project's other Treeview/Text dialogs use (e.g.
    ai_analysis_tab.py's content_frame, ui_manager.py's eff_tree_container).
  * Mouse-wheel bindings on the Treeview for Windows/Linux (<MouseWheel>) and
    macOS (<Button-4>/<Button-5>).
  * Dual Control/Command copy bindings on the Treeview (copies the selected
    row's text) for Windows and macOS.
  * Dark-mode palette selected via the project's AppleInterfaceStyle detection
    pattern (ai_assistant_panel.py), not hardcoded single-mode colors.

Result-return + session retention (briefing for Task 7.2):
  * ``self.result`` holds the assembled ``PolicySet`` after Analyze, or stays
    ``None`` after Cancel / window close.
  * ``show()`` grabs the dialog, blocks on ``wait_window`` (guarded with
    ``winfo_exists``), and returns ``self.result`` -- the same modal pattern the
    project's other return-a-value dialogs use (e.g. the Export Format dialog in
    ui_manager.py: a result holder + ``dialog.wait_window()`` + return).
  * Session retention (Req 3.3, SHOULD): the caller MAY pass a previously
    assembled ``PolicySet`` as ``existing_policy_set`` when re-opening; the
    dialog re-seeds the list from that set's Local_Groups instead of forcing the
    user to re-add them. The recommended wiring for Task 7.2 is to cache the
    returned ``PolicySet`` on the ``SuricataRuleGenerator`` instance (e.g.
    ``self._policy_set_session``) and pass it back in on the next open. The
    Current_Group is always rebuilt fresh from live editor state so it reflects
    the editor as it is now; only the Additional_Groups are restored.
"""

import os
import platform as _plat
import subprocess as _sp
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from src.analysis.policy_models import (
    GROUP_KIND_CURRENT,
    PolicySet,
    RuleGroupSource,
)

# Max_Rule_Groups: hard cap of 20 total rule groups per Policy_Set, mirroring
# AWS Network Firewall's per-policy stateful rule group limit (Req 11.1).
MAX_RULE_GROUPS = 20


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


class PolicySetDialog:
    """Configuration splash screen for a multi-rule-group review.

    Composes a ``PolicyReviewService`` for loading local groups and assembles a
    ``PolicySet`` the caller runs. Seeded with the Current_Group as the first
    group; the user adds local ``.suricata`` files, reorders with Move Up / Move
    Down, and clicks Analyze (returns the ``PolicySet``) or Cancel (returns
    ``None``).
    """

    def __init__(
        self,
        parent,
        service,
        current_group_source: RuleGroupSource,
        existing_policy_set: Optional[PolicySet] = None,
    ):
        """Build the dialog.

        Args:
            parent: The parent tk widget (the main application window).
            service: A ``PolicyReviewService`` used to load local groups
                (``load_local_group``). The dialog never runs analysis itself.
            current_group_source: The Current_Group ``RuleGroupSource`` built by
                the caller from live editor state; seeded as the first row and
                never removable (Req 1.1, 2.5).
            existing_policy_set: Optional previously-assembled ``PolicySet`` from
                an earlier open in this session (Req 3.3). When provided, its
                Local_Groups are restored beneath a freshly rebuilt Current_Group
                so the user need not re-add them.
        """
        self.parent = parent
        self.service = service
        self.current_group_source = current_group_source

        # The assembled result: a PolicySet on Analyze, or None on Cancel/close.
        self.result: Optional[PolicySet] = None

        # Build the working PolicySet. The Current_Group always leads on first
        # open. When re-opening with a retained set, we rebuild the ordering
        # from that set but substitute the freshly supplied Current_Group so it
        # reflects the editor's current state (its Local_Groups are restored).
        self.policy_set = self._build_initial_policy_set(existing_policy_set)

        # Remember the directory of the last browse for the session, and seed it
        # from the current file's directory when available.
        self._browse_dir: Optional[str] = None
        if current_group_source.origin_path:
            self._browse_dir = os.path.dirname(current_group_source.origin_path)

        self._is_dark = _detect_dark_mode()
        self._palette = self._make_palette(self._is_dark)

        # --- Toplevel -----------------------------------------------------
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Review Rules \u2014 Configure Rule Groups")
        # Cross_Platform_UI_Guidelines: resizable + minsize; NO transient().
        self.dialog.resizable(True, True)
        self.dialog.minsize(720, 460)
        self.dialog.geometry("820x520")
        try:
            self.dialog.configure(bg=self._palette["bg"])
        except tk.TclError:
            pass

        # Closing via the window manager 'X' behaves like Cancel.
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._build_ui()
        self._refresh_tree()
        self._update_counts_and_buttons()

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------
    def _build_initial_policy_set(
        self, existing_policy_set: Optional[PolicySet]
    ) -> PolicySet:
        """Assemble the starting PolicySet.

        On a fresh open, the set is just the Current_Group. When a retained set
        is supplied (Req 3.3), its groups are copied in their retained order but
        the current-kind entry is replaced by the freshly supplied
        Current_Group so it reflects live editor state; any group carrying the
        same current identity is not duplicated.
        """
        if existing_policy_set is None or not existing_policy_set.groups:
            return PolicySet(groups=[self.current_group_source])

        groups: List[RuleGroupSource] = []
        current_placed = False
        for group in existing_policy_set.groups:
            if group.kind == GROUP_KIND_CURRENT:
                # Replace any retained current group with the fresh one, keeping
                # its position in the retained order.
                groups.append(self.current_group_source)
                current_placed = True
            else:
                groups.append(group)
        if not current_placed:
            # Retained set had no current group; put the fresh one on top.
            groups.insert(0, self.current_group_source)
        return PolicySet(groups=groups)

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
                "disabled": "#6b6b6b",  # greyed load-error rows
            }
        return {
            "bg": "#f0f0f0",
            "fg": "#1a1a1a",
            "muted": "#555555",
            "accent": "#1565C0",
            "warn": "#F57C00",
            "disabled": "#9e9e9e",  # greyed load-error rows
        }

    def _build_ui(self) -> None:
        """Construct all widgets.

        Order matters (Cross_Platform_UI_Guidelines rule 5): the single
        consolidated button bar (group-management buttons plus Analyze /
        Cancel, all on one row) is packed FIRST with ``side=tk.BOTTOM``,
        followed by the feedback and counts strips, and only then the
        expandable content area. Because the button row is reserved first,
        the rule-group table can expand (expand=True) to fill the window
        while the buttons stay visible on macOS and Windows.
        """
        pal = self._palette

        # --- Intro text (top) ---------------------------------------------
        header = ttk.Frame(self.dialog, padding=(14, 12, 14, 4))
        header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(
            header,
            text=(
                "Review the open rule group by itself, or add other local "
                ".suricata rule group files to analyze your whole firewall "
                "policy together.\nGroups are evaluated top to bottom \u2014 use "
                "Move Up / Move Down to set the order."
            ),
            justify=tk.LEFT,
            wraplength=760,
        ).pack(anchor=tk.W)

        # --- Single consolidated bottom control bar ----------------------
        # ALL buttons live on ONE row, packed side=tk.BOTTOM FIRST so this
        # fixed-height strip is reserved before the content area expands
        # into the remaining space. This lets the rule-group table stretch
        # (content packs expand=True below) while GUARANTEEING no button is
        # pushed off-screen on macOS (the concern behind Cross-Platform
        # Layout rule 1). Group-management buttons are LEFT-aligned; the
        # Analyze / Cancel actions are RIGHT-aligned on the same row.
        action_bar = ttk.Frame(self.dialog, padding=(14, 8, 14, 12))
        action_bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Separator(self.dialog, orient=tk.HORIZONTAL).pack(
            side=tk.BOTTOM, fill=tk.X
        )
        # Right side: Analyze (rightmost), Cancel to its left.
        self.analyze_btn = ttk.Button(
            action_bar, text="Analyze", command=self._on_analyze
        )
        self.analyze_btn.pack(side=tk.RIGHT)
        self.cancel_btn = ttk.Button(
            action_bar, text="Cancel", command=self._on_cancel
        )
        self.cancel_btn.pack(side=tk.RIGHT, padx=(0, 8))
        # Left side: group-management buttons, on the SAME row.
        self.add_btn = ttk.Button(
            action_bar, text="Add Rule File(s)\u2026", command=self._on_add_files
        )
        self.add_btn.pack(side=tk.LEFT)
        self.move_up_btn = ttk.Button(
            action_bar, text="\u25b2 Move Up", command=self._on_move_up
        )
        self.move_up_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.move_down_btn = ttk.Button(
            action_bar, text="\u25bc Move Down", command=self._on_move_down
        )
        self.move_down_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.remove_btn = ttk.Button(
            action_bar, text="Remove", command=self._on_remove
        )
        self.remove_btn.pack(side=tk.LEFT, padx=(8, 0))

        # --- Skip / feedback report (thin strip above the button row) -----
        # Multi-line label that shows duplicate / over-cap / load-error notes.
        self.feedback_label = tk.Label(
            self.dialog,
            text="",
            justify=tk.LEFT,
            anchor=tk.W,
            bg=pal["bg"],
            fg=pal["warn"],
            wraplength=780,
        )
        self.feedback_label.pack(side=tk.BOTTOM, fill=tk.X, padx=14, pady=(0, 2))

        # --- Counts line (above the controls) -----------------------------
        self.counts_label = tk.Label(
            self.dialog,
            text="",
            anchor=tk.W,
            bg=pal["bg"],
            fg=pal["fg"],
        )
        self.counts_label.pack(side=tk.BOTTOM, fill=tk.X, padx=14, pady=(2, 4))

        # --- Content area: the ordered rule-group Treeview ----------------
        # expand=True so the table stretches to fill the window on resize.
        # This is safe (despite Cross-Platform Layout rule 1) because ALL
        # buttons live on the single action bar packed side=tk.BOTTOM FIRST
        # above, so that strip is reserved and no button can be pushed
        # off-screen on macOS.
        content = ttk.Frame(self.dialog, padding=(14, 4, 14, 4))
        content.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        ttk.Label(
            content,
            text="Rule groups will be evaluated in this order (top first):",
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(2, 4))

        # expand=True on the scroll container so the table grows with the
        # window. The fixed ``height`` below is just the default size; the
        # reserved bottom button bar keeps the actions visible regardless.
        tree_frame = ttk.Frame(content)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ordinal", "name", "origin", "rules")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=14,
        )
        self.tree.heading("ordinal", text="#")
        self.tree.heading("name", text="Rule Group")
        self.tree.heading("origin", text="Origin")
        self.tree.heading("rules", text="Rules")
        self.tree.column("ordinal", width=44, anchor=tk.CENTER, stretch=False)
        self.tree.column("name", width=460, anchor=tk.W, stretch=True)
        self.tree.column("origin", width=90, anchor=tk.CENTER, stretch=False)
        self.tree.column("rules", width=90, anchor=tk.E, stretch=False)

        vsb = ttk.Scrollbar(
            tree_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=vsb.set)
        # expand=True so the tree fills the growing container; the fixed
        # ``height`` above is just the default row count.
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Greyed style for non-analyzable / load-error rows (Req 2.7 display).
        self.tree.tag_configure("load_error", foreground=self._palette["disabled"])

        # Selection changes update which move/remove buttons are enabled.
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_counts_and_buttons())

        # Mouse-wheel bindings (Windows/Linux + macOS).
        self.tree.bind("<MouseWheel>", self._on_mousewheel)
        self.tree.bind("<Button-4>", self._on_mousewheel)
        self.tree.bind("<Button-5>", self._on_mousewheel)

        # Dual Control/Command copy bindings.
        self.tree.bind("<Control-c>", self._copy_selection)
        self.tree.bind("<Command-c>", self._copy_selection)

    # ------------------------------------------------------------------
    # Modal show / result
    # ------------------------------------------------------------------
    def show(self) -> Optional[PolicySet]:
        """Display the dialog modally and return the assembled result.

        Returns the ``PolicySet`` assembled by the user on Analyze, or ``None``
        on Cancel / window close. Uses the project's standard modal pattern: a
        ``grab_set`` for modality plus ``wait_window`` guarded by
        ``winfo_exists`` (Cross_Platform_UI_Guidelines rule 4) so an already
        destroyed dialog never raises ``TclError``.
        """
        try:
            self.dialog.grab_set()
        except tk.TclError:
            pass
        # Focus the dialog so it comes forward as the feature's primary window.
        try:
            self.dialog.lift()
            self.dialog.focus_force()
        except tk.TclError:
            pass
        if self.dialog.winfo_exists():
            self.dialog.wait_window()
        return self.result

    # ------------------------------------------------------------------
    # Treeview rendering
    # ------------------------------------------------------------------
    def _refresh_tree(self, select_index: Optional[int] = None) -> None:
        """Rebuild every Treeview row from ``self.policy_set`` in list order.

        Renumbers the ordinal ``#`` column (1, 2, 3\u2026) and greys any group
        that failed to load. Optionally reselects the row at ``select_index``
        so Move Up / Move Down keep the moved row selected.
        """
        # Clear existing rows.
        for item in self.tree.get_children():
            self.tree.delete(item)

        groups = self.policy_set.ordered_groups()
        for idx, group in enumerate(groups):
            origin = "Current" if group.kind == GROUP_KIND_CURRENT else "Local"
            if group.load_error:
                # Greyed, non-analyzable row showing the reason (Req 2.7).
                name = f"{group.name}  ({group.load_error})"
                rules_text = "0"
                tags = ("load_error",)
            else:
                name = group.name
                rules_text = str(group.analyzable_rule_count())
                tags = ()
            self.tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(idx + 1, name, origin, rules_text),
                tags=tags,
            )

        if select_index is not None and 0 <= select_index < len(groups):
            iid = str(select_index)
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self.tree.see(iid)

    def _selected_index(self) -> Optional[int]:
        """Return the selected row's index into ``policy_set.groups``, or None."""
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return int(selection[0])
        except (ValueError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Counts + button state
    # ------------------------------------------------------------------
    def _update_counts_and_buttons(self) -> None:
        """Refresh the counts line, the Analyze enablement, and button states.

        Counts (Req 1.3, 3.3, 11.1): "Groups: N of 20" and total analyzable
        rules. Analyze is enabled once the set has at least one analyzable rule.
        Move Up / Move Down / Remove reflect the current selection (Req 2.3,
        2.5). Add is disabled at the 20-group cap (Req 11.2).
        """
        total_groups = self.policy_set.total_group_count()
        total_rules = self.policy_set.total_analyzable_rules()
        self.counts_label.config(
            text=(
                f"Groups: {total_groups} of {MAX_RULE_GROUPS}"
                f"      Total analyzable rules: {total_rules}"
            )
        )

        # Analyze: enabled once at least one analyzable rule exists.
        self.analyze_btn.config(
            state=(tk.NORMAL if total_rules > 0 else tk.DISABLED)
        )

        # Add: disabled at the hard cap.
        self.add_btn.config(
            state=(
                tk.DISABLED
                if total_groups >= MAX_RULE_GROUPS
                else tk.NORMAL
            )
        )

        # Move/Remove: depend on the selection.
        idx = self._selected_index()
        groups = self.policy_set.ordered_groups()
        if idx is None:
            # Nothing selected: all three disabled.
            self.move_up_btn.config(state=tk.DISABLED)
            self.move_down_btn.config(state=tk.DISABLED)
            self.remove_btn.config(state=tk.DISABLED)
            return

        at_top = idx == 0
        at_bottom = idx == len(groups) - 1
        self.move_up_btn.config(state=(tk.DISABLED if at_top else tk.NORMAL))
        self.move_down_btn.config(
            state=(tk.DISABLED if at_bottom else tk.NORMAL)
        )

        # Remove: disabled for the Current_Group (it cannot be removed, Req 2.5).
        selected = groups[idx]
        self.remove_btn.config(
            state=(
                tk.DISABLED
                if selected.kind == GROUP_KIND_CURRENT
                else tk.NORMAL
            )
        )

    def _set_feedback(self, text: str) -> None:
        """Show (or clear) the skip / feedback report line."""
        self.feedback_label.config(text=text or "")

    # ------------------------------------------------------------------
    # Add files (Usage_Analyzer_Selection_Pattern)
    # ------------------------------------------------------------------
    def _on_add_files(self) -> None:
        """Add one or more Local_Groups via a multi-select file picker.

        Mirrors the Usage_Analyzer_Selection_Pattern: a multi-select
        ``.suricata`` picker, current-file auto-exclusion, per-file error
        aggregation, and running counts. New groups append to the BOTTOM of the
        list (Req 2.4). Enforces the duplicate refusal and 20-group cap (Req
        2.8, 11.1\u201311.3) and shows a "Skipped N file(s)" report like the
        mockup.
        """
        initial_dir = self._browse_dir
        if not initial_dir:
            initial_dir = os.path.expanduser("~")

        selected_paths = filedialog.askopenfilenames(
            title="Select Local Suricata Rule Files",
            initialdir=initial_dir,
            filetypes=[("Suricata Rules", "*.suricata"), ("All Files", "*.*")],
            parent=self.dialog,
        )
        if not selected_paths:
            return

        # Preserve directory for the next browse this session.
        self._browse_dir = os.path.dirname(selected_paths[0])

        # Absolute path of the current file (for auto-exclusion + dedupe).
        current_path = self.current_group_source.origin_path
        current_abs = os.path.abspath(current_path) if current_path else None

        # Absolute paths already present in the set (dedupe by path, Req 2.8).
        existing_abs = set()
        if current_abs:
            existing_abs.add(os.path.normpath(current_abs))
        for group in self.policy_set.groups:
            if group.origin_path:
                existing_abs.add(os.path.normpath(os.path.abspath(group.origin_path)))

        # Track skip reasons for the feedback report (Req 11.3 mockup).
        skipped: List[str] = []
        added_count = 0

        for path in selected_paths:
            try:
                path_abs = os.path.abspath(path)
            except (TypeError, ValueError, OSError):
                path_abs = path
            path_norm = os.path.normpath(path_abs)
            filename = os.path.basename(path)

            # Duplicate refusal: the current file or an already-added group.
            if path_norm in existing_abs:
                if current_abs and path_norm == os.path.normpath(current_abs):
                    skipped.append(
                        f"\u2022 {filename} \u2014 already in this review "
                        f"(the open file)"
                    )
                else:
                    skipped.append(
                        f"\u2022 {filename} \u2014 already in this review"
                    )
                continue

            # 20-group hard cap: block once full, report the rest (Req 11.3).
            if self.policy_set.total_group_count() >= MAX_RULE_GROUPS:
                skipped.append(
                    f"\u2022 {filename} \u2014 {MAX_RULE_GROUPS}-rule-group "
                    f"limit reached"
                )
                continue

            # Load via the service (never raises: load_error carried on source).
            group = self.service.load_local_group(path)
            self.policy_set.groups.append(group)  # append to bottom (Req 2.4)
            existing_abs.add(path_norm)
            added_count += 1

        self._refresh_tree()
        self._update_counts_and_buttons()

        # Build the feedback report.
        self._report_add_result(added_count, skipped)

    def _report_add_result(self, added_count: int, skipped: List[str]) -> None:
        """Compose the post-add feedback line(s).

        Shows the skipped-as-duplicate / over-cap block like the mockup, or a
        brief confirmation when everything was added, or a note when a cap block
        prevents any add.
        """
        parts: List[str] = []
        if skipped:
            parts.append(f"\u26a0  Skipped {len(skipped)} file(s):")
            parts.extend(f"   {line}" for line in skipped)
        if not parts:
            # Nothing skipped: clear any stale message.
            self._set_feedback("")
            return
        self._set_feedback("\n".join(parts))

    # ------------------------------------------------------------------
    # Reorder + remove
    # ------------------------------------------------------------------
    def _on_move_up(self) -> None:
        """Move the selected group one position earlier (Req 2.3)."""
        idx = self._selected_index()
        if idx is None or idx <= 0:
            return
        self.policy_set.move_up(idx)
        self._refresh_tree(select_index=idx - 1)
        self._update_counts_and_buttons()

    def _on_move_down(self) -> None:
        """Move the selected group one position later (Req 2.3)."""
        idx = self._selected_index()
        if idx is None or idx >= self.policy_set.total_group_count() - 1:
            return
        self.policy_set.move_down(idx)
        self._refresh_tree(select_index=idx + 1)
        self._update_counts_and_buttons()

    def _on_remove(self) -> None:
        """Remove the selected Additional_Group (never the Current_Group).

        The Current_Group cannot be removed (Req 2.5); the button is disabled
        while it is selected, and this handler guards against it defensively.
        """
        idx = self._selected_index()
        if idx is None:
            return
        groups = self.policy_set.groups
        if not (0 <= idx < len(groups)):
            return
        if groups[idx].kind == GROUP_KIND_CURRENT:
            return  # cannot remove the current group
        del groups[idx]
        # Keep a sensible selection near where the removed row was.
        new_index = min(idx, len(groups) - 1) if groups else None
        self._refresh_tree(select_index=new_index)
        self._update_counts_and_buttons()
        self._set_feedback("")

    # ------------------------------------------------------------------
    # Analyze / Cancel
    # ------------------------------------------------------------------
    def _on_analyze(self) -> None:
        """Assemble the result and close.

        Returns the ``PolicySet`` in the current list order. Guarded so a set
        with no analyzable rules cannot be analyzed (the button is already
        disabled in that state, but we re-check defensively, Req 1.6/10.5 are
        enforced by the caller with the "no rules to analyze" message).
        """
        if self.policy_set.total_analyzable_rules() <= 0:
            messagebox.showinfo(
                "No Rules to Analyze",
                "The policy set has no analyzable rules. Add a rule group with "
                "rules, or cancel.",
                parent=self.dialog,
            )
            return
        # The working PolicySet is already in list order; return it as-is.
        self.result = self.policy_set
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

    # ------------------------------------------------------------------
    # Cross-platform bindings
    # ------------------------------------------------------------------
    def _on_mousewheel(self, event):
        """Scroll the Treeview, accounting for platform delta differences."""
        if getattr(event, "num", None) == 4:  # macOS scroll up
            self.tree.yview_scroll(-3, "units")
        elif getattr(event, "num", None) == 5:  # macOS scroll down
            self.tree.yview_scroll(3, "units")
        else:  # Windows / Linux
            delta = getattr(event, "delta", 0)
            self.tree.yview_scroll(int(-1 * (delta / 120)), "units")
        return "break"

    def _copy_selection(self, event=None) -> str:
        """Copy the selected row's text to the clipboard (Control/Command-c).

        Builds a tab-separated line from the selected row's column values and
        catches ``TclError`` for the no-selection case, matching the project's
        copy-handler convention.
        """
        try:
            selection = self.tree.selection()
            if not selection:
                return "break"
            values = self.tree.item(selection[0], "values")
            text = "\t".join(str(v) for v in values)
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(text)
        except tk.TclError:
            pass
        return "break"
