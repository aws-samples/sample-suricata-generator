"""
Send Feedback dialog (tkinter layer for Help > Send Feedback).

Thin UI over the UI-free src/core/feedback.py. The dialog shows the
privacy notice and exactly the environment details that will be placed in
the GitHub issue form, then asks the operating system to open the form's
URL in the user's browser. It never signs in, never contacts GitHub itself,
and never submits anything; the user reviews and submits the form on GitHub.

Public entry points:

- open_feedback_dialog(parent, ...) opens the modal dialog.
- add_feedback_button(button_frame, owner_window, type_key, ...) adds a
  "Report a ... Issue" button to any feature window in one call. The dialog
  it opens is locked to that feedback type.
"""

from __future__ import annotations

import platform as _plat
import subprocess as _sp
import tkinter as tk
import webbrowser
from tkinter import ttk
from typing import Callable, Optional

from src.core import feedback as fb


# macOS dark mode (same pattern as src/gui/ai_assistant_panel.py).
_is_dark = False
if _plat.system() == 'Darwin':
    try:
        _r = _sp.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                     capture_output=True, text=True)
        _is_dark = 'Dark' in _r.stdout
    except Exception:
        pass
# Values match the Squid conversion report's palette so the two look alike.
_DARK = {
    "warn_bg": "#4a3b10", "warn_fg": "#ffe9a8",
    "ok_fg": "#7fd17f", "bad_fg": "#ff8a8a",
    "muted_fg": "#a0a0a0",
    "text_bg": "#1e1e1e", "text_fg": "#e6e6e6",
}
_LIGHT = {
    "warn_bg": "#fff4d1", "warn_fg": "#6b4e00",
    "ok_fg": "#1e7b1e", "bad_fg": "#b00020",
    "muted_fg": "#666666",
    "text_bg": "#ffffff", "text_fg": "#000000",
}
PALETTE = _DARK if _is_dark else _LIGHT

ACCOUNT_NOTE = (
    "You'll need a free GitHub account. GitHub will ask you to sign in if "
    "needed. If the form opens without these details, use Copy to Clipboard "
    "and paste them into the form."
)
DETAILS_LABEL = "These details will be added to the form (nothing else is sent):"
BROWSER_FAILED = ("Couldn't open your web browser. Copy this link and open it "
                  "yourself:")
COPY_FAILED = "Couldn't copy; select the text and press Ctrl+C"

# Tip shown for the conversion feedback types.
_CONVERSION_TIPS = {
    "squid_conversion": (
        "Tip: in the form, paste only the smallest Squid snippet that shows "
        "the problem, with placeholder values, not your full squid.conf."),
    "palo_alto_conversion": (
        "Tip: in the form, paste only the smallest XML excerpt that shows the "
        "problem, with placeholder values, not your full configuration export."),
}
_GENERIC_CONVERSION_TIP = (
    "Tip: in the form, paste only the smallest snippet that shows the problem, "
    "with placeholder values, not your full configuration.")

_COPIED_MS = 3000


def _tip_for(ft: fb.FeedbackType) -> str:
    if not ft.is_conversion:
        return ""
    return _CONVERSION_TIPS.get(ft.key, _GENERIC_CONVERSION_TIP)


def _title_for(ft: fb.FeedbackType, locked: bool) -> str:
    if not locked:
        return "Send Feedback"
    if ft.is_conversion:
        return "Report a " + ft.display_name.title()
    return "Send Feedback: " + ft.display_name


class _FeedbackDialog:
    """The modal Feedback_Dialog. Create it through open_feedback_dialog()."""

    def __init__(self, parent: tk.Misc, feedback_type_key: Optional[str],
                 feature_area: Optional[str], lock_type: bool,
                 on_close: Optional[Callable[[], None]]):
        self._parent = parent
        self._locked = lock_type
        self._on_close = on_close
        self._closed = False
        self._copied_after = None
        self._fallback = None
        self._fallback_url = tk.StringVar()

        self._type = fb.get_feedback_type(
            feedback_type_key or fb.DEFAULT_FEEDBACK_TYPE_KEY)
        if feature_area is not None and feature_area not in fb.FEATURE_AREAS:
            raise ValueError("unknown feature area: %r" % feature_area)
        self._initial_area = feature_area or fb.DEFAULT_FEATURE_AREA

        win = tk.Toplevel(parent)
        self.win = win
        win.title(_title_for(self._type, lock_type))
        win.geometry("640x600")
        win.minsize(540, 500)
        win.resizable(True, True)
        try:
            win.geometry("+%d+%d" % (parent.winfo_rootx() + 60,
                                     parent.winfo_rooty() + 40))
        except tk.TclError:
            pass
        win.protocol("WM_DELETE_WINDOW", self._close)
        win.bind("<Escape>", lambda e: self._close())
        win.bind("<Return>", lambda e: self._open_in_browser())

        # Collected once; the Text widget, the clipboard and the URL all use
        # this same text, so what the user sees is exactly what is sent.
        try:
            patch = str(win.tk.call("info", "patchlevel"))
        except Exception:
            patch = None
        self._env_text = fb.format_environment_info(
            fb.collect_environment_info(patch))

        self._build_buttons()
        self._build_content()
        self._apply_type()

        try:
            win.grab_set()
        except tk.TclError:
            win.after(100, self._retry_grab)
        self._open_btn.focus_set()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_buttons(self):
        win = self.win
        # Buttons first (bottom) so they stay visible at any size.
        bar = ttk.Frame(win, padding=(12, 8, 12, 12))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Button(bar, text="Copy to Clipboard",
                   command=self._copy_env).pack(side=tk.LEFT)
        self._copied = tk.Label(bar, text="", fg=PALETTE["ok_fg"])
        self._copied.pack(side=tk.LEFT, padx=(8, 0))
        self._open_btn = ttk.Button(bar, text="Open in Browser",
                                    command=self._open_in_browser,
                                    default="active")
        self._open_btn.pack(side=tk.RIGHT)
        ttk.Button(bar, text="Cancel", command=self._close).pack(
            side=tk.RIGHT, padx=(0, 6))
        self._sep = ttk.Separator(win, orient=tk.HORIZONTAL)
        self._sep.pack(side=tk.BOTTOM, fill=tk.X, padx=12)

    def _build_content(self):
        c = ttk.Frame(self.win, padding=(16, 14, 16, 6))
        c.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self._content = c
        self._wrap_labels = []

        # Feedback type: dropdown, or a fixed label when locked.
        type_row = ttk.Frame(c)
        type_row.pack(side=tk.TOP, fill=tk.X)
        type_row.columnconfigure(1, weight=1)
        if self._locked:
            ttk.Label(type_row, text="Form:").grid(row=0, column=0, sticky=tk.W)
            ttk.Label(type_row, text=self._type.display_name,
                      font=("TkDefaultFont", 9, "bold")).grid(
                row=0, column=1, sticky=tk.W, padx=(8, 0))
            self._type_combo = None
        else:
            ttk.Label(type_row, text="Feedback type:").grid(
                row=0, column=0, sticky=tk.W)
            self._type_combo = ttk.Combobox(
                type_row, state="readonly", width=40,
                values=[ft.display_name for ft in fb.FEEDBACK_TYPES])
            self._type_combo.current(fb.FEEDBACK_TYPES.index(self._type))
            self._type_combo.grid(row=0, column=1, sticky=tk.W, padx=(8, 0))
            self._type_combo.bind("<<ComboboxSelected>>",
                                  lambda e: self._on_type_selected())
        self._desc = tk.Label(type_row, text="", fg=PALETTE["muted_fg"],
                              justify=tk.LEFT, anchor=tk.W)
        self._desc.grid(row=1, column=1, sticky=tk.W, padx=(8, 0), pady=(2, 0))

        # Holders keep their place in the layout while their contents are
        # shown or hidden for the selected type.
        area_holder = ttk.Frame(c)
        area_holder.pack(side=tk.TOP, fill=tk.X)
        self._area_row = ttk.Frame(area_holder)
        ttk.Label(self._area_row, text="Feature area:").pack(side=tk.LEFT)
        self._area_combo = ttk.Combobox(self._area_row, state="readonly",
                                        width=40, values=list(fb.FEATURE_AREAS))
        self._area_combo.current(fb.FEATURE_AREAS.index(self._initial_area))
        self._area_combo.pack(side=tk.LEFT, padx=(14, 0))

        tip_holder = ttk.Frame(c)
        tip_holder.pack(side=tk.TOP, fill=tk.X)
        self._tip = tk.Label(tip_holder, text="", justify=tk.LEFT, anchor=tk.W)
        self._wrap_labels.append(self._tip)

        # Privacy notice.
        notice = tk.Frame(c, bg=PALETTE["warn_bg"])
        notice.pack(side=tk.TOP, fill=tk.X, pady=(12, 10))
        notice_label = tk.Label(notice, text="\u26a0 " + fb.PRIVACY_NOTICE,
                                bg=PALETTE["warn_bg"], fg=PALETTE["warn_fg"],
                                justify=tk.LEFT, anchor=tk.W, padx=10, pady=8)
        notice_label.pack(fill=tk.X)
        self._wrap_labels.append(notice_label)

        # The exact details that will be sent.
        ttk.Label(c, text=DETAILS_LABEL).pack(side=tk.TOP, anchor=tk.W)
        text_frame = ttk.Frame(c)
        text_frame.pack(side=tk.TOP, fill=tk.X, expand=False, pady=(4, 8))
        self._env_widget = tk.Text(text_frame, height=9, wrap=tk.WORD,
                                   bg=PALETTE["text_bg"], fg=PALETTE["text_fg"],
                                   font=("TkFixedFont", 9))
        sb = ttk.Scrollbar(text_frame, orient=tk.VERTICAL,
                           command=self._env_widget.yview)
        self._env_widget.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._env_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._env_widget.insert("1.0", self._env_text)
        self._env_widget.configure(state=tk.DISABLED)
        self._env_widget.bind("<Control-c>", self._copy_selection)
        self._env_widget.bind("<Command-c>", self._copy_selection)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._env_widget.bind(seq, self._on_mousewheel)

        note = tk.Label(c, text=ACCOUNT_NOTE, fg=PALETTE["muted_fg"],
                        justify=tk.LEFT, anchor=tk.W)
        note.pack(side=tk.TOP, fill=tk.X)
        self._wrap_labels.append(note)

        c.bind("<Configure>", self._on_resize)

    def _on_resize(self, event):
        width = max(200, event.width - 40)
        for label in self._wrap_labels:
            try:
                label.configure(wraplength=width)
            except tk.TclError:
                pass

    # ------------------------------------------------------------------
    # Type selection
    # ------------------------------------------------------------------
    def _on_type_selected(self):
        idx = self._type_combo.current()
        if 0 <= idx < len(fb.FEEDBACK_TYPES):
            self._type = fb.FEEDBACK_TYPES[idx]
        self._apply_type()

    def _apply_type(self):
        ft = self._type
        self._desc.configure(text=ft.description)
        if ft.has_feature_area:
            self._area_row.pack(side=tk.TOP, fill=tk.X, pady=(10, 0))
        else:
            self._area_row.pack_forget()
        tip = _tip_for(ft)
        if tip:
            self._tip.configure(text=tip)
            self._tip.pack(side=tk.TOP, fill=tk.X, pady=(10, 0))
        else:
            self._tip.pack_forget()

    def _selected_area(self) -> Optional[str]:
        if not self._type.has_feature_area:
            return None
        value = self._area_combo.get()
        return value if value in fb.FEATURE_AREAS else fb.DEFAULT_FEATURE_AREA

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _open_in_browser(self):
        if self._closed:
            return
        url = fb.build_prefill_url(self._type, self._env_text,
                                   self._selected_area())
        try:
            opened = bool(webbrowser.open(url, new=2))
        except Exception:
            opened = False
        if opened:
            self._close()
        else:
            self._show_fallback(url)

    def _show_fallback(self, url: str):
        self._fallback_url.set(url)
        if self._fallback is None:
            box = ttk.Frame(self.win, padding=(16, 8, 16, 4))
            label = ttk.Label(box, text=BROWSER_FAILED, justify=tk.LEFT)
            label.pack(side=tk.TOP, anchor=tk.W)
            row = ttk.Frame(box)
            row.pack(side=tk.TOP, fill=tk.X, pady=(4, 0))
            ttk.Button(row, text="Copy Link",
                       command=self._copy_link).pack(side=tk.RIGHT, padx=(6, 0))
            entry = ttk.Entry(row, textvariable=self._fallback_url,
                              state="readonly")
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self._fallback = box
        # Above the separator and button row.
        self._fallback.pack(side=tk.BOTTOM, fill=tk.X, after=self._sep)

    def _set_clipboard(self, text: str) -> bool:
        try:
            self.win.clipboard_clear()
            self.win.clipboard_append(text)
            return True
        except tk.TclError:
            return False

    def _flash(self, ok: bool, message: str):
        if self._copied_after is not None:
            try:
                self.win.after_cancel(self._copied_after)
            except tk.TclError:
                pass
        self._copied.configure(text=message,
                               fg=PALETTE["ok_fg"] if ok else PALETTE["bad_fg"])
        self._copied_after = self.win.after(_COPIED_MS, self._clear_flash)

    def _clear_flash(self):
        self._copied_after = None
        try:
            self._copied.configure(text="")
        except tk.TclError:
            pass

    def _copy_env(self):
        if self._set_clipboard(self._env_text):
            self._flash(True, "\u2713 Copied")
        else:
            self._flash(False, COPY_FAILED)

    def _copy_link(self):
        if self._set_clipboard(self._fallback_url.get()):
            self._flash(True, "\u2713 Link copied")
        else:
            self._flash(False, COPY_FAILED)

    def _copy_selection(self, event=None) -> str:
        try:
            sel = self._env_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.win.clipboard_clear()
            self.win.clipboard_append(sel)
        except tk.TclError:
            pass
        return "break"

    def _on_mousewheel(self, event) -> str:
        if event.num == 4:
            self._env_widget.yview_scroll(-3, "units")
        elif event.num == 5:
            self._env_widget.yview_scroll(3, "units")
        elif event.delta:
            self._env_widget.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"

    def _retry_grab(self):
        try:
            if self.win.winfo_exists():
                self.win.grab_set()
        except tk.TclError:
            pass

    def _close(self):
        """Single close path: Cancel, Escape, the window X, and after opening."""
        if self._closed:
            return
        self._closed = True
        try:
            if self._copied_after is not None:
                self.win.after_cancel(self._copied_after)
        except tk.TclError:
            pass
        try:
            self.win.grab_release()
            self.win.destroy()
        except tk.TclError:
            pass
        if self._on_close is not None:
            try:
                self._on_close()
            except Exception:
                pass


def open_feedback_dialog(parent: tk.Misc,
                         feedback_type_key: Optional[str] = None,
                         feature_area: Optional[str] = None,
                         lock_type: bool = False,
                         on_close: Optional[Callable[[], None]] = None
                         ) -> _FeedbackDialog:
    """Open the modal Send Feedback dialog.

    feedback_type_key: pre-selected type (default "bug").
    feature_area:      pre-selected FEATURE_AREAS entry (types with the
                       feature-area field only).
    lock_type:         True for feature buttons: hides the type dropdown and
                       shows the fixed form name instead.
    on_close:          called after the dialog is destroyed, on every close
                       path, so the caller can restore its own grab and focus.
    """
    return _FeedbackDialog(parent, feedback_type_key, feature_area,
                           lock_type, on_close)


def _refocus(window: tk.Misc) -> None:
    """Give ``window`` its grab and focus back after the dialog closes."""
    try:
        if window is not None and window.winfo_exists():
            window.grab_set()
            window.lift()
            window.focus_force()
    except tk.TclError:
        pass


def add_feedback_button(button_frame: tk.Misc,
                        owner_window: tk.Misc,
                        feedback_type_key: str,
                        feature_area: Optional[str] = None,
                        text: str = "Report a Conversion Issue\u2026",
                        on_close: Optional[Callable[[], None]] = None,
                        **pack_kwargs) -> ttk.Button:
    """Add a feature feedback button to ``button_frame`` in one call.

    The button opens the Send Feedback dialog parented to ``owner_window``,
    locked to ``feedback_type_key`` (and with ``feature_area`` pre-selected
    for types that have the feature-area field). If ``on_close`` is None, the default
    gives ``owner_window`` its grab and focus back. Nothing from the feature
    window is passed to the dialog except the type and area.
    """
    ft = fb.get_feedback_type(feedback_type_key)
    if feature_area is not None and (not ft.has_feature_area
                                     or feature_area not in fb.FEATURE_AREAS):
        raise ValueError("invalid feature area %r for %r"
                         % (feature_area, feedback_type_key))
    if on_close is None:
        def on_close():
            _refocus(owner_window)
    btn = ttk.Button(
        button_frame, text=text,
        command=lambda: open_feedback_dialog(owner_window, feedback_type_key,
                                             feature_area, lock_type=True,
                                             on_close=on_close))
    btn.pack(**pack_kwargs)
    return btn
