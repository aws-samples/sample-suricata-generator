"""
Squid configuration import: GUI (File > Import Squid Configuration...).

UI orchestrator only. The conversion runs in the UI-free Import_Core
(squid_import_core.py) on a worker thread; this module shows the options
dialog, the Conversion Report and puts the accepted rules into the editor as
a new, untitled file.

Window flow:
  options dialog (feature window)  --Convert-->  Conversion Report (its child)
  report Cancel  -> back to the options dialog, same file and options
  Import Rules   -> rules into the editor, both windows close
  closing the options dialog -> the import ends, editor unchanged

The converter is loaded on first use, so it adds nothing to Generator
start-up, and a converter that fails to load shows an error instead of
breaking the Generator.
"""

from __future__ import annotations

import os
import platform as _plat
import queue
import subprocess as _sp
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# macOS dark mode (same pattern as src/gui/ai_assistant_panel.py).
_is_dark = False
if _plat.system() == 'Darwin':
    try:
        _r = _sp.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                     capture_output=True, text=True)
        _is_dark = 'Dark' in _r.stdout
    except Exception:
        pass

_DARK = {
    "banner_bg": "#5a1d1d", "banner_fg": "#ffd7d7",
    "warn_bg": "#4a3b10", "warn_fg": "#ffe9a8",
    "ok_fg": "#7fd17f", "bad_fg": "#ff8a8a",
    "muted_fg": "#a0a0a0", "link_fg": "#6cb6ff",
    "text_bg": "#1e1e1e", "text_fg": "#e6e6e6",
}
_LIGHT = {
    "banner_bg": "#fde2e2", "banner_fg": "#8a1010",
    "warn_bg": "#fff4d1", "warn_fg": "#6b4e00",
    "ok_fg": "#1e7b1e", "bad_fg": "#b00020",
    "muted_fg": "#666666", "link_fg": "#0a58ca",
    "text_bg": "#ffffff", "text_fg": "#000000",
}
PALETTE = _DARK if _is_dark else _LIGHT

FOLDER_NOTE = (
    "Copy the contents of the Squid server's config folder (usually "
    "/etc/squid/) into the folder with squid.conf, keeping subfolders such "
    "as conf.d/. A path in the config like /etc/squid/blocked.txt is looked "
    "for as blocked.txt in this folder. Nothing outside this folder is read.")

HELP_TEXT = """Import Squid Configuration

What it does
Squid is a web proxy. Its squid.conf decides which web requests are allowed with "acl" lines (named conditions such as client addresses, domains or URL patterns) and "http_access allow|deny" lines (Squid uses the first line that matches). The import turns those lines into AWS Network Firewall Suricata rules, in the same first-match order, and puts them in the editor as a new, untitled file.

What converts
- Client addresses (src), destination addresses (dst) and ports, as rule addresses and address variables.
- Domains (dstdomain, ssl::server_name) and domain patterns, as http.host / tls.sni matches.
- URL, path, method, header, browser and MIME type conditions, as http rules.
- Each allow becomes pass (optionally with alert); each deny becomes reject or drop.

What is reported instead of converted
Anything with no firewall rule equivalent - proxy authentication, external helpers, time ranges, connection limits, response checks (http_reply_access) and similar - is listed under "Not convertible" with the reason, and no rule is made for that line. A condition is never silently dropped. The report also lists policy divergences (places the converted policy can't behave exactly like Squid), config read problems (for example a list file that is missing from the folder), notes, the HTTPS / SslBump analysis and the directives that are not access rules.

Files
Put squid.conf and every file it includes or lists in one folder (subfolders such as conf.d/ are fine). Nothing outside that folder is read, and helper programs named in the config are never run.

Firewall prerequisites (also in the report)
- Load the rules into a stateful rule group with STRICT_ORDER, in a strict-order firewall policy.
- Policy default actions: "Application drop established" and "Application alert established". To monitor first, export with the Generator's test mode.
- Keep the generated DNS rule first (the proxy's own name lookups).
- If the source Squid decrypts HTTPS (ssl_bump bump): set up TLS inspection for the clients' HTTPS traffic and block QUIC (UDP 443).
- With "Use Route 53 resolved domains": Route 53 resolved IP validation on the policy, and 169.254.169.253/32 in "Bypass destination validation IP ranges".

More detail: docs/squid_conversion_reference.md in the Generator folder.
"""


def _mousewheel(widget):
    def handler(event):
        if event.num == 4:
            widget.yview_scroll(-3, "units")
        elif event.num == 5:
            widget.yview_scroll(3, "units")
        else:
            widget.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"
    return handler


def _bind_scroll(source, target):
    h = _mousewheel(target)
    source.bind("<MouseWheel>", h)
    source.bind("<Button-4>", h)
    source.bind("<Button-5>", h)


def _readonly_text(parent, root, content, height=12):
    """A read-only, scrollable, copyable text area in `parent`."""
    frame = ttk.Frame(parent)
    text = tk.Text(frame, wrap=tk.WORD, height=height, bg=PALETTE["text_bg"],
                   fg=PALETTE["text_fg"], insertbackground=PALETTE["text_fg"])
    sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
    text.configure(yscrollcommand=sb.set)
    sb.pack(side=tk.RIGHT, fill=tk.Y)
    text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    text.insert("1.0", content)
    text.configure(state=tk.DISABLED)

    def copy(event=None):
        try:
            sel = text.get(tk.SEL_FIRST, tk.SEL_LAST)
            root.clipboard_clear()
            root.clipboard_append(sel)
        except tk.TclError:
            pass
        return "break"
    text.bind("<Control-c>", copy)
    text.bind("<Command-c>", copy)
    _bind_scroll(text, text)
    return frame, text


class SquidImporter:
    """File > Import Squid Configuration."""

    def __init__(self, parent_app):
        self.parent = parent_app
        self._landing = None            # the options dialog (feature window)
        self._report = None
        self._options = {               # remembered for the session
            "config_path": "",
            "deny_action": "reject",
            "alert_on_pass": True,
            "add_comments": True,
            "stable_sids": False,
            "route53": False,
        }
        self._busy = False

    # ------------------------------------------------------------------
    # Focus helpers (feature-window convention)
    # ------------------------------------------------------------------
    def _dialog_parent(self):
        if self._landing is not None and self._landing.winfo_exists():
            return self._landing
        return self.parent.root

    def _focus_landing(self):
        try:
            if self._landing is not None and self._landing.winfo_exists():
                self._landing.lift()
                self._landing.focus_force()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def import_configuration(self):
        """Menu entry: prompt for unsaved changes, then the options dialog."""
        if self._landing is not None and self._landing.winfo_exists():
            self._focus_landing()
            return
        if self.parent.modified and not self.parent.ask_save_changes():
            return
        try:
            from src.importers import squid_import_core  # noqa: F401  (lazy load)
        except Exception as e:                            # noqa: BLE001
            messagebox.showerror(
                "Import Squid Configuration",
                "The Squid converter could not be loaded, so the import is "
                "not available. The rest of the Generator is unaffected.\n\n"
                "%s: %s" % (type(e).__name__, e))
            return
        self._show_options_dialog()

    # ------------------------------------------------------------------
    # Options dialog (mockup 02)
    # ------------------------------------------------------------------
    def _show_options_dialog(self):
        dlg = tk.Toplevel(self.parent.root)
        self._landing = dlg
        dlg.title("Import Squid Configuration")
        dlg.geometry("720x640")
        dlg.minsize(640, 560)
        dlg.resizable(True, True)
        try:
            dlg.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 120,
                                      self.parent.root.winfo_rooty() + 60))
        except tk.TclError:
            pass

        o = self._options
        path_var = tk.StringVar(value=o["config_path"])
        deny_var = tk.StringVar(value=o["deny_action"])
        alert_var = tk.BooleanVar(value=o["alert_on_pass"])
        comments_var = tk.BooleanVar(value=o["add_comments"])
        stable_var = tk.BooleanVar(value=o["stable_sids"])
        r53_var = tk.BooleanVar(value=o["route53"])
        self._vars = (path_var, deny_var, alert_var, comments_var, stable_var, r53_var)

        # Buttons first, at the bottom (always visible).
        buttons = ttk.Frame(dlg)
        buttons.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=10)
        ttk.Button(buttons, text="Help", command=self._show_help).pack(side=tk.LEFT)
        convert_btn = ttk.Button(buttons, text="Convert", command=self._on_convert)
        convert_btn.pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Cancel", command=self._close_landing).pack(
            side=tk.RIGHT, padx=(0, 6))
        self._convert_btn = convert_btn
        ttk.Label(dlg, text="Options are remembered for the rest of this session.",
                  foreground=PALETTE["muted_fg"]).pack(side=tk.BOTTOM, anchor=tk.W, padx=14)

        # Scrollable content area.
        outer = ttk.Frame(dlg)
        outer.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(outer, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        body = ttk.Frame(canvas, padding=12)
        win = canvas.create_window((0, 0), window=body, anchor=tk.NW)
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        _bind_scroll(canvas, canvas)

        wrap = 620

        # -- file -------------------------------------------------------
        file_box = ttk.LabelFrame(body, text="Squid configuration", padding=10)
        file_box.pack(fill=tk.X)
        row = ttk.Frame(file_box)
        row.pack(fill=tk.X)
        ttk.Label(row, text="Config file:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=path_var).pack(side=tk.LEFT, fill=tk.X,
                                                   expand=True, padx=6)

        def browse():
            name = filedialog.askopenfilename(
                parent=dlg, title="Select squid.conf",
                filetypes=[("Squid configuration", "squid.conf"),
                           ("Config files", "*.conf"), ("All files", "*.*")])
            if name:
                path_var.set(name)
            self._focus_landing()
        ttk.Button(row, text="Browse\u2026", command=browse).pack(side=tk.RIGHT)
        ttk.Label(file_box, text=FOLDER_NOTE, wraplength=wrap, justify=tk.LEFT,
                  foreground=PALETTE["muted_fg"]).pack(anchor=tk.W, pady=(8, 0))

        # -- options ----------------------------------------------------
        opt_box = ttk.LabelFrame(body, text="Conversion options", padding=10)
        opt_box.pack(fill=tk.X, pady=(10, 0))
        deny_row = ttk.Frame(opt_box)
        deny_row.pack(fill=tk.X)
        ttk.Label(deny_row, text='Squid "deny" becomes:').pack(side=tk.LEFT)
        ttk.Radiobutton(deny_row, text="reject", value="reject",
                        variable=deny_var).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Radiobutton(deny_row, text="drop", value="drop",
                        variable=deny_var).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Label(opt_box, text="reject blocks and tells the client; drop blocks "
                                "silently. To monitor first, use test mode when "
                                "exporting.",
                  wraplength=wrap, foreground=PALETTE["muted_fg"]).pack(anchor=tk.W)

        def check(text, var, hint, command=None):
            ttk.Checkbutton(opt_box, text=text, variable=var,
                            command=command).pack(anchor=tk.W, pady=(8, 0))
            ttk.Label(opt_box, text=hint, wraplength=wrap - 20,
                      foreground=PALETTE["muted_fg"]).pack(anchor=tk.W, padx=(22, 0))

        check("Alert on pass", alert_var,
              "adds the alert keyword to pass rules so allowed traffic is logged")
        check("Add Squid lines as comments", comments_var,
              "each Squid access line shown above the rules it became")
        check("Use stable (content-based) SIDs", stable_var,
              "same SIDs every time this config is converted (default: "
              "date-based SIDs)")

        r53_panel = tk.Frame(body, bg=PALETTE["warn_bg"], padx=10, pady=8)

        def toggle_r53():
            if r53_var.get():
                r53_panel.pack(fill=tk.X, pady=(10, 0), after=opt_box)
            else:
                r53_panel.pack_forget()

        check("Use Route 53 resolved domains", r53_var,
              "SNI/Host spoofing protection; converts dst host names "
              "(needs firewall policy settings, shown below when checked)",
              command=toggle_r53)

        # -- Route 53 prerequisites panel (only while checked) ------------
        from src.importers.squid import prerequisites as _pre
        tk.Label(r53_panel, text="\u26a0 Route 53 resolved domains: required firewall "
                                 "policy settings",
                 bg=PALETTE["warn_bg"], fg=PALETTE["warn_fg"],
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)
        for item in (_pre.route53(), _pre.route53_proxy_bypass()):
            for ln in item.lines:
                tk.Label(r53_panel, text="\u2022 " + ln, bg=PALETTE["warn_bg"],
                         fg=PALETTE["warn_fg"], wraplength=wrap - 30,
                         justify=tk.LEFT).pack(anchor=tk.W, pady=(2, 0))
        toggle_r53()

        dlg.protocol("WM_DELETE_WINDOW", self._close_landing)
        dlg.bind("<Escape>", lambda e: self._close_landing())
        dlg.grab_set()
        dlg.focus_force()

    def _remember(self):
        path_var, deny_var, alert_var, comments_var, stable_var, r53_var = self._vars
        self._options.update({
            "config_path": path_var.get().strip(),
            "deny_action": deny_var.get(),
            "alert_on_pass": bool(alert_var.get()),
            "add_comments": bool(comments_var.get()),
            "stable_sids": bool(stable_var.get()),
            "route53": bool(r53_var.get()),
        })

    def _close_landing(self):
        if self._busy:
            return
        try:
            self._remember()
        except (tk.TclError, AttributeError):
            pass
        for w in (self._report, self._landing):
            try:
                if w is not None and w.winfo_exists():
                    w.destroy()
            except tk.TclError:
                pass
        self._report = None
        self._landing = None
        try:
            self.parent.root.focus_force()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Small windows
    # ------------------------------------------------------------------
    def _show_text_window(self, title, content, parent=None):
        win = tk.Toplevel(parent or self._dialog_parent())
        win.title(title)
        win.geometry("620x460")
        win.minsize(420, 300)
        win.resizable(True, True)

        def close():
            win.destroy()
            if self._report is not None and self._report.winfo_exists():
                self._report.lift()
                self._report.focus_force()
            else:
                self._focus_landing()
        ttk.Button(win, text="Close", command=close).pack(side=tk.BOTTOM, pady=8)
        frame, _text = _readonly_text(win, self.parent.root, content, height=18)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))
        win.protocol("WM_DELETE_WINDOW", close)
        win.focus_force()
        return win

    def _show_help(self):
        self._show_text_window("Import Squid Configuration - Help", HELP_TEXT)

    # ------------------------------------------------------------------
    # Convert (worker thread + progress)
    # ------------------------------------------------------------------
    def _build_options(self):
        from src.importers.squid import ConvertOptions
        from src.importers.squid_import_core import ImportOptions
        o = self._options
        return ImportOptions(
            convert=ConvertOptions(deny_action=o["deny_action"],
                                   alert_on_pass=o["alert_on_pass"],
                                   route53_resolved_domains=o["route53"]),
            add_comments=o["add_comments"], stable_sids=o["stable_sids"])

    def _on_convert(self):
        if self._busy:
            return
        self._remember()
        path = self._options["config_path"]
        if not path:
            messagebox.showerror("Import Squid Configuration",
                                 "Select a squid.conf file first.", parent=self._landing)
            self._focus_landing()
            return
        if not os.path.isfile(path):
            messagebox.showerror("Import Squid Configuration",
                                 "File not found:\n%s" % path, parent=self._landing)
            self._focus_landing()
            return
        options = self._build_options()
        self._start_worker(path, options)

    def _start_worker(self, path, options):
        from src.importers.squid_import_core import run_import
        results = queue.Queue()
        state = {"cancelled": False, "progress": None}
        self._busy = True
        self._convert_btn.configure(state=tk.DISABLED)

        def work():
            try:
                plan = run_import(path, options,
                                  progress=lambda s: results.put(("step", s)))
                results.put(("done", plan))
            except (OSError, ValueError) as e:
                results.put(("read_error", e))
            except Exception as e:                      # noqa: BLE001
                results.put(("error", e))

        threading.Thread(target=work, daemon=True).start()
        started = [0]

        def finish():
            self._busy = False
            prog = state["progress"]
            if prog is not None:
                try:
                    prog["win"].grab_release()
                    prog["win"].destroy()
                except tk.TclError:
                    pass
            try:
                self._convert_btn.configure(state=tk.NORMAL)
                self._landing.grab_set()
            except (tk.TclError, AttributeError):
                pass

        def poll():
            if self._landing is None or not self._landing.winfo_exists():
                self._busy = False
                return
            started[0] += 100
            try:
                while True:
                    kind, value = results.get_nowait()
                    if kind == "step":
                        if state["progress"] is not None:
                            state["progress"]["label"].configure(text=value + "\u2026")
                        continue
                    finish()
                    if state["cancelled"]:
                        self._focus_landing()
                        return
                    if kind == "done":
                        self._show_report(value)
                    elif kind == "read_error":
                        messagebox.showerror(
                            "Import Squid Configuration",
                            "The configuration could not be read:\n%s" % value,
                            parent=self._landing)
                        self._focus_landing()
                    else:
                        messagebox.showerror(
                            "Import Squid Configuration",
                            "The conversion failed (a converter defect; please "
                            "report it with the config):\n%s: %s"
                            % (type(value).__name__, value), parent=self._landing)
                        self._focus_landing()
                    return
            except queue.Empty:
                pass
            if state["progress"] is None and started[0] >= 300:
                state["progress"] = self._show_progress(state)
            self.parent.root.after(100, poll)

        self.parent.root.after(100, poll)

    def _show_progress(self, state):
        win = tk.Toplevel(self._landing)
        win.title("Converting")
        win.geometry("360x130")
        win.minsize(320, 120)
        win.resizable(True, True)
        label = ttk.Label(win, text="Converting\u2026")

        def cancel():
            state["cancelled"] = True
            label.configure(text="Cancelling\u2026")
        ttk.Button(win, text="Cancel", command=cancel).pack(side=tk.BOTTOM, pady=8)
        label.pack(pady=(14, 6))
        bar = ttk.Progressbar(win, mode="indeterminate", length=280)
        bar.pack()
        bar.start(12)
        win.protocol("WM_DELETE_WINDOW", cancel)
        try:
            win.grab_set()
        except tk.TclError:
            pass
        return {"win": win, "label": label}

    # ------------------------------------------------------------------
    # Conversion Report (mockups 03, 03a-03f)
    # ------------------------------------------------------------------
    @staticmethod
    def report_tabs(plan):
        """[(tab label, text)] for the report window, from the plan.

        Kept free of tkinter so it can be tested headlessly.
        """
        from src.importers.squid import report_sections
        r = plan.result
        sections = {key: (title, lines) for key, title, lines in report_sections(r)}

        def text_of(*keys):
            out = []
            for key in keys:
                if key in sections:
                    title, lines = sections[key]
                    if len(keys) > 1:
                        out.append(title)
                    out.extend(lines)
                    out.append("")
            return "\n".join(out).strip() or "(none)"

        def blocks(items):
            return "\n\n".join(items) if items else "(none)"

        extra = dict(plan.extra_sections)
        prereq = text_of("prerequisites") + "\n\n" + "\n".join(extra.get("SIDs", []))
        validation = "\n".join(extra.get("VALIDATION", [])) + "\n\n" + \
            "\n".join(r.accounting_text)
        return [
            ("Not convertible (%d)" % len(r.not_convertible), blocks(r.not_convertible)),
            ("Firewall prerequisites", prereq),
            ("Notes (%d)" % len(r.notes), blocks(r.notes)),
            ("HTTPS / SslBump", text_of("sslbump", "sslbump_acls")),
            ("Directives reported (%d)" % len(r.unhandled), blocks(r.unhandled)),
            ("Validation", validation),
            ("Full text", plan.report_text),
        ]

    @staticmethod
    def banner_lines(plan):
        """Lines for the red banner (empty when nothing needs attention)."""
        r = plan.result
        out = []
        if not r.accounting_ok:
            out.append("CONVERTER ERROR: the accounting check failed, so the rules "
                       "can't be imported (see the Validation tab).")
        if plan.hard_save_error:
            out.append("SAVE CHECK FAILED: %s. The rules can't be imported."
                       % plan.hard_save_error)
        if r.divergences:
            out.append("Policy divergences (the converted policy differs from "
                       "Squid) - read these first:")
            out.extend("\u2022 " + d for d in r.divergences)
        if r.problems:
            out.append("Config read problems (the output may be incomplete):")
            out.extend("\u2022 " + p for p in r.problems)
        return out

    def _show_report(self, plan):
        dlg = self._landing
        rep = tk.Toplevel(dlg)
        self._report = rep
        name = os.path.basename(self._options["config_path"])
        rep.title("Squid Conversion Report \u2014 %s (converter v%s)"
                  % (name, plan.result.converter_version))
        rep.geometry("980x700")
        rep.minsize(760, 520)
        rep.resizable(True, True)
        r = plan.result

        # Buttons first (bottom).
        buttons = ttk.Frame(rep)
        buttons.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=10)
        import_btn = ttk.Button(buttons, text="Import Rules",
                                command=lambda: self._import_plan(plan))
        import_btn.pack(side=tk.RIGHT)
        if not plan.can_import:
            import_btn.configure(state=tk.DISABLED)
        ttk.Button(buttons, text="Cancel", command=self._close_report).pack(
            side=tk.RIGHT, padx=(0, 6))
        ttk.Button(buttons, text="Save Report\u2026",
                   command=lambda: self._save_report(plan)).pack(side=tk.LEFT)
        # Opens the Squid conversion issue form. Only the feedback type is
        # passed; nothing from the plan or the user's Squid config is sent.
        from src.gui.feedback_dialog import add_feedback_button
        add_feedback_button(buttons, rep, "squid_conversion",
                            on_close=self._refocus_report,
                            side=tk.LEFT, padx=(6, 0))

        # Summary strip.
        strip = ttk.Frame(rep, padding=(12, 10, 12, 4))
        strip.pack(side=tk.TOP, fill=tk.X)
        for count, label in ((plan.rule_count, "rules"), (len(plan.variables), "variables"),
                             (len(r.divergences), "divergences"),
                             (len(r.not_convertible), "not convertible"),
                             (len(r.notes), "notes"), (len(r.problems), "config problems")):
            cell = ttk.Frame(strip)
            cell.pack(side=tk.LEFT, padx=(0, 18))
            ttk.Label(cell, text=str(count), font=("TkDefaultFont", 14, "bold")).pack()
            ttk.Label(cell, text=label, foreground=PALETTE["muted_fg"]).pack()
        status = ttk.Frame(strip)
        status.pack(side=tk.RIGHT)
        v_ok = not plan.group_errors and not plan.parse_errors and not plan.hard_save_error
        tk.Label(status, text=("\u2713 Validator: no errors" if v_ok else
                               "\u2717 Validator: errors (see Validation)"),
                 fg=PALETTE["ok_fg"] if v_ok else PALETTE["bad_fg"]).pack(anchor=tk.E)
        tk.Label(status, text=("\u2713 Accounting complete" if r.accounting_ok
                               else "\u2717 Accounting FAILED"),
                 fg=PALETTE["ok_fg"] if r.accounting_ok else PALETTE["bad_fg"]).pack(anchor=tk.E)

        # Red banner.
        banner = self.banner_lines(plan)
        if banner:
            bframe = tk.Frame(rep, bg=PALETTE["banner_bg"])
            bframe.pack(side=tk.TOP, fill=tk.X, padx=12, pady=(4, 6))
            btext = tk.Text(bframe, height=min(8, 2 + len(banner)), wrap=tk.WORD,
                            bg=PALETTE["banner_bg"], fg=PALETTE["banner_fg"],
                            relief=tk.FLAT, padx=8, pady=6)
            bsb = ttk.Scrollbar(bframe, orient=tk.VERTICAL, command=btext.yview)
            btext.configure(yscrollcommand=bsb.set)
            bsb.pack(side=tk.RIGHT, fill=tk.Y)
            btext.pack(side=tk.LEFT, fill=tk.X, expand=True)
            btext.insert("1.0", "\n".join(banner))
            btext.configure(state=tk.DISABLED)
            _bind_scroll(btext, btext)

            def copy_banner(event=None):
                try:
                    sel = btext.get(tk.SEL_FIRST, tk.SEL_LAST)
                    self.parent.root.clipboard_clear()
                    self.parent.root.clipboard_append(sel)
                except tk.TclError:
                    pass
                return "break"
            btext.bind("<Control-c>", copy_banner)
            btext.bind("<Command-c>", copy_banner)

        # Tabs.
        nb = ttk.Notebook(rep)
        nb.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=12)
        for label, content in self.report_tabs(plan):
            frame, _t = _readonly_text(nb, self.parent.root, content, height=14)
            nb.add(frame, text=label)

        rep.protocol("WM_DELETE_WINDOW", self._close_report)
        rep.bind("<Escape>", lambda e: self._close_report())
        try:
            dlg.grab_release()
        except tk.TclError:
            pass
        rep.grab_set()
        rep.focus_force()

    def _refocus_report(self):
        """Give the report its grab and focus back after the feedback dialog."""
        try:
            if self._report is not None and self._report.winfo_exists():
                self._report.grab_set()
                self._report.lift()
                self._report.focus_force()
        except tk.TclError:
            pass

    def _close_report(self):
        """Cancel on the report: back to the options dialog, same options."""
        if self._report is not None:
            try:
                self._report.grab_release()
                self._report.destroy()
            except tk.TclError:
                pass
        self._report = None
        try:
            if self._landing is not None and self._landing.winfo_exists():
                self._landing.grab_set()
        except tk.TclError:
            pass
        self._focus_landing()

    @staticmethod
    def report_content_for(plan, path):
        """The report text to write for a chosen save path: the HTML report
        for a .html/.htm path, otherwise the plain-text report. Kept free of
        tkinter so the format choice is testable headlessly."""
        if path.lower().endswith((".html", ".htm")):
            return plan.report_html
        return plan.report_text

    def _save_report(self, plan):
        stem = os.path.splitext(os.path.basename(self._options["config_path"]))[0]
        name = filedialog.asksaveasfilename(
            parent=self._report, title="Save Conversion Report",
            defaultextension=".html", initialfile="%s-conversion-report.html" % stem,
            filetypes=[("HTML files", "*.html"), ("Text files", "*.txt"),
                       ("All files", "*.*")])
        if name:
            content = self.report_content_for(plan, name)
            try:
                with open(name, "w", encoding="utf-8") as fh:
                    fh.write(content)
                messagebox.showinfo("Save Report", "Report saved:\n%s" % name,
                                    parent=self._report)
            except OSError as e:
                messagebox.showerror("Save Report",
                                     "The report could not be saved:\n%s" % e,
                                     parent=self._report)
        if self._report is not None and self._report.winfo_exists():
            self._report.lift()
            self._report.focus_force()

    # ------------------------------------------------------------------
    # Import into the editor (mockup 04)
    # ------------------------------------------------------------------
    def apply_plan(self, plan):
        """Put the plan in the editor as a new, untitled, modified file."""
        app = self.parent
        app.save_undo_state()
        app.reset_to_new_file()
        app.rules = list(plan.rows)
        app.variables.update({k: dict(v) for k, v in plan.variables.items()})
        app.current_file = None
        app.modified = True
        app.refresh_table(preserve_selection=False)
        app.auto_detect_variables()
        app.refresh_tags_table()
        app.update_status_bar()
        if hasattr(app, "_invalidate_ai_cache"):
            app._invalidate_ai_cache()

    def _import_plan(self, plan):
        if not plan.can_import:
            return
        self._close_landing_after_import()
        self.apply_plan(plan)

    def _close_landing_after_import(self):
        self._busy = False
        for w in (self._report, self._landing):
            try:
                if w is not None and w.winfo_exists():
                    w.grab_release()
                    w.destroy()
            except tk.TclError:
                pass
        self._report = None
        self._landing = None
