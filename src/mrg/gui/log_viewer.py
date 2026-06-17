"""
Log Viewer for Managed Rule Group Generator

Provides:
- GUILogHandler: A custom logging.Handler that captures log records in memory
  for display in the GUI. Records are session-only and not persisted.
- LogViewerWindow: A resizable Toplevel window that displays captured logs
  with copy-to-clipboard functionality.

Usage:
    from src.mrg.gui.log_viewer import GUILogHandler, LogViewerWindow

    # Install handler on root logger (or specific loggers)
    handler = GUILogHandler()
    logging.getLogger().addHandler(handler)

    # Open the viewer window
    LogViewerWindow(parent, handler)
"""

import logging
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from typing import List


class GUILogHandler(logging.Handler):
    """Custom logging handler that stores log records in memory.

    Thread-safe. Records are kept for the lifetime of the handler
    (i.e., the current application session) and are never persisted
    to disk.

    Attributes:
        records: List of formatted log entry dicts.
    """

    def __init__(self, level=logging.DEBUG):
        super().__init__(level)
        self._records: List[dict] = []
        self._lock_records = threading.Lock()
        self.setFormatter(logging.Formatter(
            '%(asctime)s  %(levelname)-8s  %(name)s  %(message)s',
            datefmt='%H:%M:%S',
        ))

    def emit(self, record: logging.LogRecord) -> None:
        """Store a log record.

        Args:
            record: The log record emitted by the logging framework.
        """
        try:
            formatted = self.format(record)
            entry = {
                'timestamp': datetime.fromtimestamp(record.created).strftime('%H:%M:%S.%f')[:-3],
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'formatted': formatted,
            }
            with self._lock_records:
                self._records.append(entry)
        except Exception:
            self.handleError(record)

    def get_records(self) -> List[dict]:
        """Return a snapshot of all captured records.

        Returns:
            List of log entry dicts (copy).
        """
        with self._lock_records:
            return list(self._records)

    def get_formatted_text(self) -> str:
        """Return all records as a single formatted string.

        Returns:
            Newline-separated formatted log entries.
        """
        with self._lock_records:
            return '\n'.join(r['formatted'] for r in self._records)

    def clear(self) -> None:
        """Clear all stored records."""
        with self._lock_records:
            self._records.clear()

    @property
    def record_count(self) -> int:
        """Number of stored records."""
        with self._lock_records:
            return len(self._records)


# Tag names for color-coding log levels
_LEVEL_TAGS = {
    'DEBUG': 'debug',
    'INFO': 'info',
    'WARNING': 'warning',
    'ERROR': 'error',
    'CRITICAL': 'critical',
}


class LogViewerWindow:
    """Resizable window that displays session logs.

    Features:
    - Displays all log records captured by a GUILogHandler
    - Color-coded by log level
    - Copy All to clipboard button
    - Clear button
    - Refresh button
    - Auto-scrolls to bottom on open and refresh
    - Resizable

    Args:
        parent: Parent Tk widget.
        handler: The GUILogHandler whose records to display.
    """

    def __init__(self, parent: tk.Tk, handler: GUILogHandler):
        self._parent = parent
        self._handler = handler

        self._window = tk.Toplevel(parent)
        self._window.title("Session Logs")
        self._window.geometry("900x500")
        self._window.minsize(500, 300)
        self._window.resizable(True, True)

        # Try to make it transient (stays on top of parent)
        try:
            self._window.transient(parent)
        except Exception:
            pass

        self._setup_ui()
        self._refresh_logs()

    def _setup_ui(self):
        """Build the window UI."""
        # Top info / button bar
        top_frame = ttk.Frame(self._window)
        top_frame.pack(fill=tk.X, padx=6, pady=(6, 2))

        self._count_label = ttk.Label(top_frame, text="")
        self._count_label.pack(side=tk.LEFT)

        # Filter by level
        ttk.Label(top_frame, text="  Level:").pack(side=tk.LEFT, padx=(12, 2))
        self._level_var = tk.StringVar(value="ALL")
        level_combo = ttk.Combobox(
            top_frame, textvariable=self._level_var,
            values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            state='readonly', width=10,
        )
        level_combo.pack(side=tk.LEFT)
        level_combo.bind('<<ComboboxSelected>>', lambda e: self._refresh_logs())

        # Buttons on the right
        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(side=tk.RIGHT)

        ttk.Button(btn_frame, text="Refresh", command=self._refresh_logs).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Copy All", command=self._copy_to_clipboard).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Clear", command=self._clear_logs).pack(side=tk.LEFT, padx=2)

        # Text area with scrollbar
        text_frame = ttk.Frame(self._window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(2, 6))

        self._scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._text = tk.Text(
            text_frame,
            wrap=tk.NONE,
            font=('Consolas', 9) if tk.TkVersion >= 8.5 else ('Courier', 9),
            state=tk.DISABLED,
            yscrollcommand=self._scrollbar.set,
        )
        self._text.pack(fill=tk.BOTH, expand=True)
        self._scrollbar.config(command=self._text.yview)

        # Horizontal scrollbar
        self._hscrollbar = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL, command=self._text.xview)
        self._hscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self._text.config(xscrollcommand=self._hscrollbar.set)

        # Configure level color tags
        self._text.tag_configure('debug', foreground='#888888')
        self._text.tag_configure('info', foreground='#000000')
        self._text.tag_configure('warning', foreground='#B8860B')
        self._text.tag_configure('error', foreground='#CC0000')
        self._text.tag_configure('critical', foreground='#FFFFFF', background='#CC0000')

    def _refresh_logs(self):
        """Reload logs from the handler into the text widget."""
        records = self._handler.get_records()
        level_filter = self._level_var.get()

        if level_filter != "ALL":
            records = [r for r in records if r['level'] == level_filter]

        self._text.config(state=tk.NORMAL)
        self._text.delete('1.0', tk.END)

        for rec in records:
            tag = _LEVEL_TAGS.get(rec['level'], 'info')
            self._text.insert(tk.END, rec['formatted'] + '\n', tag)

        self._text.config(state=tk.DISABLED)

        # Auto-scroll to bottom
        self._text.see(tk.END)

        # Update count
        total = self._handler.record_count
        shown = len(records)
        if level_filter == "ALL":
            self._count_label.config(text="{} log entries".format(total))
        else:
            self._count_label.config(text="{} of {} entries (filtered: {})".format(shown, total, level_filter))

    def _copy_to_clipboard(self):
        """Copy all displayed log text to the system clipboard."""
        text_content = self._text.get('1.0', tk.END).strip()
        if not text_content:
            return
        self._window.clipboard_clear()
        self._window.clipboard_append(text_content)

        # Brief visual feedback
        original = self._count_label.cget('text')
        self._count_label.config(text="Copied to clipboard!")
        self._window.after(1500, lambda: self._count_label.config(text=original))

    def _clear_logs(self):
        """Clear all stored log records."""
        self._handler.clear()
        self._refresh_logs()

    def focus(self):
        """Bring the window to front."""
        try:
            self._window.lift()
            self._window.focus_force()
        except Exception:
            pass

    @property
    def is_open(self) -> bool:
        """Check if the window is still open."""
        try:
            return self._window.winfo_exists()
        except Exception:
            return False