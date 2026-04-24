"""
AI Assistant Panel for Suricata Rule Generator.

Provides a chat-based interface for generating Suricata rules from natural
language descriptions via Amazon Bedrock (Claude). Runs as a tk.Toplevel
window independent of the main application layout.
"""

import logging
import random
import re
import threading
import tkinter as tk
from tkinter import ttk, filedialog

# Guard boto3 import — AI features degrade gracefully when absent
HAS_BOTO3 = False
try:
    import boto3
    from botocore.exceptions import (
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
    )
    HAS_BOTO3 = True
except ImportError:
    boto3 = None

from src.agent.agent_factory import AgentFactory
from src.agent.models import GenerationResult
from src.core.suricata_rule import SuricataRule

logger = logging.getLogger(__name__)

# Bedrock-supported regions for the region dropdown
BEDROCK_REGIONS = [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "ap-northeast-1",
    "ap-southeast-1",
]

# Example prompts shown when the chat is empty — a random subset is displayed each time
_EXAMPLE_PROMPTS = [
    "Block all traffic to Russia and China",
    "Allow only HTTPS to *.amazonaws.com",
    "Detect DNS tunneling",
    "Create a default deny egress policy",
    "Block SSH on non-standard ports",
    "Detect brute force SSH login attempts",
    "Allow traffic to specific domains only",
    "Block direct-to-IP HTTP and TLS connections",
    "Detect large file uploads over 10MB",
    "Block old TLS versions 1.0 and 1.1",
    "Alert on traffic to high-risk ports",
    "Detect HTTP request smuggling attempts",
    "Block QUIC traffic to force TLS inspection",
    "Allow AWS SSM and CloudWatch endpoints",
    "Detect lateral movement via SMB admin shares",
    "Create GeoIP blocking rules for sanctioned countries",
    "Detect self-signed TLS certificates",
    "Block non-HTTP traffic on port 80",
    "Rate-limit SSH alerts to reduce logging costs",
    "Detect Kerberoasting attacks on Active Directory",
]


class AIAssistantPanel:
    """AI Rule Assistant panel — chat UI + rule insertion.

    Singleton-style: calling ``show()`` either creates the window or
    brings an existing one to the front.
    """

    def __init__(self, parent_app):
        """Initialise the panel.

        Args:
            parent_app: The main ``SuricataRuleGenerator`` instance.
        """
        self.parent = parent_app
        self.window: tk.Toplevel | None = None
        self.chat_history: list[dict] = []
        self.agent_factory: AgentFactory | None = None
        self._generating: bool = False

        # UI widget references (set during _build_ui)
        self.message_area: tk.Text | None = None
        self.input_field: tk.Text | None = None
        self.submit_btn: ttk.Button | None = None
        self.region_var: tk.StringVar | None = None
        self.model_var: tk.StringVar | None = None
        self.model_combo: ttk.Combobox | None = None

        # Track model data for mapping display names → model IDs
        self._model_list: list[dict] = []

        # Disclaimer shown once per session
        self._disclaimer_accepted: bool = False


    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #

    def show(self) -> None:
        """Create the AI panel window or bring an existing one to front."""
        # Show disclaimer on first access per session
        if not self._disclaimer_accepted:
            if not self._show_disclaimer():
                return  # User declined
            self._disclaimer_accepted = True

        if self.window is not None:
            try:
                if self.window.winfo_exists():
                    self.window.lift()
                    self.window.focus_force()
                    return
            except tk.TclError:
                pass
            # Window was destroyed — fall through to recreate
            self.window = None

        self._build_ui()

        # Replay any existing chat history into the new widget
        if self.chat_history:
            self._replay_chat_history()
        else:
            self._show_example_prompts()

        # Lazily create the AgentFactory on first show
        if self.agent_factory is None:
            self.agent_factory = AgentFactory(
                aws_session=self.parent.aws_session,
                data_dir="data/",
            )

        # Kick off initial model list load for the default region
        self._refresh_models()

    # ------------------------------------------------------------------ #
    #  Disclaimer                                                         #
    # ------------------------------------------------------------------ #

    def _show_disclaimer(self) -> bool:
        """Display a one-time disclaimer dialog. Returns True if accepted."""
        disclaimer = (
            "IMPORTANT — PLEASE READ BEFORE PROCEEDING\n\n"
            "The AI Rule Assistant uses a large language model (LLM) to generate "
            "Suricata-compatible rules for AWS Network Firewall. While the tool "
            "applies multiple validation and best-practice checks, the output is "
            "provided for informational and development purposes only.\n\n"
            "Generated rules may contain errors, produce unexpected behavior, or "
            "fail to detect the intended traffic patterns. You are solely responsible "
            "for reviewing, testing, and validating all rules before deploying them "
            "to a production environment.\n\n"
            "By clicking Accept you acknowledge that:\n\n"
            "  •  AI-generated rules require human review before production use\n"
            "  •  Rules should be tested against representative traffic (e.g., PCAP\n"
            "      files or a staging environment) before deployment\n"
            "  •  The authors of this tool accept no liability for rules generated\n"
            "      by this feature\n"
            "  •  You will not deploy AI-generated rules to production without\n"
            "      appropriate testing and approval"
        )

        dialog = tk.Toplevel(self.parent.root)
        dialog.title("AI Rule Assistant — Disclaimer")
        dialog.geometry("520x440")
        dialog.transient(self.parent.root)
        dialog.grab_set()

        # Center on parent
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 150,
            self.parent.root.winfo_rooty() + 100,
        ))

        accepted = [False]  # mutable container for closure

        # Pack buttons FIRST (at bottom) so they are always visible
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(side=tk.BOTTOM, pady=10)

        ttk.Button(
            btn_frame, text="Accept",
            command=lambda: (accepted.__setitem__(0, True), dialog.destroy()),
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            btn_frame, text="Decline",
            command=dialog.destroy,
        ).pack(side=tk.LEFT, padx=10)

        # Text fills remaining space above buttons
        text = tk.Text(
            dialog, wrap=tk.WORD, font=("TkDefaultFont", 9),
            padx=15, pady=15, relief=tk.FLAT, bg=dialog.cget("bg"),
        )
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))
        text.insert("1.0", disclaimer)
        text.config(state=tk.DISABLED)

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.wait_window()
        return accepted[0]

    # ------------------------------------------------------------------ #
    #  UI Construction                                                    #
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        """Construct the Toplevel window and all child widgets."""
        self.window = tk.Toplevel(self.parent.root)
        self.window.title("AI Rule Assistant")
        self.window.geometry("700x650")
        self.window.minsize(600, 500)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        # --- Top config bar: Region + Model ---
        config_frame = ttk.Frame(self.window)
        config_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(config_frame, text="Region:").pack(side=tk.LEFT, padx=(0, 4))

        # Determine default region
        default_region = self.parent.aws_session.get_default_region()
        if default_region not in BEDROCK_REGIONS:
            default_region = "us-east-1"

        self.region_var = tk.StringVar(value=default_region)
        region_combo = ttk.Combobox(
            config_frame,
            textvariable=self.region_var,
            values=BEDROCK_REGIONS,
            state="readonly",
            width=16,
        )
        region_combo.pack(side=tk.LEFT, padx=(0, 12))
        region_combo.bind("<<ComboboxSelected>>", self._on_region_change)

        ttk.Label(config_frame, text="Model:").pack(side=tk.LEFT, padx=(0, 4))

        self.model_var = tk.StringVar(value="Loading models…")
        self.model_combo = ttk.Combobox(
            config_frame,
            textvariable=self.model_var,
            state="readonly",
            width=40,
        )
        self.model_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # --- Chat history area ---
        chat_frame = ttk.Frame(self.window)
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        scrollbar = ttk.Scrollbar(chat_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.message_area = tk.Text(
            chat_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            yscrollcommand=scrollbar.set,
            font=("TkDefaultFont", 10),
            padx=8,
            pady=8,
        )
        self.message_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.message_area.yview)

        # Allow text selection and copy even though widget is DISABLED
        self.message_area.bind("<Control-c>", self._copy_selection)
        self.message_area.bind("<Command-c>", self._copy_selection)

        # Configure text tags for styled output
        # Detect dark mode for appropriate colors
        import platform as _plat
        import subprocess as _sp
        _is_dark = False
        if _plat.system() == 'Darwin':
            try:
                _r = _sp.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                             capture_output=True, text=True)
                _is_dark = 'Dark' in _r.stdout
            except Exception:
                pass

        if _is_dark:
            _user_color = "#64B5F6"      # light blue
            _asst_color = "#81C784"      # light green
            _code_bg = "#1a1a2e"         # dark blue-gray
            _code_fg = "#e0e0e0"         # white
            _explain_color = "#b0b0b0"   # light gray
            _error_color = "#EF5350"     # bright red
            _status_color = "#9e9e9e"    # medium gray
        else:
            _user_color = "#1565C0"      # dark blue
            _asst_color = "#2E7D32"      # dark green
            _code_bg = "#F5F5F5"         # light gray
            _code_fg = "#000000"         # black
            _explain_color = "#424242"   # dark gray
            _error_color = "#D32F2F"     # dark red
            _status_color = "#757575"    # medium gray

        self.message_area.tag_configure(
            "user_msg",
            foreground=_user_color,
            font=("TkDefaultFont", 10, "bold"),
            spacing3=2,
        )
        self.message_area.tag_configure(
            "assistant_label",
            foreground=_asst_color,
            font=("TkDefaultFont", 10, "bold"),
            spacing3=2,
        )
        self.message_area.tag_configure(
            "code_block",
            background=_code_bg,
            foreground=_code_fg,
            font=("Consolas", 10),
            lmargin1=20,
            lmargin2=20,
            rmargin=20,
            spacing1=4,
            spacing3=4,
        )
        self.message_area.tag_configure(
            "explanation",
            foreground=_explain_color,
            font=("TkDefaultFont", 9),
            lmargin1=10,
            spacing1=2,
        )
        self.message_area.tag_configure(
            "error_msg",
            foreground=_error_color,
            font=("TkDefaultFont", 10),
            spacing3=2,
        )
        self.message_area.tag_configure(
            "status_msg",
            foreground=_status_color,
            font=("TkDefaultFont", 9, "italic"),
            spacing3=4,
        )

        # --- Input area ---
        input_frame = ttk.Frame(self.window)
        input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.input_field = tk.Text(
            input_frame,
            height=3,
            wrap=tk.WORD,
            font=("TkDefaultFont", 10),
        )
        self.input_field.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.input_field.bind("<Return>", self._on_enter_key)
        self.input_field.bind("<Shift-Return>", self._on_shift_enter)

        self.submit_btn = ttk.Button(
            input_frame,
            text="Generate",
            command=self._on_submit,
        )
        self.submit_btn.pack(side=tk.RIGHT)

        # Close button
        close_btn = ttk.Button(
            self.window,
            text="Close",
            command=self._on_close,
        )
        close_btn.pack(pady=(0, 10))

        # Give focus to the input field
        self.input_field.focus_set()


    # ------------------------------------------------------------------ #
    #  Region / Model Configuration (Task 3.2)                            #
    # ------------------------------------------------------------------ #

    def _on_region_change(self, *args) -> None:
        """Handle region dropdown change — refresh the model list."""
        self._refresh_models()

    def _refresh_models(self) -> None:
        """Query Bedrock for available models in the selected region (background thread)."""
        region = self.region_var.get()
        if self.model_combo is not None:
            self.model_var.set("Loading models…")
            self.model_combo.config(state="disabled")

        def _query():
            models = AgentFactory.list_models(self.parent.aws_session, region)
            # Marshal back to the main thread
            try:
                self.parent.root.after(0, lambda: self._populate_models(models))
            except tk.TclError:
                pass  # Root window destroyed

        thread = threading.Thread(target=_query, daemon=True)
        thread.start()

    def _populate_models(self, models: list[dict]) -> None:
        """Populate the model dropdown with query results (main thread)."""
        if self.window is None:
            return
        try:
            if not self.window.winfo_exists():
                return
        except tk.TclError:
            return

        self._model_list = models

        if models:
            display_names = [m.get("modelName", m.get("modelId", "unknown")) for m in models]
            self.model_combo["values"] = display_names
            self.model_combo.config(state="readonly")

            # Try to select the best Claude model by default.
            # Preference order (highest first):
            #   1. Claude Opus 4  (claude-opus-4, not opus-4-1)
            #   2. Claude Sonnet 4
            #   3. Any other Claude model
            selected_idx = 0
            best_priority = -1  # -1 = no Claude found yet
            for i, m in enumerate(models):
                mid = m.get("modelId", "").lower()
                mname = m.get("modelName", "").lower()
                combined = mid + " " + mname

                if "claude" not in combined:
                    continue

                # Determine priority for this model
                if "opus-4" in combined and "opus-4-1" not in combined:
                    priority = 3  # Claude Opus 4 (latest flagship)
                elif "sonnet-4" in combined and "sonnet-4-1" not in combined:
                    priority = 2  # Claude Sonnet 4
                else:
                    priority = 1  # Any other Claude model

                if priority > best_priority:
                    best_priority = priority
                    selected_idx = i
            self.model_var.set(display_names[selected_idx])
        else:
            self.model_combo["values"] = ["(no models found)"]
            self.model_combo.config(state="readonly")
            self.model_var.set("(no models found)")

    def _get_selected_model_id(self) -> str:
        """Return the Bedrock model ID for the currently selected model."""
        display_name = self.model_var.get()
        for m in self._model_list:
            if m.get("modelName", m.get("modelId")) == display_name:
                return m["modelId"]
        # Fallback: return the display name itself (may be a raw model ID)
        return display_name

    # ------------------------------------------------------------------ #
    #  Chat Submission & Threading (Task 3.3)                             #
    # ------------------------------------------------------------------ #

    def _on_enter_key(self, event) -> str:
        """Handle Enter key — submit unless Shift is held."""
        # Shift+Enter inserts a newline (handled by _on_shift_enter)
        self._on_submit()
        return "break"  # Prevent default newline insertion

    @staticmethod
    def _on_shift_enter(event) -> None:
        """Allow Shift+Enter to insert a newline (default Text behaviour)."""
        # Returning None lets the default handler insert the newline
        return None

    def _on_submit(self) -> None:
        """Handle user submit: validate, display, and start background generation."""
        if self._generating:
            return  # Guard against duplicate submissions

        # Get and validate input
        user_input = self.input_field.get("1.0", tk.END).strip()
        if not user_input:
            return

        # Clear input field
        self.input_field.delete("1.0", tk.END)

        # Append user message to chat history
        self.chat_history.append({"role": "user", "content": user_input})

        # Display user message in chat area
        self._append_to_chat(f"You: {user_input}\n", "user_msg")

        # Show generating indicator
        self._append_to_chat("Generating…\n", "status_msg")

        # Disable submit and set generating flag
        self._generating = True
        self.submit_btn.config(state=tk.DISABLED)

        # Start background thread
        thread = threading.Thread(
            target=self._generate_in_background,
            args=(user_input,),
            daemon=True,
        )
        thread.start()

    def _generate_in_background(self, user_input: str) -> None:
        """Run the agent pipeline on a daemon thread."""
        result: GenerationResult | None = None
        error_msg: str | None = None

        try:
            region = self.region_var.get()
            model_id = self._get_selected_model_id()

            # Collect existing SIDs from the parent's rule list
            existing_sids: set[int] = set()
            for rule in self.parent.rules:
                if hasattr(rule, "sid") and not getattr(rule, "is_comment", False) and not getattr(rule, "is_blank", False):
                    existing_sids.add(rule.sid)

            agent = self.agent_factory.get_or_create_agent(
                region=region,
                model_id=model_id,
                existing_sids=existing_sids,
            )
            result = agent.generate(user_input, self.chat_history)

        except NoCredentialsError:
            error_msg = (
                "AWS credentials not configured.\n"
                "Run `aws configure` or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY "
                "environment variables."
            )
        except Exception as exc:
            error_msg = self._classify_error(exc)

        # Marshal result back to the main thread
        try:
            self.parent.root.after(
                0, lambda: self._on_generation_complete(result, error_msg)
            )
        except tk.TclError:
            pass  # Root window destroyed

    def _classify_error(self, exc: Exception) -> str:
        """Return a user-friendly error message for common Bedrock failures."""
        msg = str(exc)

        if HAS_BOTO3 and isinstance(exc, ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ThrottlingException":
                return "Request throttled by Bedrock. Please wait a moment and try again."
            if code == "AccessDeniedException":
                return (
                    "Model access not enabled. Enable this model in the "
                    "AWS Bedrock console for your region."
                )
            return f"AWS error ({code}): {msg}"

        if HAS_BOTO3 and isinstance(exc, EndpointConnectionError):
            region = self.region_var.get() if self.region_var else "unknown"
            return (
                f"Bedrock service unavailable in {region}. "
                "Check your network connection and region selection."
            )

        if HAS_BOTO3 and isinstance(exc, NoCredentialsError):
            return (
                "AWS credentials not configured.\n"
                "Run `aws configure` or set environment variables."
            )

        return f"Generation failed: {msg}"

    def _on_generation_complete(
        self, result: GenerationResult | None, error_msg: str | None
    ) -> None:
        """Handle generation result on the main thread."""
        # Safety: check window still exists
        if self.window is None:
            self._generating = False
            return
        try:
            if not self.window.winfo_exists():
                self._generating = False
                return
        except tk.TclError:
            self._generating = False
            return

        # Remove the "Generating…" status line
        self._remove_last_status_line()

        if error_msg:
            self._append_to_chat(f"Error: {error_msg}\n\n", "error_msg")
            self.chat_history.append({"role": "assistant", "content": f"[Error] {error_msg}"})
        elif result is not None:
            self._display_result(result)
        else:
            self._append_to_chat("No response received.\n\n", "error_msg")
            self.chat_history.append({"role": "assistant", "content": "[Error] No response received."})

        # Re-enable submit
        self._generating = False
        if self.submit_btn and self.window.winfo_exists():
            self.submit_btn.config(state=tk.NORMAL)


    # ------------------------------------------------------------------ #
    #  Result Display (Task 3.4)                                          #
    # ------------------------------------------------------------------ #

    def _display_result(self, result: GenerationResult) -> None:
        """Render a GenerationResult in the chat area."""
        self._append_to_chat("Assistant:\n", "assistant_label")

        # Display errors (if any)
        if result.errors:
            for err in result.errors:
                self._append_to_chat(f"  ⚠ {err}\n", "error_msg")

        # Display generated rules
        if result.rules:
            for rule_str in result.rules:
                self._append_to_chat(f"{rule_str}\n", "code_block")
                summary = self._summarize_rule(rule_str)
                if summary:
                    self._append_to_chat(f"  ↳ {summary}\n", "explanation")

            # Add action buttons for the rule set
            self._insert_action_buttons(list(result.rules))

        # Display explanation / suggestions
        if result.explanation:
            self._append_to_chat(f"\n{result.explanation}\n", "explanation")

        self._append_to_chat("\n", None)

        # Build assistant content for chat history
        content_parts: list[str] = []
        if result.rules:
            content_parts.append("Rules:\n" + "\n".join(result.rules))
        if result.explanation:
            content_parts.append(result.explanation)
        if result.errors:
            content_parts.append("Errors:\n" + "\n".join(result.errors))

        self.chat_history.append({
            "role": "assistant",
            "content": "\n\n".join(content_parts) if content_parts else "(empty response)",
        })

    def _insert_action_buttons(self, rules: list[str]) -> None:
        """Insert 'Insert Rules' button into the chat area."""
        self.message_area.config(state=tk.NORMAL)

        btn_frame = ttk.Frame(self.message_area)

        insert_btn = ttk.Button(
            btn_frame,
            text="Insert Rules",
            command=lambda r=rules: self._insert_rules(r),
        )
        insert_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.message_area.window_create(tk.END, window=btn_frame)
        self.message_area.insert(tk.END, "\n")
        self.message_area.config(state=tk.DISABLED)

    # ------------------------------------------------------------------ #
    #  Chat Area Helpers                                                  #
    # ------------------------------------------------------------------ #

    def _show_example_prompts(self) -> None:
        """Display randomly selected example prompts as clickable buttons."""
        samples = random.sample(_EXAMPLE_PROMPTS, min(4, len(_EXAMPLE_PROMPTS)))

        self._append_to_chat(
            "Describe the traffic you want to detect or block using plain English.\n"
            "Try one of these examples to get started:\n\n",
            "explanation",
        )

        self.message_area.config(state=tk.NORMAL)
        for prompt_text in samples:
            btn = ttk.Button(
                self.message_area,
                text=f"  {prompt_text}  ",
                command=lambda t=prompt_text: self._use_example_prompt(t),
            )
            self.message_area.window_create(tk.END, window=btn)
            self.message_area.insert(tk.END, "\n")
        self.message_area.insert(tk.END, "\n")
        self.message_area.config(state=tk.DISABLED)

    def _use_example_prompt(self, text: str) -> None:
        """Fill the input field with an example prompt and clear the welcome text."""
        # Clear the welcome / example prompt area
        self.message_area.config(state=tk.NORMAL)
        self.message_area.delete("1.0", tk.END)
        self.message_area.config(state=tk.DISABLED)

        # Set the prompt text in the input field
        self.input_field.delete("1.0", tk.END)
        self.input_field.insert("1.0", text)
        self.input_field.focus_set()

    @staticmethod
    def _summarize_rule(rule_str: str) -> str:
        """Build a plain-English one-liner describing what a Suricata rule does."""
        parsed = SuricataRule.from_string(rule_str)
        if parsed is None:
            return ""

        # Action verb
        action_map = {
            "alert": "Alert on",
            "drop": "Silently drop",
            "reject": "Block (with reset)",
            "pass": "Allow",
        }
        action = action_map.get(parsed.action, parsed.action.capitalize())

        # Protocol
        proto = parsed.protocol.upper() if parsed.protocol else "IP"

        # Direction description
        src = parsed.src_net or "any"
        dst = parsed.dst_net or "any"
        dst_port = parsed.dst_port or "any"

        # Try to extract a meaningful target from the rule content
        target = ""
        content_lower = (parsed.content or "").lower()

        # Domain / SNI matching
        for buf in ("tls.sni;", "http.host;", "dns.query;"):
            if buf in content_lower:
                # Extract the content value after this buffer
                idx = content_lower.index(buf) + len(buf)
                rest = parsed.content[idx:]
                m = re.search(r'content:"([^"]+)"', rest)
                if m:
                    target = m.group(1)
                    break

        # Category matching
        for kw in ("aws_url_category:", "aws_domain_category:"):
            if kw in content_lower:
                idx = content_lower.index(kw) + len(kw)
                rest = (parsed.content or "")[idx:]
                cat = rest.split(";")[0].strip()
                target = f"category: {cat}"
                break

        # GeoIP
        if "geoip:" in content_lower:
            m = re.search(r'geoip:\w+,([A-Z,]+)', parsed.content or "")
            if m:
                target = f"countries: {m.group(1)}"

        # Build the summary
        parts = [action, proto.lower(), "traffic"]

        if src not in ("any", "$HOME_NET") or dst not in ("any", "$EXTERNAL_NET"):
            parts.append(f"from {src} to {dst}")
        elif dst != "any":
            parts.append(f"to {dst}")

        if dst_port not in ("any",):
            parts.append(f"on port {dst_port}")

        if target:
            parts.append(f"matching {target}")
        elif parsed.message:
            # Fall back to the msg field as a description
            parts.append(f"— {parsed.message}")

        return " ".join(parts)

    def _replay_chat_history(self) -> None:
        """Re-render stored chat_history into a freshly created message_area.

        Called when the panel window is reopened after being closed.
        Action buttons are not re-created for previous messages since those
        rules may have already been inserted.
        """
        for entry in self.chat_history:
            role = entry.get("role", "")
            content = entry.get("content", "")

            if role == "user":
                self._append_to_chat(f"You: {content}\n", "user_msg")
            elif role == "assistant":
                self._append_to_chat("Assistant:\n", "assistant_label")
                # Render content with basic formatting
                for line in content.split("\n"):
                    stripped = line.strip()
                    if stripped.startswith("[Error]"):
                        self._append_to_chat(f"{stripped}\n", "error_msg")
                    elif stripped and (
                        stripped.startswith("alert ")
                        or stripped.startswith("drop ")
                        or stripped.startswith("pass ")
                        or stripped.startswith("reject ")
                    ):
                        # Looks like a Suricata rule — render as code
                        self._append_to_chat(f"{stripped}\n", "code_block")
                    elif stripped.startswith("Rules:"):
                        continue  # Skip the "Rules:" label
                    elif stripped.startswith("Errors:"):
                        continue  # Skip the "Errors:" label
                    elif stripped:
                        self._append_to_chat(f"{line}\n", "explanation")
                self._append_to_chat("\n", None)

    def _copy_selection(self, event=None) -> str:
        """Copy selected text from the DISABLED message area."""
        try:
            sel = self.message_area.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.parent.root.clipboard_clear()
            self.parent.root.clipboard_append(sel)
        except tk.TclError:
            pass  # No selection
        return "break"

    def _append_to_chat(self, text: str, tag: str | None = None) -> None:
        """Append text to the chat history area and scroll to the bottom."""
        self.message_area.config(state=tk.NORMAL)
        if tag:
            self.message_area.insert(tk.END, text, tag)
        else:
            self.message_area.insert(tk.END, text)
        self.message_area.config(state=tk.DISABLED)
        self.message_area.see(tk.END)

    def _remove_last_status_line(self) -> None:
        """Remove the last 'Generating…' status line from the chat area."""
        self.message_area.config(state=tk.NORMAL)
        # Search backwards for the status tag
        try:
            idx = self.message_area.tag_prevrange("status_msg", tk.END)
            if idx:
                self.message_area.delete(idx[0], idx[1])
        except tk.TclError:
            pass
        self.message_area.config(state=tk.DISABLED)

    # ------------------------------------------------------------------ #
    #  Rule Insertion (Task 5.1)                                          #
    # ------------------------------------------------------------------ #

    def _insert_rules(self, rules: list[str]) -> None:
        """Parse rules, assign unique SIDs, and insert into the parent's rule list.

        Steps:
        1. Save undo state so the user can revert with Ctrl+Z.
        2. Collect existing SIDs to avoid collisions.
        3. Parse each rule string, assign a fresh SID, validate, and append.
        4. Refresh the UI (variables, table, status bar).
        """
        # 1. Save undo state BEFORE making any changes
        self.parent.save_undo_state()

        # 2. Collect current SIDs (skip comments and blanks)
        current_sids: set[int] = set()
        for rule in self.parent.rules:
            if hasattr(rule, "sid") and not getattr(rule, "is_comment", False) and not getattr(rule, "is_blank", False):
                current_sids.add(rule.sid)

        # 3. Determine next SID using the same logic as the main editor:
        #    blank file starts at 100, otherwise highest existing SID + 1
        next_sid = max(current_sids, default=99) + 1

        inserted_count = 0
        errors: list[str] = []

        for rule_str in rules:
            try:
                parsed = SuricataRule.from_string(rule_str)
                if parsed is None:
                    errors.append(f"Could not parse rule: {rule_str[:80]}…" if len(rule_str) > 80 else f"Could not parse rule: {rule_str}")
                    continue

                # Assign a non-conflicting SID (skip any already in use)
                while next_sid in current_sids:
                    next_sid += 1
                parsed.sid = next_sid
                current_sids.add(next_sid)
                next_sid += 1

                # Validate rule length (AWS Network Firewall limit: 8,192 chars)
                length_error = self._validate_rule_length(parsed)
                if length_error:
                    errors.append(length_error)
                    continue

                # Validate protocol/category compatibility
                category_error = self._validate_protocol_category(parsed)
                if category_error:
                    errors.append(category_error)
                    continue

                # Append to the parent's rule list
                self.parent.rules.append(parsed)

                # Change tracking: create baseline snapshot so this version is preserved
                if getattr(self.parent, 'tracking_enabled', False):
                    self._record_tracking_snapshot(parsed)

                inserted_count += 1

            except Exception as exc:
                errors.append(f"Error inserting rule: {exc}")

        # 4. Post-insertion UI updates
        if inserted_count > 0:
            self.parent.modified = True
            self.parent.auto_detect_variables()
            self.parent.refresh_table()

            # Update status bar
            status_msg = f"Inserted {inserted_count} AI-generated rule{'s' if inserted_count != 1 else ''}"
            if hasattr(self.parent, "update_status_bar"):
                self.parent.update_status_bar(status_msg)

        # 5. Display feedback in the chat area
        if inserted_count > 0:
            self._append_to_chat(
                f"✓ Inserted {inserted_count} rule{'s' if inserted_count != 1 else ''} into the rule list.\n",
                "status_msg",
            )

        for err in errors:
            self._append_to_chat(f"⚠ {err}\n", "error_msg")


    # ------------------------------------------------------------------ #
    #  Rule Validation Helpers                                            #
    # ------------------------------------------------------------------ #

    def _validate_rule_length(self, rule: SuricataRule) -> str | None:
        """Check rule length against AWS Network Firewall 8,192 char limit.

        Expands variables using the parent's variable definitions, matching
        the same logic as the main editor's validate_total_rule_length.

        Returns an error string if invalid, None if OK.
        """
        rule_string = rule.to_string()

        # Expand variables to their actual values
        for var_name, var_data in self.parent.variables.items():
            definition = var_data.get("definition", "") if isinstance(var_data, dict) else var_data
            if definition:
                rule_string = rule_string.replace(var_name, definition)

        total_length = len(rule_string)
        if total_length > 8192:
            return (
                f"SID {rule.sid}: Rule length {total_length} chars exceeds "
                f"AWS Network Firewall limit of 8,192 chars (with variables expanded)"
            )
        return None

    def _validate_protocol_category(self, rule: SuricataRule) -> str | None:
        """Check that aws_url_category/aws_domain_category match the rule protocol.

        Returns an error string if invalid, None if OK.
        """
        content_lower = (rule.content or "").lower()
        protocol_lower = (rule.protocol or "").lower()

        if "aws_url_category:" in content_lower and protocol_lower != "http":
            return (
                f"SID {rule.sid}: aws_url_category requires HTTP protocol "
                f"(rule uses {rule.protocol.upper()})"
            )

        if "aws_domain_category:" in content_lower and protocol_lower not in ("tls", "http"):
            return (
                f"SID {rule.sid}: aws_domain_category requires TLS or HTTP protocol "
                f"(rule uses {rule.protocol.upper()})"
            )

        return None

    def _record_tracking_snapshot(self, rule: SuricataRule) -> None:
        """Create a baseline change-tracking snapshot for a newly inserted rule.

        Mirrors the same logic used by insert_new_rule_from_editor and the
        other 5 insertion methods fixed in Bug #21 / Bug #22. Handles the
        case where tracking is enabled on a new unsaved file (snapshots live
        in pending_history, not on disk yet).
        """
        import os
        from src.managers.revision_manager import RevisionManager

        # Determine history filename
        if self.parent.current_file:
            history_filename = self.parent.current_file.replace('.suricata', '.history')
        else:
            temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'user_files')
            history_filename = os.path.join(temp_dir, '_unsaved_.history')

        history_file_exists = os.path.exists(history_filename)

        # CRITICAL: Check if baseline snapshots exist in pending_history
        # (handles tracking enabled on new file before first save)
        has_pending_snapshots = any(
            entry.get('action') == 'baseline_snapshot' and 'rule_snapshot' in entry.get('details', {})
            for entry in self.parent.pending_history
        )

        if not history_file_exists:
            should_create_snapshot = True
            revision_manager = RevisionManager(history_filename)
        elif has_pending_snapshots:
            should_create_snapshot = True
            revision_manager = RevisionManager(history_filename)
        else:
            revision_manager = RevisionManager(history_filename)
            needs_upgrade, version = revision_manager.detect_format_and_upgrade_needed()
            should_create_snapshot = not needs_upgrade

        if should_create_snapshot:
            rule_guid = revision_manager.generate_rule_guid()
            self.parent.rule_guids[rule.sid] = rule_guid

            history_details = {
                'line': len(self.parent.rules),
                'sid': rule.sid,
                'action': rule.action,
                'message': rule.message,
            }

            snapshot_entry = revision_manager.save_change_with_snapshot(
                rule,
                'rule_added',
                history_details,
                self.parent.get_version_number(),
                rule_guid=rule_guid,
            )

            self.parent.pending_history.append(snapshot_entry)
        else:
            rule_details = {
                'line': len(self.parent.rules),
                'rule_text': rule.to_string(),
            }
            self.parent.add_history_entry('rule_added', rule_details)

    # ------------------------------------------------------------------ #
    #  Window Lifecycle                                                   #
    # ------------------------------------------------------------------ #

    def _on_close(self) -> None:
        """Handle window close — clean up references gracefully."""
        if self.window is not None:
            try:
                if self.window.winfo_exists():
                    self.window.destroy()
            except tk.TclError:
                pass
        self.window = None
