"""
Container Association Manager — Tools-menu feature for managing AWS Network
Firewall container associations (list, view, create, edit, delete) and
cross-account sharing via AWS RAM.

This module owns the multi-screen tkinter UI and orchestrates AWS calls
through the UI-free API layer in `container_association_api`. It follows the
application's established patterns:
- AWS access via `parent_app.aws_session.get_client(service, region_name=...)`.
- The rule-group browser's Region selector + on-demand load + Treeview.
- The deploy path's indeterminate progress dialog and error taxonomy.
- The HAS_BOTO3 graceful-degradation pattern.

UI conventions (workspace rules) applied to every Toplevel:
- No transient() calls (global macOS monkey-patch).
- resizable(True, True) + minsize(); action buttons packed side=BOTTOM first.
- Dark-mode aware colors; dual Ctrl/Cmd copy bindings; scroll-wheel bindings.
"""

import platform as _plat
import subprocess as _sp
import tkinter as tk
from tkinter import ttk, messagebox

from src.core.aws_regions import AWS_COMMERCIAL_REGIONS
from src.core.constants import arn_account
from src.aws import container_association_api as api

# Optional boto3 import with graceful degradation (mirrors other AWS modules)
HAS_BOTO3 = False
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    boto3 = None


def _detect_dark_mode() -> bool:
    """Return True when macOS is in Dark mode (best-effort; False elsewhere)."""
    if _plat.system() == 'Darwin':
        try:
            r = _sp.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                        capture_output=True, text=True)
            return 'Dark' in r.stdout
        except Exception:
            return False
    return False


class ContainerAssociationManager:
    """Coordinates the Container Association Manager screens and AWS calls."""

    def __init__(self, parent_app):
        self.parent = parent_app
        self.region = None                 # selected Region (set on landing open)
        self.state = {}                    # in-progress add/edit state
        self._clients = {}                 # (service, region) -> boto3 client cache
        self._busy = False                 # write-in-flight guard (R4.12)
        self._welcome_shown = False        # session-only; never persisted (R2)
        self._account_id = None            # cached caller account for ownership
        self._landing = None               # the Landing (Container Associations) window
        self._dark = _detect_dark_mode()

        # Color palette (dark/light) for status and greyed rows.
        if self._dark:
            self._c_grey = '#888888'
            # Secondary text: a legible blue for larger informational blocks
            # (e.g. the Welcome prerequisites section). Must differ per mode: a
            # dark blue is unreadable on the dark-mode background, so dark mode
            # uses a lighter sky blue (mirrors the _c_link approach for macOS).
            self._c_secondary = '#7FB0E8'
            self._c_warn = '#E0A030'
            self._c_link = '#5AA9FF'
        else:
            self._c_grey = '#999999'
            self._c_secondary = '#1A3E6E'
            self._c_warn = '#CC6600'
            self._c_link = 'blue'

    # ------------------------------------------------------------------
    # Client helpers
    # ------------------------------------------------------------------
    def _client(self, service):
        """Return a cached boto3 client for the given service in the current Region."""
        key = (service, self.region)
        if key not in self._clients:
            self._clients[key] = self.parent.aws_session.get_client(
                service, region_name=self.region)
        return self._clients[key]

    def _reset_clients(self):
        """Drop cached clients (e.g., after a Region change)."""
        self._clients.clear()

    def _account(self):
        """Return (and cache) the caller's AWS account id, or None on failure."""
        if self._account_id is None:
            try:
                sts = self.parent.aws_session.get_client('sts', region_name=self.region)
                acct = sts.get_caller_identity().get('Account')
                # Only cache a real value; leave as None so a later load retries
                # rather than sticking on a transient first-call failure.
                if acct:
                    self._account_id = acct
                    return acct
                return None
            except Exception:
                return None
        return self._account_id

    def _copy_arn(self, arn):
        """Copy an ARN to the system clipboard (cross-platform)."""
        try:
            self.parent.root.clipboard_clear()
            self.parent.root.clipboard_append(arn)
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Window focus helpers
    #
    # The feature's child dialogs (detail view, review, success, progress, the
    # add/edit form) are parented to the Landing window so they stack above it,
    # and when they close focus returns to the Landing window rather than falling
    # back to the main application window. (transient() is intentionally NOT used
    # — the codebase disables it on macOS; we lift()+focus_force() instead.)
    # ------------------------------------------------------------------
    def _dialog_parent(self):
        """Return the window child dialogs should be parented to.

        Prefers the Landing window (so children stay grouped above it); falls
        back to the main window if the Landing window isn't open yet.
        """
        landing = getattr(self, '_landing', None)
        try:
            if landing is not None and landing.winfo_exists():
                return landing
        except tk.TclError:
            pass
        return self.parent.root

    def _focus_landing(self):
        """Bring the Landing window back to the front with focus (if it's open)."""
        landing = getattr(self, '_landing', None)
        try:
            if landing is not None and landing.winfo_exists():
                landing.lift()
                landing.focus_force()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Entry point + Welcome (R1, R2)
    # ------------------------------------------------------------------
    def start(self):
        """Open the feature: Welcome once per session, then the Landing screen."""
        if not HAS_BOTO3:
            messagebox.showinfo(
                "boto3 Required",
                "Managing container associations requires boto3.\n\n"
                "Install with: pip install boto3\n\n"
                "See Help > AWS Setup for details.")
            return
        if not self._welcome_shown:
            self._welcome_shown = True
            self._show_welcome()
        else:
            self._show_landing()

    def _show_welcome(self, standalone=False):
        """Show the Welcome screen.

        Args:
            standalone: When True (reopened via the "?" button), closing returns
                        to the Landing screen without advancing the flow.
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Manage Container Associations")
        dialog.geometry("640x640")
        dialog.grab_set()
        dialog.resizable(True, True)
        dialog.minsize(600, 560)
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 120,
            self.parent.root.winfo_rooty() + 80))

        # Buttons first (packed at bottom) so they are always visible.
        button_frame = ttk.Frame(dialog)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=(0, 15))

        def go_next():
            dialog.destroy()
            if not standalone:
                self._show_landing()

        def cancel():
            dialog.destroy()

        if standalone:
            ttk.Button(button_frame, text="Close", command=cancel).pack(side=tk.RIGHT)
        else:
            ttk.Button(button_frame, text="Next \u25b8", command=go_next).pack(side=tk.RIGHT)
            ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.RIGHT, padx=(0, 8))

        content = ttk.Frame(dialog)
        content.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(content, text="Manage Container Associations",
                  font=("TkDefaultFont", 13, "bold")).pack(anchor=tk.W, pady=(0, 10))

        intro = (
            "Container associations let AWS Network Firewall track the live IP "
            "addresses of your ECS/EKS containers and expose them as a dynamic "
            "IP set you can reference in rules.\n\n"
            "With this tool you can:\n"
            "   \u2022 List associations in an account/Region\n"
            "   \u2022 Create, edit, and delete associations (ECS or EKS)\n"
            "   \u2022 Share an association with a firewall account (via AWS RAM)\n\n"
            "These actions operate on live AWS resources. Some require specific "
            "IAM permissions and cluster prerequisites (shown where relevant, and "
            "in Help > AWS Setup)."
        )
        ttk.Label(content, text=intro, wraplength=560, justify=tk.LEFT).pack(anchor=tk.W)

        # Prerequisites & permissions (informational, non-blocking) — R5.
        prereq = ttk.LabelFrame(content, text="Prerequisites & IAM permissions")
        prereq.pack(fill=tk.BOTH, expand=False, pady=(14, 0))
        prereq_text = (
            "Environmental prerequisites (configured outside this tool):\n"
            "   \u2022 EKS: disable source NAT (SNAT) on the VPC CNI so the firewall "
            "sees pod IPs.\n"
            "   \u2022 ECS: tasks must use awsvpc network mode. Attribute filters apply "
            "to EC2 launch-type container instances (not Fargate).\n\n"
            "IAM permissions this feature uses:\n"
            "   \u2022 network-firewall: List/Describe/Create/Update/Delete"
            "ContainerAssociation, tag actions\n"
            "   \u2022 ecs: ListClusters/DescribeClusters/ListContainerInstances/"
            "DescribeContainerInstances; eks: ListClusters/DescribeCluster\n"
            "   \u2022 iam:CreateServiceLinkedRole (first use, created automatically)\n"
            "   \u2022 ram: CreateResourceShare/AssociateResourceShare/"
            "DisassociateResourceShare/GetResourceShareAssociations (sharing)\n\n"
            "See Help > AWS Setup for the complete IAM policy and a connectivity test."
        )
        ttk.Label(prereq, text=prereq_text, wraplength=560, justify=tk.LEFT,
                  foreground=self._c_secondary).pack(anchor=tk.W, padx=8, pady=8)

    # ------------------------------------------------------------------
    # Landing screen (R3, R4, R12)
    # ------------------------------------------------------------------
    def _show_landing(self):
        """Show the Landing screen: Region selector, association table, actions."""
        if self.region is None:
            try:
                self.region = self.parent.aws_session.get_default_region()
            except Exception:
                self.region = 'us-east-1'

        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Container Associations")
        dialog.geometry("860x600")
        dialog.grab_set()
        dialog.resizable(True, True)
        dialog.minsize(720, 480)
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 90,
            self.parent.root.winfo_rooty() + 60))
        self._landing = dialog

        # --- Action buttons (packed at bottom first) ---
        button_frame = ttk.Frame(dialog)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=(0, 15))

        self._btn_add_ecs = ttk.Button(button_frame, text="Add ECS association",
                                       command=lambda: self._open_add('ECS'))
        self._btn_add_ecs.pack(side=tk.LEFT)
        self._btn_add_eks = ttk.Button(button_frame, text="Add EKS association",
                                       command=lambda: self._open_add('EKS'))
        self._btn_add_eks.pack(side=tk.LEFT, padx=(8, 0))

        self._btn_delete = ttk.Button(button_frame, text="Delete", state='disabled',
                                      command=self._on_delete)
        self._btn_delete.pack(side=tk.RIGHT)
        self._btn_edit = ttk.Button(button_frame, text="Edit", state='disabled',
                                    command=self._on_edit)
        self._btn_edit.pack(side=tk.RIGHT, padx=(0, 8))
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 8))

        # --- Top controls: Region, Refresh, "?" ---
        controls = ttk.Frame(dialog)
        controls.pack(side=tk.TOP, fill=tk.X, padx=15, pady=(15, 8))

        profile = self.parent.aws_session.display_name
        ttk.Label(controls, text=f"Profile: {profile}").pack(side=tk.LEFT)
        ttk.Label(controls, text="Region:").pack(side=tk.LEFT, padx=(15, 5))
        self._region_var = tk.StringVar(value=self.region)
        self._region_combo = ttk.Combobox(
            controls, textvariable=self._region_var, values=AWS_COMMERCIAL_REGIONS,
            state="readonly", width=18)
        self._region_combo.pack(side=tk.LEFT)
        self._region_combo.bind('<<ComboboxSelected>>', self._on_region_change)

        self._refresh_btn = ttk.Button(controls, text="\u21bb Refresh", command=self._load_associations)
        self._refresh_btn.pack(side=tk.LEFT, padx=(15, 0))
        ttk.Button(controls, text="?", width=3,
                   command=lambda: self._show_welcome(standalone=True)).pack(side=tk.LEFT, padx=(8, 0))

        # --- Table ---
        tree_container = ttk.Frame(dialog)
        tree_container.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=15, pady=(0, 8))

        columns = ("Type", "Name", "Status", "SharedWith")
        self._tree = ttk.Treeview(tree_container, columns=columns, show="headings", selectmode="browse")
        self._tree.heading("Type", text="Type")
        self._tree.heading("Name", text="Name")
        self._tree.heading("Status", text="Status")
        self._tree.heading("SharedWith", text="Shared with")
        self._tree.column("Type", width=70, stretch=False)
        self._tree.column("Name", width=280, stretch=True)
        self._tree.column("Status", width=100, stretch=False)
        self._tree.column("SharedWith", width=300, stretch=True)

        vsb = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        # Greyed styling for not-owned rows (dark-mode aware).
        self._tree.tag_configure("notowned", foreground=self._c_grey)

        # Scroll-wheel bindings (Windows/Linux + macOS).
        def _on_wheel(event):
            if getattr(event, 'num', None) == 4:
                self._tree.yview_scroll(-3, "units")
            elif getattr(event, 'num', None) == 5:
                self._tree.yview_scroll(3, "units")
            else:
                self._tree.yview_scroll(int(-1 * (event.delta / 120)), "units")
        self._tree.bind("<MouseWheel>", _on_wheel)
        self._tree.bind("<Button-4>", _on_wheel)
        self._tree.bind("<Button-5>", _on_wheel)

        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self._tree.bind("<Double-1>", self._on_tree_double_click)

        # --- Status footer ---
        self._status_label = ttk.Label(dialog, text="", font=("TkDefaultFont", 9))
        self._status_label.pack(side=tk.TOP, fill=tk.X, padx=15, pady=(0, 8))

        # rows keyed by tree item id -> association dict
        self._rows = {}

        # Load after the dialog is visible so the status text shows.
        dialog.after(150, self._load_associations)

    def _set_controls_enabled(self, enabled):
        """Enable/disable Region + Refresh (disabled while a write is in flight)."""
        state = 'readonly' if enabled else 'disabled'
        try:
            self._region_combo.configure(state=state)
            self._refresh_btn.configure(state=('normal' if enabled else 'disabled'))
        except tk.TclError:
            pass

    def _on_region_change(self, event=None):
        """Handle Region change: reset clients/account and reload."""
        if self._busy:
            return
        self.region = self._region_var.get()
        self._reset_clients()
        self._account_id = None
        self._load_associations()

    def _load_associations(self):
        """List associations for the current Region and populate the table (R4.1, R4.11)."""
        if self._busy:
            return
        # Rebuild clients and re-resolve the caller account from the CURRENT
        # aws_session on every load, so the feature always honors the AWS
        # profile selected in the main window (which can change between the
        # manager being constructed and this load) without needing a manual
        # region round-trip.
        self._reset_clients()
        self._account_id = None
        # Clear table and show progress in the status footer.
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._rows.clear()
        self._status_label.config(text=f"Loading associations in {self.region}\u2026")
        self._landing.update_idletasks()

        try:
            nfw = self._client('network-firewall')
        except Exception as e:
            self._status_label.config(text="Could not create an AWS client.")
            messagebox.showerror("Error", f"Could not create an AWS client:\n\n{str(e)}")
            return

        # An older-but-installed boto3 has the network-firewall client but not
        # the container-association operations (added in botocore 1.43.x).
        if not api.supports_container_associations(nfw):
            self._status_label.config(text="Your installed AWS SDK is too old for this feature.")
            messagebox.showerror(
                "Update boto3 Required",
                "Your installed AWS SDK (boto3/botocore) is too old to manage "
                "container associations.\n\n"
                f"Container associations require botocore {api.MIN_BOTOCORE_VERSION} "
                "or newer. Update with:\n\n"
                "    pip install --upgrade boto3 botocore\n\n"
                "Then reopen this feature.")
            return

        try:
            associations = api.list_container_associations(nfw)
        except NoCredentialsError:
            self._status_label.config(text="No AWS credentials found for this profile.")
            messagebox.showerror(
                "AWS Credentials Required",
                "No AWS credentials were found for the selected profile.\n\n"
                "Configure credentials (aws configure) or select a different "
                "profile from the status bar dropdown.\n\n"
                "See Help > AWS Setup for details.")
            return
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            msg = e.response.get('Error', {}).get('Message', str(e))
            self._status_label.config(text=f"Error listing associations: {code}")
            if code == 'AccessDeniedException':
                messagebox.showerror(
                    "Insufficient AWS Permissions",
                    "Your AWS credentials lack permission to list container "
                    "associations.\n\nRequired: network-firewall:ListContainerAssociations\n\n"
                    "See Help > AWS Setup for the complete IAM policy.")
            else:
                messagebox.showerror("AWS Error", f"Failed to list container associations.\n\n"
                                                   f"Error Code: {code}\nMessage: {msg}")
            return
        except Exception as e:
            self._status_label.config(text="Error listing associations.")
            messagebox.showerror("Error", f"An unexpected error occurred:\n\n{str(e)}")
            return

        # The list response only carries {arn, name}; Type and Status come from
        # DescribeContainerAssociation. Describe each association (best-effort:
        # a shared-in association we lack describe permission on still shows its
        # name/ARN row).
        for a in associations:
            arn = a.get('arn', '')
            try:
                detail = api.describe_container_association_normalized(nfw, arn)
                a['type'] = detail.get('type', '')
                a['status'] = detail.get('status', '')
            except Exception:
                a['type'] = ''
                a['status'] = ''

        # Enrich with shared-with (RAM) — all-or-nothing gating (R12).
        shared_map = {}
        self._ram_available = False
        try:
            ram = self._client('ram')
            if api.ram_read_available(ram):
                self._ram_available = True
                arns = [a.get('arn') for a in associations if a.get('arn')]
                shared_map = api.get_shared_with(ram, arns)
        except Exception:
            self._ram_available = False

        # Update the "Shared with" heading to signal gating state.
        self._tree.heading("SharedWith",
                           text="Shared with" if self._ram_available
                           else "Shared with (RAM perms required)")

        account = self._account()
        for a in associations:
            arn = a.get('arn', '')
            name = a.get('name') or (arn.split('/')[-1] if arn else '(unknown)')
            ctype = a.get('type', '')
            status = a.get('status', '')
            # Ownership: if we know our account, compare it to the ARN's account
            # segment. If our account is unknown (STS unavailable), assume owned
            # (fail-safe: AWS rejects owner-only ops anyway) rather than greying
            # a row the user actually owns.
            row_account = arn_account(arn)
            if account is None or row_account is None:
                owned = True
            else:
                owned = (row_account == account)

            # A not-owned row is shared INTO this account; RAM only reports
            # shares this account owns, so its principals are empty. The helper
            # renders "Shared from another account" instead of "Not shared".
            shared_text = api.shared_cell_text(
                owned, self._ram_available, shared_map.get(arn, []))

            tags = () if owned else ("notowned",)
            item = self._tree.insert("", tk.END,
                                     values=(ctype, name, status, shared_text), tags=tags)
            self._rows[item] = {
                'arn': arn, 'name': name, 'type': ctype, 'status': status,
                'owned': owned, 'shared_with': shared_map.get(arn, []) if self._ram_available else None,
            }

        # Remember existing names for the create-time collision warning (R7a.2).
        self._existing_names = [a.get('name') for a in associations if a.get('name')]

        count = len(associations)
        if count == 0:
            self._status_label.config(
                text=f"No container associations in {self.region}. "
                     f"Use \u201cAdd ECS/EKS association\u201d to create one.")
        else:
            self._status_label.config(text=f"{count} association(s) in {self.region}.")
        self._update_action_buttons()

    def _selected_row(self):
        """Return the association dict for the current selection, or None."""
        sel = self._tree.selection()
        if not sel:
            return None
        return self._rows.get(sel[0])

    def _on_tree_select(self, event=None):
        self._update_action_buttons()

    def _update_action_buttons(self):
        """Enable Edit/Delete only for a selected owned association (R4.7, R4.8)."""
        row = self._selected_row()
        can_manage = bool(row and row.get('owned'))
        state = 'normal' if can_manage else 'disabled'
        try:
            self._btn_edit.configure(state=state)
            self._btn_delete.configure(state=state)
        except tk.TclError:
            pass

    def _on_tree_double_click(self, event=None):
        """Double-click: owned -> Edit; not-owned -> read-only External detail (R4.8, R4.9)."""
        row = self._selected_row()
        if not row:
            return
        if row.get('owned'):
            self._open_edit(row)
        else:
            self._open_external_detail(row)

    def _on_edit(self):
        row = self._selected_row()
        if row and row.get('owned'):
            self._open_edit(row)

    def _on_delete(self):
        row = self._selected_row()
        if row and row.get('owned'):
            self._confirm_delete(row)

    # ------------------------------------------------------------------
    # Add / Edit form (R6-R9, R9a, R10a) — Task 7
    # ------------------------------------------------------------------
    def _open_add(self, container_type):
        """Open the Add form for a new association of the given type."""
        state = {
            'mode': 'create', 'type': container_type, 'region': self.region,
            'name': '', 'arn': None, 'update_token': None, 'description': '',
            'monitoring': [{'cluster_arn': '', 'cluster_name': '', 'filters': []}],
            'tags': {}, 'share': {'enabled': False, 'account_id': ''},
        }
        _AssociationForm(self, state).show()

    def _open_edit(self, row):
        """Open the Edit window for an owned association (loads current state)."""
        arn = row['arn']
        try:
            nfw = self._client('network-firewall')
            detail = api.describe_container_association_normalized(nfw, arn)
        except Exception as e:
            messagebox.showerror("Error",
                                 f"Could not load the association details:\n\n{str(e)}")
            return

        monitoring = []
        for cfg in detail.get('monitoring', []):
            cluster_arn = cfg.get('cluster_arn', '')
            filters = [{'key': f.get('key', ''), 'value': f.get('value', ''),
                        'source': 'existing'}
                       for f in cfg.get('filters', [])]
            monitoring.append({'cluster_arn': cluster_arn,
                               'cluster_name': cluster_arn.split('/')[-1] if cluster_arn else '',
                               'filters': filters})

        # Determine current sharing state from the row's shared_with principals.
        principals = row.get('shared_with') or []
        share = {'enabled': bool(principals),
                 'account_id': principals[0] if principals else ''}

        state = {
            'mode': 'edit', 'type': detail.get('type') or row['type'], 'region': self.region,
            'name': detail.get('name') or row['name'], 'arn': arn,
            'update_token': detail.get('update_token', ''),
            'status': detail.get('status') or row.get('status', ''),
            'description': detail.get('description', ''),
            'monitoring': monitoring or [{'cluster_arn': '', 'cluster_name': '', 'filters': []}],
            'tags': dict(detail.get('tags', {})),
            'share': share,
        }
        # Snapshot for the edit diff (deep-ish copy of mutable parts).
        import copy
        state['loaded'] = {
            'description': state['description'],
            'monitoring': copy.deepcopy(state['monitoring']),
            'tags': dict(state['tags']),
            'share': dict(share),
        }
        _AssociationForm(self, state).show()

    def _open_external_detail(self, row):
        """Read-only view for an association owned by another account (R4a)."""
        arn = row.get('arn', '')
        # Best-effort describe; a not-owned (shared-in) association may or may
        # not be describable depending on permissions — degrade gracefully.
        details = None
        try:
            nfw = self._client('network-firewall')
            details = api.describe_container_association_normalized(nfw, arn)
        except Exception:
            details = None

        d = tk.Toplevel(self._dialog_parent())
        d.title("Container Association (owned by another account)")
        d.geometry("620x460")
        d.grab_set()
        d.resizable(True, True)
        d.minsize(520, 340)
        d.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 130,
                               self.parent.root.winfo_rooty() + 80))

        def close():
            d.destroy()
            self._focus_landing()
        d.protocol("WM_DELETE_WINDOW", close)

        button_frame = ttk.Frame(d)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=(0, 15))
        ttk.Button(button_frame, text="Close", command=close).pack(side=tk.RIGHT)

        body = ttk.Frame(d)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(body,
                  text="This association is shared with your account. You can view and "
                       "copy its ARN here, but it must be managed in its owner account.",
                  wraplength=560, justify=tk.LEFT, foreground=self._c_grey).pack(
            anchor=tk.W, pady=(0, 12))

        disp_name = (details or {}).get('name') or row.get('name', '')
        disp_type = (details or {}).get('type') or row.get('type', '') or '(unavailable)'
        disp_status = (details or {}).get('status') or row.get('status', '') or '(unavailable)'
        ttk.Label(body, text=f"Name:   {disp_name}").pack(anchor=tk.W)
        ttk.Label(body, text=f"Type:   {disp_type}").pack(anchor=tk.W)
        ttk.Label(body, text=f"Status: {disp_status}").pack(anchor=tk.W, pady=(0, 8))

        arn_row = ttk.Frame(body)
        arn_row.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(arn_row, text="ARN:").pack(side=tk.LEFT)
        ttk.Label(arn_row, text=arn, foreground=self._c_grey, wraplength=430,
                  justify=tk.LEFT).pack(side=tk.LEFT, padx=(6, 6))
        ttk.Button(arn_row, text="Copy ARN", command=lambda: self._copy_arn(arn)).pack(side=tk.LEFT)

        # Show monitoring configs when describable (may be unavailable for a
        # cross-account shared-in association).
        if details and details.get('monitoring'):
            cfg_frame = ttk.LabelFrame(body, text="Monitoring configurations")
            cfg_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 8))
            txt = tk.Text(cfg_frame, wrap=tk.WORD, height=9, font=("Consolas", 9))
            txt.insert(tk.END, "\n".join(api.format_monitoring_lines(details['monitoring'])))
            txt.config(state=tk.DISABLED)
            txt.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
            txt.bind("<Control-c>", lambda e: self._copy_text_selection(txt))
            txt.bind("<Command-c>", lambda e: self._copy_text_selection(txt))
        elif details is None:
            ttk.Label(body,
                      text="(Details are not available cross-account; the association is "
                           "managed in its owner account.)",
                      wraplength=560, justify=tk.LEFT, foreground=self._c_grey).pack(
                anchor=tk.W, pady=(4, 8))

        ttk.Label(body,
                  text="\u24d8 To reference this association in a rule group, the association "
                       "must exist in \u2014 or be shared with \u2014 the AWS account where the "
                       "rule group is deployed.",
                  wraplength=560, justify=tk.LEFT, foreground=self._c_grey).pack(
            anchor=tk.W, pady=(8, 0))

    # ------------------------------------------------------------------
    # Review + Deploy (R10) — Task 9
    # ------------------------------------------------------------------
    def _show_review(self, state, form_dialog):
        """Show the read-only Review screen; Deploy is the only write trigger."""
        # Parent to the form dialog so Review stacks above it (Cancel returns to
        # the form); fall back to the Landing window if the form is gone.
        review_parent = form_dialog if (form_dialog is not None) else self._dialog_parent()
        d = tk.Toplevel(review_parent)
        mode = state['mode']
        d.title("Review \u2014 Create" if mode == 'create'
                else f"Review \u2014 Edit: {state['name']}")
        d.geometry("640x520")
        d.grab_set()
        d.resizable(True, True)
        d.minsize(520, 380)
        d.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 120,
                               self.parent.root.winfo_rooty() + 70))

        # Buttons first.
        button_frame = ttk.Frame(d)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=(0, 15))
        self._deploy_done = False

        def on_deploy():
            if self._deploy_done:
                return
            self._deploy(state, review_dialog=d, form_dialog=form_dialog)

        def on_cancel():
            d.destroy()  # returns to the form with entries intact

        deploy_btn = ttk.Button(button_frame, text="Deploy", command=on_deploy)
        deploy_btn.pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=(0, 8))
        self._review_deploy_btn = deploy_btn

        # Body: create summary or edit diff.
        body = ttk.Frame(d)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=15, pady=15)
        if mode == 'create':
            ttk.Label(body, text="This will create the following container association:",
                      font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))
            lines = api.format_create_summary_lines(state)
        else:
            ttk.Label(body, text="Changes to apply:",
                      font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 8))
            diff = api.diff_association(state.get('loaded', {}), self._edit_current_snapshot(state))
            lines = api.format_diff_lines(diff)
            self._pending_diff = diff

        text = tk.Text(body, wrap=tk.WORD, height=18, font=("Consolas", 9))
        text.insert("1.0", "\n".join(lines))
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)
        # Copy bindings (read-only text).
        text.bind("<Control-c>", lambda e: self._copy_text_selection(text))
        text.bind("<Command-c>", lambda e: self._copy_text_selection(text))

    def _edit_current_snapshot(self, state):
        """Return the edit state's current mutable parts for diffing."""
        return {
            'description': state.get('description', ''),
            'monitoring': state.get('monitoring', []),
            'tags': state.get('tags', {}),
            'share': state.get('share', {}),
        }

    def _copy_text_selection(self, text_widget):
        try:
            sel = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.parent.root.clipboard_clear()
            self.parent.root.clipboard_append(sel)
        except tk.TclError:
            pass
        return "break"

    def _deploy(self, state, review_dialog, form_dialog):
        """Execute create or edit (+ tags + sharing) with progress and error handling."""
        self._busy = True
        self._set_controls_enabled(False)
        progress = self._make_progress("Deploying to AWS\u2026")
        partial = []  # steps that succeeded, for partial-failure reporting
        try:
            nfw = self._client('network-firewall')
            if state['mode'] == 'create':
                params = api.build_create_request(state)
                response = api.create_container_association(nfw, params)
                arn = response.get('ContainerAssociationArn', '')
                status = response.get('Status', 'CREATING')
                partial.append("association created")
                # Sharing is a follow-on step; a failure here does NOT abort the
                # create — it's reported on the success screen instead.
                sharing_error = self._apply_sharing(state, arn, partial)
                self._deploy_done = True
                self._safe_destroy(progress)
                self._safe_destroy(review_dialog)
                self._safe_destroy(form_dialog)
                self._show_create_success(state, arn, status, sharing_error=sharing_error)
            else:
                params = api.build_update_request(state, state['update_token'])
                api.update_container_association(nfw, params)
                partial.append("association updated")
                self._apply_tag_changes(state, nfw, partial)
                sharing_error = self._apply_sharing(state, state['arn'], partial, is_edit=True)
                self._deploy_done = True
                self._safe_destroy(progress)
                self._safe_destroy(review_dialog)
                self._safe_destroy(form_dialog)
                if sharing_error:
                    messagebox.showwarning(
                        "Saved \u2014 but sharing failed",
                        "The container association was updated successfully.\n\n"
                        "However, the sharing change could not be applied:\n\n"
                        f"{sharing_error}\n\n"
                        "The association itself is fine. You can retry the sharing "
                        "change by editing the association again.")
                else:
                    messagebox.showinfo("Saved", "The container association was updated.")
                # Return focus to the Landing window (the edit form is gone).
                self._focus_landing()
        except NoCredentialsError:
            self._safe_destroy(progress)
            self._handle_aws_error(None, "deploy", no_creds=True, partial=partial)
        except ClientError as e:
            self._safe_destroy(progress)
            self._handle_aws_error(e, "deploy", partial=partial)
        except Exception as e:
            self._safe_destroy(progress)
            self._handle_aws_error(e, "deploy", generic=True, partial=partial)
        finally:
            self._busy = False
            self._set_controls_enabled(True)
            # Refresh the landing list so the result is visible (R4.10).
            if getattr(self, '_landing', None) is not None:
                try:
                    self._load_associations()
                except tk.TclError:
                    pass

    def _apply_tag_changes(self, state, nfw, partial):
        """Apply tag add/overwrite and removals for an edit, using the loaded snapshot."""
        loaded_tags = (state.get('loaded') or {}).get('tags', {})
        new_tags = state.get('tags', {})
        to_set = {k: v for k, v in new_tags.items()
                  if k not in loaded_tags or loaded_tags[k] != v}
        to_remove = [k for k in loaded_tags if k not in new_tags]
        if to_set:
            api.tag_resource(nfw, state['arn'], to_set)
            partial.append("tags updated")
        if to_remove:
            api.untag_resource(nfw, state['arn'], to_remove)
            partial.append("tags removed")

    def _apply_sharing(self, state, arn, partial, is_edit=False):
        """Create/associate or disassociate the RAM share to match the desired state.

        Sharing is a follow-on step to the primary create/update: a sharing
        failure must NOT abort or undo the association that was just created or
        updated. So this method catches its own errors and RETURNS them instead
        of raising:

        Returns:
            None  -> no sharing change was needed, or the change succeeded.
            str   -> a human-readable error message if the RAM operation failed.
        """
        share = state.get('share') or {}
        want_enabled = bool(share.get('enabled'))
        account = (share.get('account_id') or '').strip()

        if is_edit:
            loaded_share = (state.get('loaded') or {}).get('share', {})
            was_enabled = bool(loaded_share.get('enabled'))
            was_account = (loaded_share.get('account_id') or '').strip()
        else:
            was_enabled, was_account = False, ''

        if want_enabled == was_enabled and account == was_account:
            return None  # no sharing change

        try:
            ram = self._client('ram')
            if want_enabled and account:
                api.create_or_associate_share(ram, arn, account)
                partial.append(f"shared with {account}")
                # If the target account changed, remove the old association.
                if was_enabled and was_account and was_account != account:
                    api.disassociate_share(ram, arn, was_account)
            elif not want_enabled and was_enabled and was_account:
                api.disassociate_share(ram, arn, was_account)
                partial.append(f"unshared from {was_account}")
            return None
        except NoCredentialsError:
            return ("AWS credentials were not available for the sharing (RAM) "
                    "operation.")
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            msg = e.response.get('Error', {}).get('Message', str(e))
            if code == 'AccessDeniedException':
                return ("Your credentials lack permission to share via AWS RAM "
                        "(needs ram:CreateResourceShare / AssociateResourceShare / "
                        "DisassociateResourceShare). See Help > AWS Setup.")
            return f"AWS RAM error ({code}): {msg}"
        except Exception as e:
            return f"Unexpected error during sharing: {str(e)}"

    def _show_create_success(self, state, arn, status, sharing_error=None):
        """Success screen with ARN, status, Copy ARN, console link, cross-account note.

        The association create always succeeds to reach this screen. `sharing_error`
        (when set) reports that the follow-on RAM sharing step failed, shown as a
        prominent warning; the created association is still fully usable.
        """
        import webbrowser
        region = state.get('region') or 'us-east-1'
        console_url = (f"https://{region}.console.aws.amazon.com/vpcconsole/home"
                       f"?region={region}#NetworkFirewallContainerAssociations:")

        d = tk.Toplevel(self._dialog_parent())
        d.title("\u2713 Container Association Created")
        d.geometry("620x480" if sharing_error else "620x400")
        d.grab_set()
        d.resizable(True, True)
        d.minsize(520, 380 if sharing_error else 320)
        d.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 140,
                               self.parent.root.winfo_rooty() + 90))

        def done():
            d.destroy()
            self._focus_landing()
        d.protocol("WM_DELETE_WINDOW", done)

        button_frame = ttk.Frame(d)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=(0, 15))
        ttk.Button(button_frame, text="Done", command=done).pack(side=tk.RIGHT)

        body = ttk.Frame(d)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=20)
        ttk.Label(body, text="\u2713 Created successfully",
                  font=("TkDefaultFont", 12, "bold"),
                  foreground=("#4CAF50" if self._dark else "green")).pack(anchor=tk.W, pady=(0, 12))
        ttk.Label(body, text=f"Name:   {state['name']}").pack(anchor=tk.W)
        ttk.Label(body, text=f"Status: {status}  (usable as a reference now; may take a few "
                             f"minutes to become ACTIVE)",
                  wraplength=560, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 8))

        # If the follow-on RAM sharing step failed, make it prominent — but frame
        # it clearly as separate from the (successful) association creation.
        if sharing_error:
            share_frame = ttk.LabelFrame(body, text="\u26a0 Sharing failed")
            share_frame.pack(fill=tk.X, pady=(0, 10))
            ttk.Label(share_frame,
                      text=("The association was created successfully, but sharing it "
                            "with the firewall account did NOT succeed:"),
                      wraplength=540, justify=tk.LEFT).pack(anchor=tk.W, padx=8, pady=(8, 4))
            ttk.Label(share_frame, text=sharing_error, wraplength=540, justify=tk.LEFT,
                      foreground=self._c_warn).pack(anchor=tk.W, padx=8, pady=(0, 4))
            ttk.Label(share_frame,
                      text=("You can retry sharing by editing this association. Until it is "
                            "shared, a rule group in the firewall account won't be able to "
                            "reference it."),
                      wraplength=540, justify=tk.LEFT, foreground=self.m_grey()).pack(
                anchor=tk.W, padx=8, pady=(0, 8))

        arn_row = ttk.Frame(body)
        arn_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(arn_row, text="ARN:").pack(side=tk.LEFT)
        ttk.Label(arn_row, text=arn, foreground=self.m_grey(), wraplength=440,
                  justify=tk.LEFT).pack(side=tk.LEFT, padx=(6, 6))
        ttk.Button(arn_row, text="Copy ARN", command=lambda: self._copy_arn(arn)).pack(side=tk.LEFT)

        link = tk.Button(body, text="View in AWS Console \u2192 Network Firewall \u2192 "
                                    "Container associations",
                         fg=self._c_link, cursor="hand2", relief=tk.FLAT,
                         font=("TkDefaultFont", 9, "underline"), borderwidth=0,
                         highlightthickness=0, command=lambda: webbrowser.open(console_url))
        link.pack(anchor=tk.W, pady=(0, 12))

        ttk.Label(body,
                  text="\u24d8 To use this association in a rule group, it must exist in \u2014 "
                       "or be shared with \u2014 the AWS account where the rule group is deployed.",
                  wraplength=560, justify=tk.LEFT, foreground=self.m_grey()).pack(anchor=tk.W)

    def m_grey(self):
        """Convenience accessor for the grey palette color."""
        return self._c_grey

    # ------------------------------------------------------------------
    # Delete (R10b) — Task 9
    # ------------------------------------------------------------------
    def _confirm_delete(self, row):
        """Confirm and delete an owned association."""
        name = row.get('name', '(unknown)')
        confirm = messagebox.askyesno(
            "Delete Container Association?",
            f"Delete \"{name}\" ({row.get('type', '')}) in {self.region}?\n\n"
            "This calls AWS to delete the association. If a rule group still "
            "references it, AWS will reject the deletion.")
        if not confirm:
            return
        self._busy = True
        self._set_controls_enabled(False)
        progress = self._make_progress("Deleting association\u2026")
        deleted = False
        share_cleanup_note = ""
        try:
            nfw = self._client('network-firewall')
            api.delete_container_association(nfw, row['arn'])
            deleted = True
            # If the association was shared, detach the resource from the
            # tool-managed RAM share so it doesn't leave an orphaned share
            # association behind. Best-effort: a cleanup failure must not make
            # the (successful) association delete look like it failed.
            if row.get('shared_with'):
                try:
                    ram = self._client('ram')
                    api.disassociate_resource_from_shares(ram, row['arn'])
                except Exception as e:
                    share_cleanup_note = (
                        "\n\nNote: the association was deleted, but its AWS RAM "
                        "share entry could not be removed automatically "
                        f"({str(e)[:120]}). You may want to remove it in the "
                        "RAM console.")
            self._safe_destroy(progress)
        except NoCredentialsError:
            self._safe_destroy(progress)
            self._handle_aws_error(None, "delete", no_creds=True)
        except ClientError as e:
            self._safe_destroy(progress)
            self._handle_aws_error(e, "delete")
        except Exception as e:
            self._safe_destroy(progress)
            self._handle_aws_error(e, "delete", generic=True)
        finally:
            self._busy = False
            self._set_controls_enabled(True)
            try:
                self._load_associations()
            except tk.TclError:
                pass
        # Confirm success to the user (delete is async; it may briefly show
        # DELETING then disappear from the list).
        if deleted:
            messagebox.showinfo(
                "Association Deleted",
                f"Deletion of \u201c{name}\u201d was initiated successfully.\n\n"
                "The association enters a DELETING state and is removed once AWS "
                "finishes cleanup, so it may briefly still appear in the list."
                + share_cleanup_note)
            # Return focus to the Landing window after the popup is dismissed.
            self._focus_landing()

    # ------------------------------------------------------------------
    # Progress + error taxonomy (R15) — Task 9
    # ------------------------------------------------------------------
    def _make_progress(self, message):
        """Create an indeterminate progress dialog (mirrors the deploy path)."""
        d = tk.Toplevel(self._dialog_parent())
        d.title("Working\u2026")
        d.geometry("400x120")
        d.grab_set()
        d.resizable(False, False)
        d.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 200,
                               self.parent.root.winfo_rooty() + 200))
        frame = ttk.Frame(d)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        ttk.Label(frame, text=message).pack(pady=12)
        bar = ttk.Progressbar(frame, mode='indeterminate')
        bar.pack(pady=8)
        bar.start(10)
        d.update()
        return d

    def _safe_destroy(self, dialog):
        """Destroy a dialog if it still exists (macOS-safe)."""
        try:
            if dialog is not None and dialog.winfo_exists():
                dialog.destroy()
        except tk.TclError:
            pass

    def _handle_aws_error(self, exc, op, no_creds=False, generic=False, partial=None):
        """Surface an AWS error using the deploy-path taxonomy (R15).

        partial: list of already-succeeded step descriptions, reported so a
        partial multi-step Deploy is not presented as full success (R10.7).

        Whatever branch fires, focus is returned to the Landing window after the
        error dialog is dismissed so the user isn't dropped to the main program
        window (e.g. a failed in-use delete).
        """
        try:
            self._render_aws_error(exc, op, no_creds=no_creds, generic=generic,
                                   partial=partial)
        finally:
            self._focus_landing()

    def _render_aws_error(self, exc, op, no_creds=False, generic=False, partial=None):
        """Show the appropriate error dialog for an AWS failure (see _handle_aws_error)."""
        partial_note = ""
        if partial:
            partial_note = ("\n\nNote: the following step(s) DID complete before the "
                            "error:\n" + "\n".join("\u2022 " + p for p in partial))

        if no_creds:
            messagebox.showerror(
                "AWS Credentials Required",
                "No AWS credentials were found for the selected profile.\n\n"
                "Configure credentials (aws configure) or select a different profile "
                "from the status bar dropdown.\n\nSee Help > AWS Setup for details."
                + partial_note)
            return

        if generic or exc is None:
            messagebox.showerror(
                "Error", f"An unexpected error occurred:\n\n{str(exc)}" + partial_note)
            return

        # ClientError branch.
        code = exc.response.get('Error', {}).get('Code', 'Unknown')
        message = exc.response.get('Error', {}).get('Message', str(exc))

        if code == 'AccessDeniedException':
            perms = {
                'deploy': "network-firewall:CreateContainerAssociation / "
                          "UpdateContainerAssociation (and ecs/eks describe, "
                          "iam:CreateServiceLinkedRole, ram:* for sharing)",
                'delete': "network-firewall:DeleteContainerAssociation",
            }.get(op, "the required network-firewall permission")
            messagebox.showerror(
                "Insufficient AWS Permissions",
                f"Your AWS credentials lack permission for this operation.\n\n"
                f"Likely required: {perms}\n\n"
                f"See Help > AWS Setup for the complete IAM policy." + partial_note)
        elif code in ('InvalidRequestException', 'ValidationException'):
            messagebox.showerror(
                "Invalid Request",
                f"AWS rejected the request.\n\nError: {message}\n\n"
                "You can go back and correct the input." + partial_note)
        elif code in ('InvalidOperationException', 'ResourceInUseException'):
            # In-use delete (R10b.3) — surface verbatim, no reference lookup.
            messagebox.showerror(
                "Cannot Complete Operation",
                f"AWS rejected the operation.\n\nError: {message}\n\n"
                "If deleting, a rule group may still reference this association; "
                "remove the reference first." + partial_note)
        elif code == 'InvalidTokenException':
            # Stale UpdateToken (R10a.8).
            messagebox.showwarning(
                "Association Changed",
                "This association was changed since you opened it, so your update "
                "could not be applied.\n\nThe list will refresh; please reopen and "
                "re-apply your changes." + partial_note)
        else:
            messagebox.showerror(
                "AWS Error",
                f"The operation failed.\n\nError Code: {code}\nMessage: {message}"
                + partial_note)


class _AssociationForm:
    """The shared Add/Edit form (single scrollable window).

    Add and Edit use the same form; Edit pre-populates from the loaded state
    and locks the immutable fields (Type always, Name on Edit). Fields map to
    the manager's `state` dict; on Review the state is validated (pre-flight)
    and handed to the manager's Review screen.
    """

    def __init__(self, manager, state):
        self.m = manager
        self.state = state
        self.parent = manager.parent
        self._config_widgets = []   # per-card widget bundles
        self._tag_rows = []         # [(key_var, value_var, frame)]
        self._cluster_cache = None  # list of {name, arn} (ECS) or names (EKS)

    # -- lifecycle -----------------------------------------------------
    def show(self):
        d = tk.Toplevel(self.m._dialog_parent())
        self.dialog = d
        mode = self.state['mode']
        ctype = self.state['type']
        if mode == 'create':
            d.title(f"Add {ctype} Association")
        else:
            d.title(f"Edit Association: {self.state['name']}")
        d.geometry("720x680")
        d.grab_set()
        d.resizable(True, True)
        d.minsize(640, 520)
        d.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 100,
                               self.parent.root.winfo_rooty() + 50))

        def cancel():
            d.destroy()
            self.m._focus_landing()
        d.protocol("WM_DELETE_WINDOW", cancel)

        # Buttons at the bottom first (always visible).
        button_frame = ttk.Frame(d)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=(0, 15))
        ttk.Button(button_frame, text="Review", command=self._on_review).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.RIGHT, padx=(0, 8))

        # Scrollable body (canvas + inner frame).
        outer = ttk.Frame(d)
        outer.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(outer, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        self._body = ttk.Frame(canvas)
        self._body.bind("<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self._body, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        def _on_wheel(event):
            if getattr(event, 'num', None) == 4:
                canvas.yview_scroll(-3, "units")
            elif getattr(event, 'num', None) == 5:
                canvas.yview_scroll(3, "units")
            else:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<Enter>", lambda e: (canvas.bind_all("<MouseWheel>", _on_wheel),
                                          canvas.bind_all("<Button-4>", _on_wheel),
                                          canvas.bind_all("<Button-5>", _on_wheel)))
        canvas.bind("<Leave>", lambda e: (canvas.unbind_all("<MouseWheel>"),
                                          canvas.unbind_all("<Button-4>"),
                                          canvas.unbind_all("<Button-5>")))

        self._build_body()

    # -- body ----------------------------------------------------------
    def _build_body(self):
        b = self._body
        pad = {'padx': 15, 'pady': (10, 0)}
        mode = self.state['mode']

        # Type badge + Name
        header = ttk.Frame(b)
        header.pack(fill=tk.X, **pad)
        ttk.Label(header, text="Type:").pack(side=tk.LEFT)
        ttk.Label(header, text=f" {self.state['type']} ",
                  relief=tk.SOLID, borderwidth=1).pack(side=tk.LEFT, padx=(4, 20))
        ttk.Label(header, text="  (type cannot be changed after creation)",
                  foreground=self.m._c_grey).pack(side=tk.LEFT)

        name_row = ttk.Frame(b)
        name_row.pack(fill=tk.X, **pad)
        ttk.Label(name_row, text="Name:").pack(side=tk.LEFT)
        self._name_var = tk.StringVar(value=self.state.get('name', ''))
        name_entry = ttk.Entry(name_row, textvariable=self._name_var, width=40)
        name_entry.pack(side=tk.LEFT, padx=(6, 0))
        if mode == 'edit':
            name_entry.configure(state='readonly')
        else:
            ttk.Label(name_row, text="  (a-z A-Z 0-9 - ; 1-128)",
                      foreground=self.m._c_grey).pack(side=tk.LEFT, padx=(6, 0))

        # Edit-only: ARN + Copy + Status
        if mode == 'edit':
            arn_row = ttk.Frame(b)
            arn_row.pack(fill=tk.X, **pad)
            ttk.Label(arn_row, text="ARN:").pack(side=tk.LEFT)
            ttk.Label(arn_row, text=self.state['arn'], foreground=self.m._c_grey,
                      wraplength=480, justify=tk.LEFT).pack(side=tk.LEFT, padx=(6, 6))
            ttk.Button(arn_row, text="Copy ARN",
                       command=lambda: self.m._copy_arn(self.state['arn'])).pack(side=tk.LEFT)
            if self.state.get('status'):
                ttk.Label(b, text=f"Status: {self.state['status']}",
                          foreground=self.m._c_grey).pack(anchor=tk.W, padx=15)

        # Description
        desc_frame = ttk.LabelFrame(b, text="Description (optional, max 512)")
        desc_frame.pack(fill=tk.X, **pad)
        self._desc_var = tk.StringVar(value=self.state.get('description', ''))
        ttk.Entry(desc_frame, textvariable=self._desc_var).pack(fill=tk.X, padx=8, pady=8)

        # Monitoring configurations
        self._mon_frame = ttk.LabelFrame(b, text="Monitoring configurations (1-5)")
        self._mon_frame.pack(fill=tk.X, **pad)
        self._cards_container = ttk.Frame(self._mon_frame)
        self._cards_container.pack(fill=tk.X, padx=4, pady=4)
        self._add_cfg_btn = ttk.Button(self._mon_frame, text="+ Add configuration",
                                       command=self._add_config)
        self._add_cfg_btn.pack(anchor=tk.W, padx=8, pady=(0, 4))
        ttk.Label(self._mon_frame,
                  text="Configurations are independent (OR across configurations).",
                  foreground=self.m._c_grey).pack(anchor=tk.W, padx=8, pady=(0, 8))

        for cfg in self.state['monitoring']:
            self._render_config_card(cfg)
        self._update_add_config_state()

        # Sharing
        share_frame = ttk.LabelFrame(b, text="Sharing")
        share_frame.pack(fill=tk.X, **pad)
        self._share_var = tk.BooleanVar(value=self.state['share'].get('enabled', False))
        share_cb = ttk.Checkbutton(
            share_frame, text="Share with the firewall account",
            variable=self._share_var, command=self._on_share_toggle)
        share_cb.pack(anchor=tk.W, padx=8, pady=(8, 0))
        _Tooltip(share_cb,
                 "Only share if the firewall is in a different AWS account.\n"
                 "If the firewall is in this same account, sharing is not needed\n"
                 "and this box should be left unchecked.")
        acct_row = ttk.Frame(share_frame)
        acct_row.pack(fill=tk.X, padx=8, pady=(4, 8))
        ttk.Label(acct_row, text="Account:").pack(side=tk.LEFT)
        self._acct_var = tk.StringVar(value=self.state['share'].get('account_id', ''))
        self._acct_entry = ttk.Entry(acct_row, textvariable=self._acct_var, width=16)
        self._acct_entry.pack(side=tk.LEFT, padx=(6, 0))

        # RAM gating: disable share controls when RAM sharing is unavailable.
        self._share_cb = share_cb
        if not self._ram_sharing_available():
            share_cb.configure(state='disabled')
            self._acct_entry.configure(state='disabled')
            ttk.Label(share_frame,
                      text="RAM permissions required to share (see Help > AWS Setup).",
                      foreground=self.m._c_grey).pack(anchor=tk.W, padx=8, pady=(0, 8))
        else:
            self._on_share_toggle()

        # Tags
        tags_frame = ttk.LabelFrame(b, text="Tags (optional)")
        tags_frame.pack(fill=tk.X, padx=15, pady=(10, 15))
        self._tags_container = ttk.Frame(tags_frame)
        self._tags_container.pack(fill=tk.X, padx=4, pady=4)
        ttk.Button(tags_frame, text="+ Add tag", command=lambda: self._add_tag_row()).pack(
            anchor=tk.W, padx=8, pady=(0, 8))
        for k, v in self.state.get('tags', {}).items():
            self._add_tag_row(k, v)

    # -- sharing helpers ----------------------------------------------
    def _ram_sharing_available(self):
        """Best-effort check that RAM sharing is usable (reuses the read probe)."""
        try:
            ram = self.m._client('ram')
            return api.ram_read_available(ram)
        except Exception:
            return False

    def _on_share_toggle(self):
        state = 'normal' if self._share_var.get() else 'disabled'
        try:
            self._acct_entry.configure(state=state)
        except tk.TclError:
            pass

    # -- monitoring config cards --------------------------------------
    def _add_config(self):
        cfg = {'cluster_arn': '', 'cluster_name': '', 'filters': []}
        self.state['monitoring'].append(cfg)
        self._render_config_card(cfg)
        self._update_add_config_state()

    def _update_add_config_state(self):
        try:
            self._add_cfg_btn.configure(
                state=('disabled' if len(self.state['monitoring']) >= api.MAX_MONITORING_CONFIGS
                       else 'normal'))
        except tk.TclError:
            pass

    def _render_config_card(self, cfg):
        idx = self.state['monitoring'].index(cfg) + 1
        card = ttk.LabelFrame(self._cards_container, text=f"Configuration {idx}")
        card.pack(fill=tk.X, padx=4, pady=6)

        # Collapse/expand header: toggle button + one-line summary shown when collapsed.
        header = ttk.Frame(card)
        header.pack(fill=tk.X, padx=8, pady=(6, 0))
        toggle_btn = ttk.Button(header, width=3)
        toggle_btn.pack(side=tk.LEFT)
        summary_label = ttk.Label(header, text="")  # normal (default) foreground
        summary_label.pack(side=tk.LEFT, padx=(6, 0))

        # Body holds everything below the header; collapsing hides it.
        body = ttk.Frame(card)
        body.pack(fill=tk.X)

        # Cluster row: dropdown + choose-from-list + remove config
        row = ttk.Frame(body)
        row.pack(fill=tk.X, padx=8, pady=(8, 2))
        ttk.Label(row, text="Cluster:").pack(side=tk.LEFT)
        cluster_var = tk.StringVar(value=cfg.get('cluster_name', ''))
        cluster_combo = ttk.Combobox(row, textvariable=cluster_var, width=40, state="readonly")
        cluster_combo.pack(side=tk.LEFT, padx=(6, 6))
        ttk.Button(row, text="Remove", command=lambda: self._remove_config(cfg)).pack(side=tk.RIGHT)

        arn_label = ttk.Label(body, text=cfg.get('cluster_arn', ''),
                              foreground=self.m._c_grey, wraplength=560, justify=tk.LEFT)
        arn_label.pack(anchor=tk.W, padx=8)

        # Populate the dropdown lazily on first drop-down open (clusters are
        # returned sorted by name).
        def load_dropdown(event=None):
            names, _ = self._load_clusters()
            cluster_combo.configure(values=names)
        cluster_combo.bind("<Button-1>", load_dropdown)

        def on_pick(event=None):
            name = cluster_var.get()
            self._set_cluster(cfg, name, arn_label)
        cluster_combo.bind("<<ComboboxSelected>>", on_pick)

        # Attribute filters area
        filt_frame = ttk.Frame(body)
        filt_frame.pack(fill=tk.X, padx=8, pady=(4, 8))
        bundle = {'cfg': cfg, 'card': card, 'body': body, 'combo': cluster_combo,
                  'cluster_var': cluster_var, 'arn_label': arn_label,
                  'filt_frame': filt_frame, 'filter_rows': [],
                  'discovered_tree': None, 'checked_items': set(),
                  'summary_label': summary_label, 'toggle_btn': toggle_btn,
                  'collapsed': False}
        self._config_widgets.append(bundle)

        # If this card already has a cluster (edit flow, or reselect), run ECS
        # discovery now so saved filters reconcile against discovered attributes
        # instead of all falling through to the warned "Custom" section.
        if self.state['type'] == 'ECS' and cfg.get('cluster_arn') and '_discovered' not in cfg:
            self._discover_ecs(cfg)

        self._render_filters(bundle)

        # Wire the collapse toggle; start collapsed on edit (existing config),
        # expanded on create (new config).
        toggle_btn.configure(command=lambda: self._toggle_collapse(bundle))
        start_collapsed = (self.state['mode'] == 'edit')
        self._set_collapsed(bundle, start_collapsed)

    def _set_collapsed(self, bundle, collapsed):
        """Show/hide a config card body and update its toggle + summary."""
        bundle['collapsed'] = collapsed
        try:
            if collapsed:
                bundle['body'].pack_forget()
                bundle['toggle_btn'].configure(text="\u25b8")   # ▸
                bundle['summary_label'].configure(text=self._config_summary(bundle))
            else:
                bundle['body'].pack(fill=tk.X)
                bundle['toggle_btn'].configure(text="\u25be")   # ▾
                bundle['summary_label'].configure(text="")
        except tk.TclError:
            pass

    def _toggle_collapse(self, bundle):
        self._set_collapsed(bundle, not bundle['collapsed'])

    def _config_summary(self, bundle):
        """One-line summary shown when a config is collapsed: cluster + selected filters."""
        cfg = bundle['cfg']
        cluster = cfg.get('cluster_name') or (cfg.get('cluster_arn', '').split('/')[-1]) or '(no cluster)'
        selected = self._selected_filters(bundle)
        if not selected:
            return f"{cluster} \u2014 no attribute filters"
        shown = ", ".join(f"{f['key']}={f['value']}" for f in selected[:2])
        extra = f" (+{len(selected) - 2})" if len(selected) > 2 else ""
        return f"{cluster} \u2014 {shown}{extra}"

    def _selected_filters(self, bundle):
        """Return the currently-selected filters for a config (discovered ticks + custom)."""
        selected = []
        # Discovered ticks are stored as (key, value) pairs (see _build_discovered_tree).
        for key, value in bundle.get('checked_items', set()):
            selected.append({'key': key, 'value': value, 'source': 'discovered'})
        # Custom rows: include a row if EITHER key or value is non-empty, so a
        # half-filled row (e.g. a value with a missing key) survives to pre-flight
        # validation and is flagged, rather than being silently dropped. A fully
        # blank row is ignored (harmless).
        for rec in bundle['filter_rows']:
            if rec.get('kind') == 'custom':
                key = rec['key_var'].get().strip()
                value = rec['value_var'].get().strip()
                if key or value:
                    selected.append({'key': key, 'value': value, 'source': 'custom'})
        return selected

    def _remove_config(self, cfg):
        if len(self.state['monitoring']) <= 1:
            messagebox.showinfo("At least one required",
                                "An association must have at least one monitoring configuration.")
            return
        self.state['monitoring'].remove(cfg)
        self._rebuild_cards()

    def _rebuild_cards(self):
        for child in self._cards_container.winfo_children():
            child.destroy()
        self._config_widgets = []
        for cfg in self.state['monitoring']:
            self._render_config_card(cfg)
        self._update_add_config_state()

    # -- cluster selection --------------------------------------------
    def _load_clusters(self, force=False):
        """Fetch cluster names for the current type/Region. Returns (names, error).

        Caches successful results (so the dropdown and the modal share one list),
        but does NOT cache failures — so a transient error can be retried rather
        than permanently showing an empty list. `error` is None on success or a
        message string on failure.
        """
        if self._cluster_cache is not None and not force:
            names = [c['name'] if isinstance(c, dict) else c for c in self._cluster_cache]
            return names, None
        try:
            if self.state['type'] == 'ECS':
                clusters = api.list_ecs_clusters(self.m._client('ecs'))
                self._cluster_cache = clusters
                return [c['name'] for c in clusters], None
            else:
                clusters = api.list_eks_clusters(self.m._client('eks'))
                self._cluster_cache = list(clusters)
                return list(clusters), None
        except Exception as e:
            # Do not cache the failure; allow a later retry.
            return [], str(e)

    def _cluster_names(self):
        """Return just the cluster-name list (compat helper)."""
        names, _ = self._load_clusters()
        return names

    def _resolve_cluster_arn(self, name):
        """Resolve a chosen cluster name to its ARN (ECS from cache; EKS via describe)."""
        if self.state['type'] == 'ECS':
            for c in (self._cluster_cache or []):
                if isinstance(c, dict) and c['name'] == name:
                    return c['arn']
            return ''
        else:
            try:
                return api.resolve_eks_cluster_arn(self.m._client('eks'), name)
            except Exception:
                return ''

    def _set_cluster(self, cfg, name, arn_label):
        """Set a config's cluster (overwrites previous), then refresh its filters."""
        arn = self._resolve_cluster_arn(name)
        cfg['cluster_name'] = name
        cfg['cluster_arn'] = arn
        try:
            arn_label.configure(text=arn)
        except tk.TclError:
            pass
        # ECS: auto-discover attributes for the newly selected cluster.
        bundle = next((b for b in self._config_widgets if b['cfg'] is cfg), None)
        if bundle is not None:
            if self.state['type'] == 'ECS' and arn:
                self._discover_ecs(cfg)
            self._render_filters(bundle)

    # -- attribute filters --------------------------------------------
    def _discover_ecs(self, cfg):
        """Auto-discover ECS attributes for a config's cluster; store on the cfg."""
        try:
            attrs = api.discover_ecs_attributes(self.m._client('ecs'), cfg['cluster_arn'])
            # Discovery genuinely succeeded (even if it found nothing). An empty
            # result here is a real signal: no registered EC2 container instances,
            # so attribute filters can't match (Fargate-only / no instances yet).
            cfg['_discovery_ok'] = True
        except Exception:
            # Could not determine attributes (permissions, throttle, etc.). This
            # is NOT evidence of a Fargate-only cluster, so don't let the empty
            # list drive the Fargate warning.
            attrs = []
            cfg['_discovery_ok'] = False
        cfg['_discovered'] = attrs

    def _render_filters(self, bundle):
        """(Re)render the attribute-filter area for one configuration card."""
        frame = bundle['filt_frame']
        for child in frame.winfo_children():
            child.destroy()
        bundle['filter_rows'] = []
        cfg = bundle['cfg']

        ttk.Label(frame, text="Attribute filters  (all must match \u2014 AND):",
                  font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)

        if self.state['type'] == 'ECS':
            discovered = cfg.get('_discovered', [])
            # Build a unique, ordered list of discovered (key, value) pairs.
            seen = set()
            discovered_pairs = []
            for attr in discovered:
                pair = (attr['key'], attr['value'])
                if pair not in seen:
                    seen.add(pair)
                    discovered_pairs.append(pair)

            # Saved filters, indexed by (key, value), so we can pre-tick the
            # discovered row that matches a saved filter and NOT also list it
            # as a custom row.
            saved_pairs = {(f.get('key', ''), f.get('value', '')) for f in cfg['filters']}
            discovered_pair_set = set(discovered_pairs)

            if discovered_pairs:
                ttk.Label(frame,
                          text="Discovered (tick to include; click the box column to toggle):",
                          foreground=self.m._c_grey).pack(anchor=tk.W)
                ttk.Label(frame,
                          text="Discovered from container instances currently registered in this "
                               "cluster. An instance that isn't running now (e.g. in another AZ or "
                               "of another instance type) won't appear until it registers \u2014 use "
                               "\u201c+ Add filter\u201d to specify one ahead of time.",
                          foreground=self.m._c_grey, wraplength=560, justify=tk.LEFT).pack(
                    anchor=tk.W, pady=(0, 2))
                self._build_discovered_tree(frame, bundle, discovered_pairs, saved_pairs)
            # Custom (free-form) rows: only saved filters NOT covered by a
            # discovered row (so a saved filter that matches a discovered
            # attribute appears once, ticked above — not duplicated here).
            ttk.Label(frame, text="Custom:", foreground=self.m._c_grey).pack(anchor=tk.W, pady=(4, 0))
            for f in cfg['filters']:
                if (f.get('key', ''), f.get('value', '')) not in discovered_pair_set:
                    self._add_filter_row(bundle, f.get('key', ''), f.get('value', ''))
        else:
            # EKS: free-form only, with the not-verified hint.
            for f in cfg['filters']:
                self._add_filter_row(bundle, f.get('key', ''), f.get('value', ''))
            ttk.Label(frame,
                      text="\u24d8 These keys/values are not verified against the cluster. "
                           "A key or value that doesn't exist matches no containers.",
                      foreground=self.m._c_warn, wraplength=560, justify=tk.LEFT).pack(
                anchor=tk.W, pady=(2, 0))

        ttk.Button(frame, text="+ Add filter",
                   command=lambda: self._add_filter_row(bundle)).pack(anchor=tk.W, pady=(4, 0))

    _CHECKED = "\u2611"    # ☑
    _UNCHECKED = "\u2610"  # ☐

    def _build_discovered_tree(self, frame, bundle, discovered_pairs, saved_pairs):
        """Render discovered attributes in a resizable Treeview with a tick column.

        Columns: a narrow checkbox-glyph column (click to toggle), then resizable
        Key and Value columns with a horizontal scrollbar so long keys are fully
        readable by stretching. Ticking is tracked in bundle['checked_items'].
        """
        container = ttk.Frame(frame)
        container.pack(fill=tk.X, pady=(0, 4))

        columns = ("check", "key", "value")
        # Height caps the visible rows so a huge attribute set doesn't dominate
        # the form; the tree scrolls internally.
        height = min(max(len(discovered_pairs), 3), 10)
        tree = ttk.Treeview(container, columns=columns, show="headings",
                            selectmode="none", height=height)
        tree.heading("check", text="")
        tree.heading("key", text="Attribute key")
        tree.heading("value", text="Value")
        tree.column("check", width=32, minwidth=32, stretch=False, anchor=tk.CENTER)
        tree.column("key", width=280, minwidth=120, stretch=True)   # resizable/draggable
        tree.column("value", width=180, minwidth=80, stretch=True)

        vsb = ttk.Scrollbar(container, orient=tk.VERTICAL, command=tree.yview)
        hsb = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.grid_columnconfigure(0, weight=1)

        checked = bundle['checked_items']
        # Track checked rows by their (key, value) PAIR, not by Treeview item id:
        # item ids are only unique within a single tree, so two config cards for
        # the same cluster produce colliding ids (both 'I001', ...). Keying on the
        # value pair keeps each card's selection correct and independent.
        checked.clear()
        for key, value in discovered_pairs:
            pre_ticked = (key, value) in saved_pairs
            glyph = self._CHECKED if pre_ticked else self._UNCHECKED
            tree.insert("", tk.END, values=(glyph, key, value))
            if pre_ticked:
                checked.add((key, value))

        def toggle(item):
            if not item:
                return
            pair = (tree.set(item, "key"), tree.set(item, "value"))
            if pair in checked:
                checked.discard(pair)
                tree.set(item, "check", self._UNCHECKED)
            else:
                checked.add(pair)
                tree.set(item, "check", self._CHECKED)

        def on_click(event):
            # Toggle when the click lands on a row (any column, for an easy target).
            row = tree.identify_row(event.y)
            if row:
                toggle(row)
                return "break"
        tree.bind("<Button-1>", on_click)
        # Space also toggles the focused row (keyboard accessibility).
        def on_space(event):
            toggle(tree.focus())
            return "break"
        tree.bind("<space>", on_space)

        # Scroll-wheel support (Windows/Linux + macOS).
        def on_wheel(event):
            if getattr(event, 'num', None) == 4:
                tree.yview_scroll(-3, "units")
            elif getattr(event, 'num', None) == 5:
                tree.yview_scroll(3, "units")
            else:
                tree.yview_scroll(int(-1 * (event.delta / 120)), "units")
        tree.bind("<MouseWheel>", on_wheel)
        tree.bind("<Button-4>", on_wheel)
        tree.bind("<Button-5>", on_wheel)

        bundle['discovered_tree'] = tree

    def _add_filter_row(self, bundle, key='', value=''):
        frame = bundle['filt_frame']
        r = ttk.Frame(frame)
        # Insert just before the "+ Add filter" button if present; simplest is pack at end.
        r.pack(fill=tk.X, anchor=tk.W)
        key_var = tk.StringVar(value=key)
        val_var = tk.StringVar(value=value)
        # Warning marker for custom rows (ECS) / all rows (EKS).
        ttk.Label(r, text="\u26a0", foreground=self.m._c_warn).pack(side=tk.LEFT)
        _Tooltip(r.winfo_children()[-1],
                 "Not verified against the cluster; matches nothing if no\n"
                 "running container carries this attribute.")
        ttk.Entry(r, textvariable=key_var, width=20).pack(side=tk.LEFT, padx=(2, 2))
        ttk.Label(r, text="=").pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=val_var, width=22).pack(side=tk.LEFT, padx=(2, 2))

        row_rec = {'kind': 'custom', 'key_var': key_var, 'value_var': val_var, 'frame': r}

        def remove():
            r.destroy()
            if row_rec in bundle['filter_rows']:
                bundle['filter_rows'].remove(row_rec)
        ttk.Button(r, text="Remove", command=remove).pack(side=tk.LEFT, padx=(4, 0))
        bundle['filter_rows'].append(row_rec)

    # -- tags ----------------------------------------------------------
    def _add_tag_row(self, key='', value=''):
        r = ttk.Frame(self._tags_container)
        r.pack(fill=tk.X, pady=2)
        key_var = tk.StringVar(value=key)
        val_var = tk.StringVar(value=value)
        ttk.Entry(r, textvariable=key_var, width=22).pack(side=tk.LEFT)
        ttk.Label(r, text="=").pack(side=tk.LEFT, padx=4)
        ttk.Entry(r, textvariable=val_var, width=28).pack(side=tk.LEFT)
        rec = (key_var, val_var, r)

        def remove():
            r.destroy()
            if rec in self._tag_rows:
                self._tag_rows.remove(rec)
        ttk.Button(r, text="Remove", command=remove).pack(side=tk.LEFT, padx=(6, 0))
        self._tag_rows.append(rec)

    # -- collect + review ---------------------------------------------
    def _collect_state(self):
        """Read the widgets back into self.state (name, description, monitoring,
        tags, sharing) so it can be validated and reviewed."""
        if self.state['mode'] == 'create':
            self.state['name'] = self._name_var.get().strip()
        self.state['description'] = self._desc_var.get().strip()

        # Monitoring configs + filters. Discovered ticks come from the Treeview
        # checked set; custom rows come from the free-form entries.
        for bundle in self._config_widgets:
            cfg = bundle['cfg']
            cfg['filters'] = self._selected_filters(bundle)
            # Fargate signal for preflight: discovery ran successfully AND found
            # zero attributes => the cluster has no registered EC2 container
            # instances right now, so any attribute filter matches nothing.
            # Only trust an empty result when discovery actually succeeded; a
            # manual ARN (no discovery) or a failed discovery must not trigger it.
            cfg['_no_discovered_attrs'] = bool(
                cfg.get('_discovery_ok') and not cfg.get('_discovered'))

        # Tags.
        tags = {}
        for key_var, val_var, _ in self._tag_rows:
            key = key_var.get().strip()
            if key:
                tags[key] = val_var.get().strip()
        self.state['tags'] = tags

        # Sharing.
        self.state['share'] = {
            'enabled': bool(self._share_var.get()),
            'account_id': self._acct_var.get().strip(),
        }

    def _on_review(self):
        self._collect_state()
        existing_names = getattr(self.m, '_existing_names', None)
        result = api.preflight_validate(self.state, existing_names=existing_names)
        if result['errors']:
            messagebox.showerror("Please fix the following",
                                 "\n".join("\u2022 " + e for e in result['errors']))
            return
        if result['warnings']:
            proceed = messagebox.askokcancel(
                "Warnings",
                "\n".join("\u2022 " + w for w in result['warnings'])
                + "\n\nProceed to review anyway?")
            if not proceed:
                return
        # Hand off to the manager's Review screen (Task 9).
        self.m._show_review(self.state, self.dialog)


class _Tooltip:
    """Minimal hover tooltip for a widget (cross-platform, no external deps)."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self._tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None):
        if self._tip is not None:
            return
        try:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + 20
        except tk.TclError:
            return
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self._tip, text=self.text, justify=tk.LEFT,
                 background="#FFFFE0", relief=tk.SOLID, borderwidth=1,
                 font=("TkDefaultFont", 8)).pack(ipadx=4, ipady=2)

    def _hide(self, _event=None):
        if self._tip is not None:
            self._tip.destroy()
            self._tip = None
