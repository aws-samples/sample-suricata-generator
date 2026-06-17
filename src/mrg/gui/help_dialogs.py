"""
Help Dialogs for Managed Rule Group Generator.

Provides:
- AWS Setup Guide: Multi-tab help dialog (Prerequisites, IAM Permissions, Credentials, Testing)
- About dialog: Version info and feature summary

Cross-platform notes (Section 14.3):
- macOS transient() workaround
- Platform-safe font fallbacks
"""

import platform
import threading
import tkinter as tk
from tkinter import ttk
from typing import Optional

from src.aws.aws_session_manager import AWSSessionManager
from src.mrg.version import MRG_VERSION

# Application metadata
APP_TITLE = "Managed Rule Group Generator"
APP_VERSION = MRG_VERSION

# IAM policy JSON for the Lambda role (from spec Section 11)
IAM_POLICY_JSON = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeRuleGroups",
      "Effect": "Allow",
      "Action": [
        "network-firewall:DescribeRuleGroup"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ManageUserRuleGroups",
      "Effect": "Allow",
      "Action": [
        "network-firewall:UpdateRuleGroup",
        "network-firewall:CreateRuleGroup",
        "network-firewall:DeleteRuleGroup",
        "network-firewall:TagResource"
      ],
      "Resource": "arn:aws:network-firewall:*:*:stateful-rulegroup/*"
    },
    {
      "Sid": "ListRuleGroups",
      "Effect": "Allow",
      "Action": [
        "network-firewall:ListRuleGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PublishNotifications",
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "arn:aws:sns:*:*:ManagedRuleGenerator-Notifications"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/ManagedRuleGenerator-*"
    }
  ]
}"""

# IAM deploy policy — permissions the user running the tool needs
IAM_DEPLOY_POLICY_JSON = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NetworkFirewallAccess",
      "Effect": "Allow",
      "Action": [
        "network-firewall:ListRuleGroups",
        "network-firewall:DescribeRuleGroup",
        "network-firewall:CreateRuleGroup",
        "network-firewall:UpdateRuleGroup",
        "network-firewall:DeleteRuleGroup",
        "network-firewall:TagResource"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaAccess",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:DeleteFunction",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:*:*:function:ManagedRuleGenerator-*"
    },
    {
      "Sid": "IAMAccess",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:ListRolePolicies",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:PassRole"
      ],
      "Resource": "arn:aws:iam::*:role/ManagedRuleGenerator-*"
    },
    {
      "Sid": "SNSAccess",
      "Effect": "Allow",
      "Action": [
        "sns:CreateTopic",
        "sns:DeleteTopic",
        "sns:Subscribe",
        "sns:Unsubscribe",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "sns:ListSubscriptionsByTopic",
        "sns:GetTopicAttributes",
        "sns:Publish"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsAccess",
      "Effect": "Allow",
      "Action": [
        "logs:DeleteLogGroup"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/ManagedRuleGenerator-*"
    },
    {
      "Sid": "STSAccess",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}"""


def _get_monospace_font():
    """Get platform-appropriate monospace font."""
    system = platform.system()
    if system == 'Darwin':
        return ('Menlo', 10)
    elif system == 'Windows':
        return ('Consolas', 10)
    else:
        return ('DejaVu Sans Mono', 10)


class AWSSetupGuideDialog:
    """Multi-tab help dialog for AWS setup guidance.

    Tabs:
    - Prerequisites: boto3 requirement and install instructions
    - IAM Permissions: IAM policy JSON with Copy to Clipboard
    - Credentials: AWS CLI configure, env vars, IAM role methods
    - Testing: Run Tests button for validating AWS connectivity
    """

    def __init__(self, parent, session_manager: Optional[AWSSessionManager] = None):
        self._parent = parent
        self._session_manager = session_manager or AWSSessionManager()
        self._dialog = tk.Toplevel(parent)
        self._dialog.title("AWS Setup Guide")
        self._dialog.geometry("680x750")
        self._dialog.resizable(True, True)
        self._dialog.minsize(550, 500)
        if platform.system() != 'Darwin':
            self._dialog.transient(parent)
        self._dialog.grab_set()
        self._test_results = []
        self._setup_ui()

    def _setup_ui(self):
        """Build the tabbed interface."""
        main_frame = ttk.Frame(self._dialog, padding=8)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._notebook = ttk.Notebook(main_frame)
        self._notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        self._setup_prerequisites_tab()
        self._setup_iam_tab()
        self._setup_credentials_tab()
        self._setup_testing_tab()

        # Close button
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Close", command=self._close).pack(side=tk.RIGHT)

    def _setup_prerequisites_tab(self):
        """Prerequisites tab: boto3 requirement and install instructions."""
        frame = ttk.Frame(self._notebook, padding=12)
        self._notebook.add(frame, text="Prerequisites")

        ttk.Label(frame, text="Prerequisites", font=('TkDefaultFont', 12, 'bold')).pack(anchor=tk.W, pady=(0, 8))

        text = tk.Text(frame, wrap=tk.WORD, height=20, state=tk.DISABLED,
                       font=('TkDefaultFont', 10))
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scroll.set)

        content = (
            "Python Requirements\n"
            "====================\n\n"
            "1. Python 3.7 or later\n"
            "   Download: https://www.python.org/downloads/\n\n"
            "2. boto3 (AWS SDK for Python)\n"
            "   boto3 is required for all AWS operations including fetching\n"
            "   managed rule groups, deploying, and managing backups.\n\n"
            "   Install with pip:\n"
            "   $ pip install boto3\n\n"
            "   Or with pip3 on systems where Python 2 is the default:\n"
            "   $ pip3 install boto3\n\n"
            "   Verify installation:\n"
            "   $ python -c \"import boto3; print(boto3.__version__)\"\n\n"
            "3. tkinter (included with most Python installations)\n"
            "   tkinter provides the GUI framework. It is included with\n"
            "   standard Python installations on Windows and macOS.\n\n"
            "   On Linux, you may need to install it separately:\n"
            "   $ sudo apt-get install python3-tk    (Debian/Ubuntu)\n"
            "   $ sudo yum install python3-tkinter   (RHEL/CentOS)\n\n"
            "AWS Requirements\n"
            "================\n\n"
            "1. An AWS account with Network Firewall access\n"
            "2. AWS credentials configured (see Credentials tab)\n"
            "3. Appropriate IAM permissions (see IAM Permissions tab)\n"
            "4. At least one AWS region with Network Firewall enabled\n"
        )

        text.config(state=tk.NORMAL)
        text.insert('1.0', content)
        text.config(state=tk.DISABLED)

        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _setup_iam_tab(self):
        """IAM Permissions tab: policy JSON with Copy to Clipboard."""
        frame = ttk.Frame(self._notebook, padding=12)
        self._notebook.add(frame, text="IAM Permissions")

        ttk.Label(frame, text="IAM Permissions", font=('TkDefaultFont', 12, 'bold')).pack(anchor=tk.W, pady=(0, 4))

        ttk.Label(frame, text=(
            "The user running this tool needs permissions to manage Network Firewall,\n"
            "Lambda, IAM, and SNS resources. Attach the following policy to your IAM\n"
            "user or role:"
        ), wraplength=620, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 8))

        # Policy display
        mono_font = _get_monospace_font()
        policy_frame = ttk.Frame(frame)
        policy_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        self._iam_text = tk.Text(policy_frame, wrap=tk.NONE, font=mono_font,
                                 state=tk.DISABLED)
        v_scroll = ttk.Scrollbar(policy_frame, orient=tk.VERTICAL, command=self._iam_text.yview)
        h_scroll = ttk.Scrollbar(policy_frame, orient=tk.HORIZONTAL, command=self._iam_text.xview)
        self._iam_text.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self._iam_text.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        policy_frame.grid_rowconfigure(0, weight=1)
        policy_frame.grid_columnconfigure(0, weight=1)

        self._iam_text.config(state=tk.NORMAL)
        self._iam_text.insert('1.0', IAM_DEPLOY_POLICY_JSON)
        self._iam_text.config(state=tk.DISABLED)

        # Copy button and info
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)

        self._copy_btn = ttk.Button(btn_frame, text="Copy to Clipboard",
                                     command=self._copy_iam_policy)
        self._copy_btn.pack(side=tk.LEFT)

        self._copy_status = ttk.Label(btn_frame, text="", foreground='#2E7D32')
        self._copy_status.pack(side=tk.LEFT, padx=(8, 0))

        ttk.Label(frame, text=(
            "\nPermission Details:\n"
            "\u2022 NetworkFirewallAccess — Build, deploy, manage, and delete rule groups\n"
            "\u2022 LambdaAccess — Deploy and manage the auto-sync Lambda function;\n"
            "  also used by Browse Deployed Configs (lambda:GetFunction,\n"
            "  lambda:GetFunctionConfiguration) to read deployed configurations\n"
            "\u2022 IAMAccess — Create/manage the Lambda execution role\n"
            "\u2022 SNSAccess — Subscribe to managed rule group updates and notifications\n"
            "\u2022 STSAccess — Validate credentials (Help > AWS Setup Guide > Testing)\n"
            "\n"
            "The Lambda function also needs its own IAM role (created automatically\n"
            "during deployment) with permissions to read managed rule groups, manage\n"
            "user rule groups, publish SNS notifications, and write CloudWatch logs."
        ), wraplength=620, justify=tk.LEFT, font=('TkDefaultFont', 9)).pack(anchor=tk.W, pady=(4, 0))

    def _setup_credentials_tab(self):
        """Credentials tab: three methods for configuring AWS credentials."""
        frame = ttk.Frame(self._notebook, padding=12)
        self._notebook.add(frame, text="Credentials")

        ttk.Label(frame, text="AWS Credentials Configuration",
                  font=('TkDefaultFont', 12, 'bold')).pack(anchor=tk.W, pady=(0, 8))

        text = tk.Text(frame, wrap=tk.WORD, height=20, state=tk.DISABLED,
                       font=('TkDefaultFont', 10))
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scroll.set)

        content = (
            "Method 1: AWS CLI (Recommended)\n"
            "================================\n\n"
            "Install the AWS CLI and run:\n\n"
            "  $ aws configure\n"
            "  AWS Access Key ID: AKIAIOSFODNN7EXAMPLE\n"
            "  AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/...\n"
            "  Default region name: us-east-1\n"
            "  Default output format: json\n\n"
            "For named profiles (multi-account):\n\n"
            "  $ aws configure --profile prod-account\n\n"
            "Then select the profile in the Profile dropdown in the\n"
            "configuration panel.\n\n\n"
            "Method 2: Environment Variables\n"
            "================================\n\n"
            "Set these environment variables before launching the tool:\n\n"
            "  Windows (cmd):\n"
            "    set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "    set AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/...\n"
            "    set AWS_DEFAULT_REGION=us-east-1\n\n"
            "  macOS / Linux:\n"
            "    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/...\n"
            "    export AWS_DEFAULT_REGION=us-east-1\n\n\n"
            "Method 3: IAM Role (EC2 / SSO)\n"
            "================================\n\n"
            "If running on an EC2 instance, assign an IAM role with the\n"
            "necessary permissions. No credentials configuration needed.\n\n"
            "For AWS IAM Identity Center (SSO):\n\n"
            "  $ aws configure sso\n"
            "  $ aws sso login --profile my-sso-profile\n\n"
            "Then select the SSO profile from the Profile dropdown.\n\n\n"
            "Profile Selection in This Tool\n"
            "================================\n\n"
            "The Profile dropdown in the configuration panel lists all\n"
            "profiles from ~/.aws/credentials and ~/.aws/config.\n\n"
            "  - (default) uses the standard AWS credential chain\n"
            "  - Selecting a named profile overrides the credential chain\n"
            "  - The selected profile is saved in the .mrg file\n"
            "  - Use the refresh button to reload profiles after changes\n"
        )

        text.config(state=tk.NORMAL)
        text.insert('1.0', content)
        text.config(state=tk.DISABLED)

        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _setup_testing_tab(self):
        """Testing tab: Run Tests button with pass/fail results."""
        frame = ttk.Frame(self._notebook, padding=12)
        self._notebook.add(frame, text="Testing")

        ttk.Label(frame, text="AWS Connectivity Tests",
                  font=('TkDefaultFont', 12, 'bold')).pack(anchor=tk.W, pady=(0, 4))

        ttk.Label(frame, text=(
            "Click 'Run Tests' to validate your AWS setup. Tests check boto3\n"
            "installation, credentials, and API access."
        ), wraplength=620, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 8))

        # Profile info
        profile_name = self._session_manager.display_name if self._session_manager else '(default)'
        self._profile_info_label = ttk.Label(
            frame, text="Testing with profile: {}".format(profile_name),
            font=('TkDefaultFont', 10, 'italic'))
        self._profile_info_label.pack(anchor=tk.W, pady=(0, 8))

        # Run Tests button
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(0, 8))
        self._run_tests_btn = ttk.Button(btn_frame, text="Run Tests", command=self._run_tests)
        self._run_tests_btn.pack(side=tk.LEFT)

        self._test_status_label = ttk.Label(btn_frame, text="", font=('TkDefaultFont', 9))
        self._test_status_label.pack(side=tk.LEFT, padx=(12, 0))

        # Results
        results_frame = ttk.LabelFrame(frame, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True)

        self._results_text = tk.Text(results_frame, wrap=tk.WORD, state=tk.DISABLED,
                                      font=('TkDefaultFont', 10))
        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL,
                                        command=self._results_text.yview)
        self._results_text.configure(yscrollcommand=results_scroll.set)

        self._results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=4)

        # Configure tags for pass/fail
        self._results_text.tag_configure('pass', foreground='#2E7D32')
        self._results_text.tag_configure('fail', foreground='#D32F2F')
        self._results_text.tag_configure('info', foreground='#1976D2')
        self._results_text.tag_configure('header', font=('TkDefaultFont', 10, 'bold'))

    def _copy_iam_policy(self):
        """Copy the IAM policy JSON to the clipboard."""
        try:
            self._dialog.clipboard_clear()
            self._dialog.clipboard_append(IAM_DEPLOY_POLICY_JSON)
            self._copy_status.config(text="Copied!")
            self._dialog.after(2000, lambda: self._copy_status.config(text=""))
        except tk.TclError:
            self._copy_status.config(text="Copy failed")

    def _run_tests(self):
        """Run AWS connectivity tests in a background thread."""
        self._run_tests_btn.config(state=tk.DISABLED)
        self._test_status_label.config(text="Running tests...")
        self._results_text.config(state=tk.NORMAL)
        self._results_text.delete('1.0', tk.END)
        self._results_text.config(state=tk.DISABLED)

        def _do_tests():
            results = run_aws_tests(self._session_manager)
            self._parent.after(0, lambda: self._display_test_results(results))

        threading.Thread(target=_do_tests, daemon=True).start()

    def _display_test_results(self, results):
        """Display test results in the results text widget."""
        self._test_results = results
        self._run_tests_btn.config(state=tk.NORMAL)

        passed = sum(1 for r in results if r['passed'])
        total = len(results)
        self._test_status_label.config(
            text="{}/{} tests passed".format(passed, total),
            foreground='#2E7D32' if passed == total else '#D32F2F')

        self._results_text.config(state=tk.NORMAL)
        self._results_text.delete('1.0', tk.END)

        for r in results:
            status = "PASS" if r['passed'] else "FAIL"
            tag = 'pass' if r['passed'] else 'fail'
            self._results_text.insert(tk.END, "[{}] ".format(status), tag)
            self._results_text.insert(tk.END, "{}\n".format(r['name']), 'header')
            if r.get('detail'):
                self._results_text.insert(tk.END, "      {}\n".format(r['detail']), 'info')
            self._results_text.insert(tk.END, "\n")

        self._results_text.config(state=tk.DISABLED)

    def _close(self):
        """Close the dialog."""
        if self._dialog.winfo_exists():
            self._dialog.grab_release()
            self._dialog.destroy()

    def wait(self):
        """Wait for the dialog to close."""
        if self._dialog.winfo_exists():
            self._parent.wait_window(self._dialog)

    @property
    def dialog(self):
        return self._dialog

    @property
    def notebook(self):
        return self._notebook

    @property
    def test_results(self):
        return list(self._test_results)


def run_aws_tests(session_manager: Optional[AWSSessionManager] = None) -> list:
    """Run AWS connectivity tests and return results.

    Tests:
    1. boto3 installation
    2. AWS credentials (sts:GetCallerIdentity)
    3. Network Firewall API access (ListRuleGroups)
    4. Lambda/IAM permissions (iam:GetRole / lambda:GetFunction)

    Args:
        session_manager: Optional AWSSessionManager instance.

    Returns:
        List of dicts with 'name', 'passed', 'detail' keys.
    """
    if session_manager is None:
        session_manager = AWSSessionManager()

    results = []

    # Test 1: boto3 installation
    try:
        import boto3
        results.append({
            'name': 'boto3 Installation',
            'passed': True,
            'detail': 'boto3 {} installed'.format(boto3.__version__),
        })
    except ImportError:
        results.append({
            'name': 'boto3 Installation',
            'passed': False,
            'detail': 'boto3 is not installed. Run: pip install boto3',
        })
        return results  # Can't proceed without boto3

    # Test 2: AWS Credentials
    profile = session_manager.display_name
    valid, info = session_manager.validate_profile()
    if valid:
        account = info.get('Account', 'Unknown')
        arn = info.get('Arn', 'Unknown')
        results.append({
            'name': 'AWS Credentials ({})'.format(profile),
            'passed': True,
            'detail': 'Account: {}, Identity: {}'.format(account, arn),
        })
    else:
        results.append({
            'name': 'AWS Credentials ({})'.format(profile),
            'passed': False,
            'detail': str(info),
        })
        return results  # Can't proceed without credentials

    # Test 3: Network Firewall API access
    try:
        region = session_manager.get_default_region()
        client = session_manager.get_client('network-firewall', region_name=region)
        response = client.list_rule_groups(Scope='MANAGED', Type='STATEFUL', MaxResults=1)
        count = len(response.get('RuleGroups', []))
        results.append({
            'name': 'Network Firewall API Access',
            'passed': True,
            'detail': 'ListRuleGroups succeeded in {} ({} managed rule groups found)'.format(
                region, count if count else '0+'),
        })
    except Exception as e:
        error_str = str(e)
        results.append({
            'name': 'Network Firewall API Access',
            'passed': False,
            'detail': error_str[:200],
        })

    # Test 4: Lambda/IAM Permissions
    try:
        region = session_manager.get_default_region()
        lambda_client = session_manager.get_client('lambda', region_name=region)
        # Try to get the MRG Lambda function — it may not exist yet, but the API call
        # tests whether we have lambda:GetFunction permission
        try:
            func_name = 'ManagedRuleGenerator-{}'.format(region)
            lambda_client.get_function(FunctionName=func_name)
            results.append({
                'name': 'Lambda/IAM Permissions',
                'passed': True,
                'detail': 'Lambda function found: {}'.format(func_name),
            })
        except lambda_client.exceptions.ResourceNotFoundException:
            # Function doesn't exist yet, but we had permission to check
            results.append({
                'name': 'Lambda/IAM Permissions',
                'passed': True,
                'detail': 'Lambda access OK (function not yet deployed)',
            })
    except Exception as e:
        error_str = str(e)
        if 'AccessDenied' in error_str or 'not authorized' in error_str.lower():
            results.append({
                'name': 'Lambda/IAM Permissions',
                'passed': False,
                'detail': 'Access denied: {}'.format(error_str[:150]),
            })
        else:
            results.append({
                'name': 'Lambda/IAM Permissions',
                'passed': False,
                'detail': error_str[:200],
            })

    return results


def show_aws_setup_guide(parent, session_manager: Optional[AWSSessionManager] = None):
    """Show the AWS Setup Guide dialog.

    Args:
        parent: Parent tkinter widget.
        session_manager: Optional AWSSessionManager instance.

    Returns:
        The AWSSetupGuideDialog instance.
    """
    dialog = AWSSetupGuideDialog(parent, session_manager=session_manager)
    dialog.wait()
    return dialog


def load_release_notes():
    """Load and parse release notes from RELEASE_NOTES.md file.

    Extracts the first two versions (current and previous) for display
    in the About dialog, following the same pattern as Suricata Generator.

    Returns:
        Formatted release notes string.
    """
    try:
        import os
        # Look for RELEASE_NOTES.md in the project root (parent of src/)
        script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        release_notes_path = os.path.join(script_dir, "RELEASE_NOTES.md")

        with open(release_notes_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract the first two versions for the About dialog
        lines = content.split('\n')
        release_text = "Release Notes:\n\n"
        version_count = 0

        for line in lines:
            if line.startswith('## Version') and version_count < 2:
                version_count += 1
                if version_count > 1:
                    release_text += "\n"
                release_text += line.replace('## ', '') + ":\n"
            elif line.startswith('### ') and version_count <= 2:
                release_text += "\u2022 " + line.replace('### ', '') + "\n"
            elif line.startswith('- **') and version_count <= 2:
                release_text += "  " + line.replace('- **', '\u2022 ').replace('**:', ':').replace('**', '') + "\n"
            elif line.startswith('---') and version_count >= 2:
                break

        return release_text.strip()

    except (OSError, IOError, UnicodeDecodeError):
        return "Release Notes:\n\nUnable to load release notes from RELEASE_NOTES.md file."


def show_about(parent):
    """Show the About dialog with version info, authors, release notes, and feature summary.

    Args:
        parent: Parent tkinter widget.
    """
    import webbrowser

    dialog = tk.Toplevel(parent)
    dialog.title("About {}".format(APP_TITLE))
    dialog.geometry("550x580")
    dialog.resizable(False, False)
    if platform.system() != 'Darwin':
        dialog.transient(parent)
    dialog.grab_set()

    main_frame = ttk.Frame(dialog, padding=16)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Text widget with scrollbar for rich formatting
    text_frame = ttk.Frame(main_frame)
    text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

    text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('TkDefaultFont', 10),
                          state=tk.DISABLED, bg=dialog.cget('bg'), bd=0,
                          highlightthickness=0)
    scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Configure text tags
    text_widget.tag_configure('title', font=('TkDefaultFont', 14, 'bold'), justify=tk.CENTER)
    text_widget.tag_configure('version', font=('TkDefaultFont', 11), justify=tk.CENTER)
    text_widget.tag_configure('description', font=('TkDefaultFont', 10), justify=tk.CENTER)
    text_widget.tag_configure('heading', font=('TkDefaultFont', 10, 'bold'))
    text_widget.tag_configure('bold', font=('TkDefaultFont', 10, 'bold'))
    text_widget.tag_configure('hyperlink', foreground='blue', underline=True)
    text_widget.tag_configure('normal', font=('TkDefaultFont', 9))
    text_widget.tag_configure('bullet', font=('TkDefaultFont', 9))

    text_widget.config(state=tk.NORMAL)

    # Title and version
    text_widget.insert(tk.END, APP_TITLE + '\n', 'title')
    text_widget.insert(tk.END, 'Version {}\n\n'.format(APP_VERSION), 'version')
    text_widget.insert(tk.END,
        'Generate filtered rule groups from AWS-managed\n'
        'threat signature rule groups for Network Firewall.\n\n', 'description')

    # Authors section
    text_widget.insert(tk.END, 'Authors:\n', 'heading')

    # Brian Westmoreland with LinkedIn link
    brian_name_start = text_widget.index(tk.INSERT)
    text_widget.insert(tk.END, 'Brian Westmoreland')
    brian_name_end = text_widget.index(tk.INSERT)
    text_widget.tag_add('bold', brian_name_start, brian_name_end)
    text_widget.insert(tk.END, ' (')
    brian_link_start = text_widget.index(tk.INSERT)
    text_widget.insert(tk.END, 'LinkedIn')
    brian_link_end = text_widget.index(tk.INSERT)
    text_widget.tag_add('hyperlink', brian_link_start, brian_link_end)
    text_widget.tag_add('brian_linkedin', brian_link_start, brian_link_end)
    text_widget.insert(tk.END, ')\n')

    # Lawton Pittenger with LinkedIn link
    lawton_name_start = text_widget.index(tk.INSERT)
    text_widget.insert(tk.END, 'Lawton Pittenger')
    lawton_name_end = text_widget.index(tk.INSERT)
    text_widget.tag_add('bold', lawton_name_start, lawton_name_end)
    text_widget.insert(tk.END, ' (')
    lawton_link_start = text_widget.index(tk.INSERT)
    text_widget.insert(tk.END, 'LinkedIn')
    lawton_link_end = text_widget.index(tk.INSERT)
    text_widget.tag_add('hyperlink', lawton_link_start, lawton_link_end)
    text_widget.tag_add('lawton_linkedin', lawton_link_start, lawton_link_end)
    text_widget.insert(tk.END, ')\n\n')

    # Configure hyperlink behavior
    def on_brian_click(event):
        webbrowser.open('https://www.linkedin.com/in/brian-westmoreland-b55b755/')

    def on_lawton_click(event):
        webbrowser.open('https://www.linkedin.com/in/lawtonpittenger/')

    def on_link_enter(event):
        text_widget.config(cursor='hand2')

    def on_link_leave(event):
        text_widget.config(cursor='')

    text_widget.tag_bind('brian_linkedin', '<Button-1>', on_brian_click)
    text_widget.tag_bind('brian_linkedin', '<Enter>', on_link_enter)
    text_widget.tag_bind('brian_linkedin', '<Leave>', on_link_leave)

    text_widget.tag_bind('lawton_linkedin', '<Button-1>', on_lawton_click)
    text_widget.tag_bind('lawton_linkedin', '<Enter>', on_link_enter)
    text_widget.tag_bind('lawton_linkedin', '<Leave>', on_link_leave)

    text_widget.config(state=tk.DISABLED)

    # Close button
    ttk.Button(main_frame, text="Close",
               command=lambda: _close_dialog(dialog)).pack(side=tk.RIGHT)

    return dialog


def _close_dialog(dialog):
    """Close a dialog safely."""
    if dialog.winfo_exists():
        dialog.grab_release()
        dialog.destroy()


def export_rules_to_suricata(rules: list, filepath: str) -> int:
    """Export rules to a .suricata file.

    Writes the raw rule strings to the specified file, one rule per line.
    Only active rules (non-comment, non-blank with a raw string) are exported.

    Args:
        rules: List of ParsedRule objects.
        filepath: Path to write the .suricata file.

    Returns:
        Number of rules written.

    Raises:
        IOError: If the file cannot be written.
    """
    count = 0
    with open(filepath, 'w', encoding='utf-8') as f:
        for rule in rules:
            if rule.raw and not rule.is_comment and not rule.is_blank:
                f.write(rule.raw.rstrip() + '\n')
                count += 1
    return count
