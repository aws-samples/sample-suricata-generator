# Release Notes

## Version 2.1.2 - April 14, 2026

### Flow Tester v1.3.0 - April 17, 2026

#### New Protocol Support
- **Added 14 new protocols to Test Flow**: dns, ssh, smtp, ftp, imap, dcerpc, smb, krb5, msn, ikev2, http2, ntp, dhcp, tftp
  - **TCP-based protocols** (ssh, smtp, ftp, imap, dcerpc, smb, krb5, msn, ikev2, http2): Full TCP handshake + established phase testing with protocol-specific flow diagram steps (e.g., "SSH Key Exchange", "SMB Negotiate Request")
  - **UDP-based protocols** (dns, ntp, dhcp, tftp): Request/response flow diagrams with correct protocol matching against `udp` rules
  - **DNS query matching**: Rules using `dns.query; content:".example.com";` are now evaluated against the query name input, using the same pattern matching logic as `tls.sni` and `http.host`
  - Protocol dropdown expanded from 6 to 20 protocols with sensible default ports for each (SSH→22, SMTP→25, DNS→53, SMB→445, etc.)

#### Contextual Query Name Field for DNS
- **DNS flows show a "Query Name:" input field**: Similar to the URL/Domain field for HTTP/TLS, selecting DNS reveals a query name input (default: `example.com`) used to evaluate `dns.query` content matching in rules

#### Bug Fix: dotprefix Modifier Matching
- **Fixed `dotprefix` content matching for domain rules**: Rules using `content:".example.com"; dotprefix;` now correctly match both `example.com` and `sub.example.com`
  - Previously, `dotprefix` matching failed for exact domain matches (e.g., `example.com` against `.example.com`)
  - Now simulates Suricata's actual behavior of prepending `.` to the inspected buffer before matching

#### Wording Change: No Matching Rules
- **Changed "ALLOWED (no matching rules)" to "UNKNOWN (no matching rules)"**: When no rules match a test flow, the result now reflects that the outcome depends on the firewall policy's default action, which is external to the rule group

#### Improvement: Overridden Rules Hidden from Results
- **FLOW-scope PASS rules removed from results when overridden by PACKET-scope DROP/REJECT**: When a scope conflict occurs and the PACKET-scope action is the actual final behavior, the overridden FLOW-scope PASS rule is no longer displayed in the Matched Rules table or Flow Diagram, reducing user confusion.

---

### Bug Fix: Load AWS Best Practices Template Broken
- **Fixed "Load AWS Best Practices Template" failing to extract rules**: The AWS best practices page updated its introductory text before the Suricata rules template, causing the parser to fail with "Could not find Suricata rules in the AWS best practices page"
  - **Root Cause**: The `extract_rules_from_html()` method in `file_manager.py` used a hardcoded marker string (`"Below we have also included a custom template for an egress security use case"`) to locate the rules section in the HTML. The AWS page changed this text to `"Here is a custom Suricata template that customer find helpful"`, so the marker was never found and the method returned an empty string
  - **Solution**: Updated the marker to match the current page text, with the old marker retained as a fallback for resilience against future changes
  - **Impact**: File > Load AWS Best Practices Template now works again, correctly fetching and parsing all rules from the AWS best practices page

---

## Version 2.1.1 - March 26, 2026

### Bug Fix: Comment Toggle (Spacebar) Error with Legitimate Comments
- **Fixed "Toggle Completed with Errors" popup when toggling mixed selections**: Corrected bug where pressing spacebar to comment/uncomment rules would show an error dialog when the selection included legitimate comments (not commented-out rules)
  - **Root Cause**: The toggle logic attempted to parse every comment line back into a valid Suricata rule. Legitimate comments (e.g., `# This is a note`) failed parsing and triggered validation error popups
  - **New Behavior**: Uses a simple `#` toggle approach:
    - If **any** selected non-blank line is an active rule → **add `#`** to all selected lines (rules become commented, existing comments get an additional `#`)
    - If **all** selected non-blank lines are comments → **remove one `#`** from each line. If the result is a valid rule, it becomes active. If not, it stays as a comment with one fewer `#`
  - **Impact**: Mixed selections of rules and comments no longer produce error popups. The spacebar toggle works predictably in all cases

### Enhancement: Case-Insensitive Keyboard Shortcuts
- **Fixed keyboard shortcuts not working with Caps Lock enabled**: All Ctrl+letter shortcuts now work regardless of Caps Lock state
  - Added uppercase bindings for all Ctrl+letter combinations: Ctrl+N, Ctrl+O, Ctrl+S, Ctrl+Z, Ctrl+E, Ctrl+C, Ctrl+A, Ctrl+F, Ctrl+G, and Ctrl+V
  - Previously, shortcuts like Ctrl+F (Find) only responded to lowercase `f`, so pressing Ctrl+F with Caps Lock on had no effect
  - Applies to both the main window bindings and the tree-specific Ctrl+V paste binding

---

## Version 2.1.0 - March 22, 2026

### New Feature: AWS Managed Rule Group Analysis
- **Complete Firewall Visibility in Rule Usage Analyzer**: Enhanced the CloudWatch Rule Usage Analyzer to include AWS managed rule groups alongside your custom rule groups, giving you full visibility across your entire firewall policy
  - **Browse and Select Managed Rule Groups**: New "Add Managed Rule Groups" button in the "Configure Rule Usage Analysis" dialog opens a browser where you can browse all AWS managed rule groups (e.g., ThreatSignaturesPhishingActionOrder, MalwareDomainListActionOrder, BotNetCommandAndControlActionOrder) and select which ones to include in the analysis
    - Multi-select checkbox interface for selecting multiple managed rule groups at once
    - Displays rule count per group with search filtering by name
    - Region inherited from the parent configuration dialog
    - Selections remembered during the session for easy re-analysis
  - **Combined CloudWatch Analysis**: Selected managed rule group SIDs are extracted via lightweight regex parsing and included alongside your custom rule SIDs in the CloudWatch Logs Insights query, providing hit counts for ALL rules in your firewall policy
    - Fast SID extraction handles managed rule groups with thousands of rules (e.g., 4,050+ rules) in milliseconds
    - No additional CloudWatch query cost — the same query runs against the same log group; only post-processing is expanded
  - **New "All Rules" Tab (Tab 10)**: Comprehensive view showing every rule (custom + managed) with hit counts in a sortable, filterable table
    - Columns: SID, Hits, Hits/Day, % Traffic, Last Hit, Source, Action, Message
    - Filter controls for Source (custom file or individual managed rule group), Action (drop/alert/pass/reject), and Hits (all/has hits/unused/low-frequency)
    - Column sorting with default by Hits descending
    - Color-coded rows: custom rules in black, managed rules in teal (#2E8B8B)
    - Export support in text and HTML formats
  - **Enhanced Summary Tab**: New "Analysis Scope" section showing custom rule count, managed rule group breakdown (per-group rule counts), and total rules analyzed
    - Per-group effectiveness summary: total rules, rules with hits, total hits
    - Color legend explaining teal (managed) vs black (custom) distinction
  - **Search Tab Integration**: Searching for a managed rule SID shows the managed rule group name as the source with teal color styling
  - **Reduced Untracked Noise**: Managed rule SIDs are now recognized as "known" and excluded from the Untracked tab, reducing noise from SIDs that were previously unidentifiable
  - **Health Score Unchanged**: Health score calculation remains custom-rules-only — managed rules are not included to avoid distorting the score, since users don't control managed rule content
  - **Persistent Cache**: All managed rule group data (metadata, SIDs, per-SID statistics) saved to `.stats` files for instant offline access on subsequent opens without re-querying AWS
  - **No New Dependencies**: Uses existing boto3 and AWS session management; requires read-only `network-firewall:ListRuleGroups` and `network-firewall:DescribeRuleGroup` permissions (most users already have these from the import feature)

---

## Flow Tester Bug Fixes (v1.2.1) - March 17, 2026

### Bug Fix 1: All-Negated Network Groups Not Matching External IPs
- **Fixed $EXTERNAL_NET matching failure**: Corrected critical bug in `_ip_matches_group()` where IP addresses were never matched against all-negated network groups like `[!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16]`
  - **Root Cause**: The method tracked whether any positive (non-negated) item matched via an `included` flag, but when all items in the group were negations, there were no positive items to set `included = True` — so the method always returned `False`
  - **Impact**: Every rule referencing `$EXTERNAL_NET` (when defined as the negation of `$HOME_NET`) failed to match any destination IP. The flow tester reported "no rules match" and "undetermined" for all flows targeting external IPs
  - **Solution**: Added a `has_positive_item` flag. When all items in a group are negated and no exclusion matched the IP, the method now correctly returns `True` — matching Suricata's semantics where an all-negated group means "everything EXCEPT these ranges"

### Bug Fix 2: Partial Allow Not Detected When Handshake Passes but No Established Rule Matches
- **Fixed missing PARTIAL_ALLOW detection**: Corrected bug where flows that passed the TCP handshake but had no rule governing the established/application-layer phase were incorrectly reported as "ALLOWED"
  - **Root Cause**: The existing `partial_allow` check only detected cases where the established phase was actively blocked (DROP/REJECT). When the established phase had zero matching action rules (both `flow_scope_action` and `packet_scope_action` were `None`), `_test_flow_phase` returned `True` and the final action remained "PASS" from the handshake
  - **Impact**: A flow like `tls 10.0.0.10:1234 -> 8.8.8.8:443 www.notamazon.com` against a ruleset with only a handshake pass rule and a domain-specific TLS pass rule (for `.amazon.com`) would show as "ALLOWED" instead of indicating the undetermined outcome
  - **Solution**: After the established phase completes, the code now checks `scope_details['established']` — if both flow and packet scope actions are `None`, it sets `partial_allow = True` and `final_action = 'PARTIAL_ALLOW'`
  - **UI**: Added `PARTIAL_ALLOW` display in the flow test results, shown in orange: "PARTIAL ALLOW - Handshake passes but no rule governs established traffic (port appears OPEN, app-layer outcome undetermined)"

---

## Palo Alto Importer v1.0.1-beta - March 15, 2026

### Bug Fix: macOS Dialog Resizability
- **Made all import wizard dialogs resizable**: Beta warning, Step 1 (file selection), and Step 1.5 (zone mapping) dialogs changed from fixed-size to resizable, fixing a macOS issue where the Browse button was cut off on the Step 1 dialog
  - Step 1 default width also increased from 550px to 600px for better cross-platform fit
  - Steps 2 and 3 were already resizable (no change)

---

## Version 2.0.0 - March 14, 2026

### Project Restructuring
- **Organized Source Code into Package Structure**: Restructured all Python source files from a flat root directory into a well-organized `src/` package with categorized subdirectories
  - **`src/core/`**: Core data models and utilities (`suricata_rule.py`, `constants.py`, `version.py`, `security_validator.py`, `rule_filter.py`)
  - **`src/analysis/`**: Rule analysis and testing (`rule_analyzer.py`, `flow_tester.py`, `rule_usage_analyzer.py`)
  - **`src/aws/`**: AWS integration (`aws_session_manager.py`, `aws_service_detector.py`, `traffic_analyzer.py`, `traffic_analyzer_ui.py`)
  - **`src/importers/`**: Import functionality (`domain_importer.py`, `domain_list_importer.py`, `stateful_rule_importer.py`, `palo_alto_importer.py`)
  - **`src/managers/`**: File, search, template, and revision management (`file_manager.py`, `search_manager.py`, `template_manager.py`, `revision_manager.py`)
  - **`src/gui/`**: UI components (`ui_manager.py`, `advanced_editor.py`, `advanced_editor_tkinter_backup.py`)
  - **`data/`**: Data files moved to dedicated directory (`common_ports.json`, `content_keywords.json`, `rule_templates.json`, `palo_alto_app_map.json`)
- **Added `.gitignore`**: New `.gitignore` file excludes `__pycache__/`, `*.pyc`, virtual environments, IDE files, and OS-specific files
- **No Functionality Changes**: All features work identically — this is purely an organizational improvement
- **Same Launch Command**: Program still launches with `python suricata_generator.py` from the project root

---

## Version 1.33.0 - March 14, 2026

### New Feature: Palo Alto Networks Configuration Import (Beta)
- **Import Palo Alto XML Configurations**: Convert Palo Alto Networks firewall security policies to Suricata rules for AWS Network Firewall migration
  - **File > Import Palo Alto Configuration**: Multi-step wizard guides users through XML file selection, zone mapping, scope selection, and conversion preview
  - **App-ID Conversion**: Best-effort mapping of Palo Alto App-ID applications to Suricata equivalents
    - **Tier 1 (High Confidence)**: Direct protocol mapping for 24 applications (ssl→tls, web-browsing→http, dns→dns, ssh→ssh, etc.)
    - **Tier 2 (Medium Confidence)**: Domain-based TLS SNI matching for 50+ SaaS/cloud applications (Facebook, Slack, Teams, GitHub, etc.)
    - **Tier 3 (Unmappable)**: Commented-out stubs with suggested alternatives for proprietary App-ID signatures
  - **Address Object Resolution**: Supports ip-netmask, ip-range, FQDN, address groups (including nested groups), and inline IP/CIDR addresses
  - **Zone-to-Variable Mapping**: PA zones converted to Suricata IP Set variables with optional CIDR definition dialog
  - **GeoIP Support**: Country codes in source/destination fields automatically converted to Suricata `geoip` keywords
  - **URL Category Mapping**: PA URL filtering categories mapped to AWS `aws_domain_category` keywords; custom URL category lists expanded to domain-matching rules
  - **FQDN Domain Rules**: FQDN address objects generate TLS SNI + HTTP host rule pairs; non-HTTP/TLS protocols flagged with manual IP resolution guidance
  - **Deny Action Mapping**: Application-aware deny action conversion — TCP apps map to `reject` (RST), UDP apps map to `drop`, matching PA's per-application deny behavior
  - **Conversion Report**: Export detailed text or HTML reports documenting every mapping decision, warning, and recommendation
  - **Test Mode**: Convert all imported rules to `alert` action for safe production testing
  - **Rule Analyzer Integration**: Optional post-import analysis for conflict detection and optimization
  - **Data-Driven Design**: All application mappings, URL categories, and service definitions stored in user-editable `palo_alto_app_map.json`
  - **Supported PAN-OS Versions**: 10.1, 10.2, 11.0, 11.1, 11.2 (core XML schema compatible with 8.x and 9.x)

---

## Version 1.32.0 - February 22, 2026

### New Feature: AWS Profile Support
- **Multi-Account AWS Profile Selector**: New centralized AWS session management enables seamless switching between AWS accounts and regions directly within the program
  - **Profile Selector in Status Bar**: Dropdown combobox on the right side of the status bar shows all available AWS profiles from `~/.aws/credentials` and `~/.aws/config`
    - Select any profile to immediately change which AWS credentials and default region are used for all subsequent AWS operations
    - `(default)` option uses the standard AWS credential chain (identical to previous behavior)
    - `↻` Refresh button re-reads AWS config files to pick up newly added profiles without restarting
  - **Session-Only Selection**: Profile resets to `(default)` on every program launch — not persisted to disk for predictable startup behavior and security
  - **Centralized Session Manager**: New `aws_session_manager.py` module provides a single point of control for all AWS API calls across 8 source files
    - All boto3 `Session()` and `client()` calls routed through `AWSSessionManager` for consistent credential usage
    - Profile's configured default region automatically picked up by region selectors throughout the program
    - Lazy credential validation — no AWS API calls triggered on profile selection or startup
  - **Profile-Aware Error Messages**: All AWS credential error dialogs updated to include the active profile name and suggest `aws configure --profile <name>` or switching profiles
  - **Comprehensive AWS Feature Coverage**: Profile selection affects all AWS operations:
    - Export > AWS Network Firewall (Direct Deploy)
    - Import Stateful Rule Group from AWS
    - Import Domain List from AWS
    - Traffic Analysis (CloudWatch queries)
    - Rule Usage Analysis (CloudWatch queries)
    - Help > AWS Setup credential verification
  - **Graceful Degradation**: Non-AWS features completely unaffected by profile selection
    - boto3 not installed → dropdown shows `(boto3 not installed)` and is disabled
    - No AWS config files → dropdown shows `(no profiles found)` and is disabled
  - **Native AssumeRole and SSO Support**: Profiles with `role_arn`/`source_profile` or SSO configuration work transparently via boto3's native handling
  - **Cross-Platform**: Works on Windows, macOS, and Linux — all file path resolution delegated to boto3/botocore

---

## Version 1.31.3 - February 19, 2026

### Bug Fix: Untracked Rules Lost on Stats File Reload
- **Fixed untracked SIDs not persisting across program restarts**: Corrected bug where the Untracked tab showed 0 rules when viewing saved analysis results after closing and reopening the program, despite previously showing the correct count
  - **Root Cause**: The `untracked_sids` field was missing from both the `_serialize_analysis_results()` and `_deserialize_analysis_results()` methods in `ui_manager.py`. When saving to `.stats` file, `untracked_sids` was not written to JSON; when loading, it was never restored — defaulting to an empty set
  - **Impact**: After closing the program and reopening with a saved `.stats` file, the Untracked tab always showed "0" rules even though the original analysis had detected untracked SIDs (e.g., AWS default policy rules not in the user's rule file)
  - **Solution**: Added `untracked_sids` to both serialization (save) and deserialization (load) methods, matching the existing pattern used for `unused_sids` and `unlogged_sids`
  - **Existing `.stats` files**: Files saved before this fix will load with an empty untracked set (graceful default). Re-save after running analysis to persist the data

---

## Flow Tester Enhancement (v1.2.0) - February 17, 2026

### Three Major Fixes: Flowbits Inference, Cross-Scope Deconfliction, and Partial Allow Detection
- **Flowbits Inference Engine**: The flow tester no longer skips rules with `flowbits:isnotset` — it now infers the flowbits state by scanning the ruleset
  - **How It Works**: When encountering `flowbits:isnotset,<bitname>`, the tester finds all rules that do `flowbits:set,<bitname>` and checks if any would match the current flow. If no setter matches, the bit is NOT set, so `isnotset` = TRUE and the rule is evaluated
  - **Real-World Impact**: Default block rules like `reject tcp ... (flowbits:isnotset,blocked; flowbits:isnotset,X25519Kyber768; ...)` now correctly match plain TCP flows where no TLS rule sets those bits
  - **Inference Display**: Results table shows color-coded flowbits inference rows (green for TRUE, red for FALSE) with explanations like "flowbits:isnotset,blocked = TRUE (no tls rule that sets 'blocked' matches this tcp flow)"
- **Cross-Scope Deconfliction Fix**: PACKET-scope DROP/REJECT now correctly overrides FLOW-scope PASS
  - **The Problem**: FLOW-scope PASS from IPONLY rules (e.g., `pass ip 10.0.2.16/28 <> 10.0.1.16/28`) was incorrectly stopping all further rule evaluation, preventing PACKET-scope rules from firing
  - **The Fix**: All three tiers (IPONLY, PKT, APPLAYER) now evaluate independently within their scope. A FLOW-scope PASS allows the flow to exist, but PACKET-scope rules still inspect individual packets and can reject them
  - **Scope Conflict Display**: When FLOW=PASS but PACKET=REJECT, the final action label shows "BLOCKED (REJECT) - PACKET scope overrides FLOW scope PASS" with a detailed scope analysis section in the results table
- **Partial Allow Detection**: Detects when the TCP handshake succeeds but the established connection is blocked
  - **The Scenario**: Port appears OPEN (handshake rules pass SYN/SYN-ACK/ACK) but actual connections FAIL (established-phase reject rule fires)
  - **How Users See This**: Tools like `Test-NetConnection` show port is open, but RDP/SSH/etc. connections fail — a confusing troubleshooting scenario
  - **Display**: Final action label shows "BLOCKED (REJECT) - Port appears OPEN but connections will FAIL" — directly addressing the user's confusion

### Bug Fix: Missing FLOW-Scope Rules in Matched Results
- **Fixed Missing SIDs**: Corrected indentation bug where FLOW-scope rules (IPONLY pass/alert) were not appearing in the matched rules table during handshake phase
  - **Root Cause**: The `else: # scope == 'FLOW'` branch was at incorrect indentation level, causing it to be unreachable when PACKET-scope rules were also present
  - **Impact**: SIDs like 100057 (IPONLY pass) and 202501022 (PKT pass to_client) were missing from results
  - **Solution**: Fixed indentation so both PACKET and FLOW scope branches are correctly nested within the action processing logic

---

## Rules Analysis Engine Enhancement (v1.11.0) - February 16, 2026

### New Check: Reject Action on QUIC Protocol (AWS Network Firewall Restriction)
- **QUIC Protocol Reject Detection**: New critical validation check identifies rules that use REJECT action with QUIC protocol, which is not supported by AWS Network Firewall
  - **AWS Restriction**: AWS Network Firewall does not allow the `reject` action on `quic` protocol rules; such rules must use `drop`, `pass`, or `alert` instead
  - **Automatic Detection**: Analyzer scans all rules and flags QUIC protocol + reject action combinations as CRITICAL issues
  - **Report Integration**: New dedicated section "🚨 REJECT ON QUIC PROTOCOL - CRITICAL" in both text and HTML analysis reports
  - **Clear Guidance**: Each detected issue includes specific line number, full rule text, and actionable suggestion to change action from `reject` to `drop`
  - **Pre-Deployment Safety**: Catches this configuration error before attempting to deploy to AWS Network Firewall
  - **Consistent Pattern**: Follows same detection pattern as existing reject-on-IP-protocol check

---

## Version 1.31.2 - February 16, 2026

### Bug Fix: macOS Multi-Monitor Window Disappearing
- **Fixed popup windows disappearing when dragged to another monitor on macOS**: All popup/dialog windows (flow tester, analysis results, configuration dialogs, etc.) would vanish when dragged from the primary monitor to a secondary monitor on macOS
  - **Root Cause**: tkinter's `Toplevel.transient()` on macOS (Cocoa-based Tk) constrains child windows to the parent window's screen/display space. When a transient window is moved to a different monitor, macOS hides it because it's outside the parent's display bounds. This behavior does not occur on Windows or Linux
  - **Solution**: Added a global monkey-patch at application startup that makes `transient()` a no-op on macOS (`platform.system() == 'Darwin'`). This fixes all 79 popup windows across 8 source files without modifying any individual dialog code
  - **Scope**: Affects `ui_manager.py`, `suricata_generator.py`, `traffic_analyzer_ui.py`, `stateful_rule_importer.py`, `search_manager.py`, `file_manager.py`, `domain_list_importer.py`, and `domain_importer.py`
  - **Windows/Linux Impact**: None — the fix only activates on macOS. `grab_set()` continues to provide modal behavior on all platforms

---

## Version 1.31.1 - February 16, 2026

### Bug Fix: macOS AWS Rule Group Import Crash
- **Fixed TclError Crash on macOS When Importing from AWS**: Resolved two bugs in the "Import from AWS" rule group browser that caused crashes on macOS
  - **Bug Fix 1 - wait_window on Destroyed Dialog**: Fixed `TclError: bad window path name` crash when AWS errors (credentials, permissions, timeout) caused the browse dialog to be destroyed before `wait_window()` was called
    - **Root Cause**: `load_rule_groups()` called `dialog.destroy()` on error paths, then `browse_and_select()` called `dialog.wait_window()` on the already-destroyed dialog. macOS Cocoa-based Tk strictly validates window references, raising an error, while Windows Win32-based Tk silently tolerates it
    - **Solution**: Added `dialog.winfo_exists()` guard before calling `wait_window()`
  - **Bug Fix 2 - Empty Region Destroys Browse Dialog**: Fixed the browse dialog being destroyed when no rule groups exist in the selected region, preventing users from switching to a different region
    - **Root Cause**: When `_fetch_rule_groups()` returned an empty list, `load_rule_groups()` showed a `messagebox.showinfo()` and called `dialog.destroy()`, closing the entire browse dialog
    - **Impact**: Users with rule groups in other regions (e.g., us-east-1) but none in their default region (e.g., us-west-2) could not switch regions to find their rule groups
    - **Solution**: Replaced `dialog.destroy()` with an inline status message: "No rule groups found in this region. Try selecting a different region." — the browse dialog stays open for region switching
  - **macOS vs Windows**: Bug 1 was macOS-only (Windows Tk silently ignores `wait_window` on destroyed dialogs). Bug 2 affected both platforms — the dialog would close on both, but only macOS raised a `TclError` for the subsequent `wait_window` call

## Version 1.31.0 - February 15, 2026

### New Feature: Category-Based Domain Analysis (Rule Usage Analyzer - Tab 9)
- **Category Domain Visibility**: New "Categories" tab in the Rule Usage Analysis results window shows which specific domains were seen in CloudWatch alert logs for each URL/domain category
  - **Compliance Reporting**: Answer questions like "Show me all Command & Control domains we detected" or "Which Malware domains did we detect this month?"
  - **Threat Intelligence**: Understand attack patterns by category with per-domain hit counts and rule associations
  - **Policy Validation**: Verify that category-based rules are catching expected traffic with direct vs indirect domain distinction
  - **Domain Discovery**: See exactly which domains triggered each category rule, with sortable columns for Domain, Hits, % of Category, Rule SID, and Action
- **Smart Category Dropdown**: Hybrid population from both rule definitions and CloudWatch data
  - Rule-defined categories always appear (even with 0 hits) — shows how many rules target each category
  - Discovered categories from CloudWatch added automatically when domains belong to multiple categories
  - Format: `Category Name (N rules, M hits)` with accurate direct hit counts
- **Direct vs Indirect Domain Display**: Visual distinction between domains matched by rules targeting the selected category vs domains that appear only because AWS classifies them in that category
  - **Direct domains** (normal text): A rule targeting this category fired and matched the domain — real hits, SIDs, and actions shown
  - **Indirect domains** (greyed out, n/a): Domain belongs to this category per AWS's database, but a different category's rule fired first due to strict rule ordering
- **Separate CloudWatch Query**: Runs an independent query (`isPresent(event.aws_category)`) that does not affect existing analysis tabs — if the category query fails, the other 8 tabs are unaffected
- **Truncation Warning**: Displays a warning banner if the category query returned the maximum 10,000 records, advising users to analyze a shorter time range
- **Export Category Report**: Export all categories with domain tables, hit counts, SIDs, and direct/indirect indicators to a plain text report file
- **Help Button**: In-tab help explaining how category data is aggregated, direct vs indirect domains, dropdown labels, and strict rule ordering effects
- **Persistent Cache**: Category analysis data saved and loaded with .stats companion files for instant access on subsequent opens without re-querying CloudWatch
- **Empty State Guidance**: When no category data exists, the tab displays clear instructions on how to create category rules and enable the feature

## Version 1.30.6 - February 14, 2026

### Rules Analysis Engine Bug Fix (v1.10.5) - Protocol Layering False Positive Reduction
- **Fixed Excessive Protocol Layering Conflict Detection**: Corrected two bugs causing hundreds of false positive protocol layering conflicts, particularly with east-west traffic rules using specific IPs and ports
  - **Bug Fix 1 - Flow Keyword Detection with Whitespace**: Fixed `has_flow_keywords()` failing to detect flow keywords when a space follows the colon (e.g., `flow: to_server` vs `flow:to_server`)
    - **Root Cause**: Method used simple string matching (`'flow:to_server' in content`) which didn't match `flow: to_server` (with space after colon) — a valid and common Suricata syntax
    - **Impact**: PKT rules with flow keywords like `flow: to_server` were not recognized as having flow keywords, causing them to be flagged as protocol layering conflicts when they should have been filtered out
    - **Solution**: Changed from string-based matching to regex-based matching with `re.search(r'flow:\s*(established|to_server|to_client|not_established|stateless)', ...)` to handle optional whitespace
    - **Example**: `pass tcp $HOME_NET any -> 10.0.1.48 $AD (flow: to_server; ...)` was incorrectly flagged as conflicting with HTTP app-layer rules
  - **Bug Fix 2 - Scope-Aware "Significantly Broader" Check for Flow-Only Rules**: Fixed `is_significantly_broader()` incorrectly classifying narrow-scope flow-only rules as "significantly broader"
    - **Root Cause**: When a rule had only flow keywords (no content matching), it was always considered "significantly broader" regardless of its network/port scope
    - **Impact**: Rules targeting specific IPs and specific ports (e.g., AD traffic on `10.0.1.48:$AD`) were incorrectly flagged as broader than rules targeting `any any` destinations, generating false protocol layering conflicts
    - **Solution**: Added network/port scope comparison — a flow-only rule is NOT considered "significantly broader" if it has narrower scope (specific dst_net while the other has `any`, or specific dst_port while the other has `any`)
    - **Example**: `pass tcp $HOME_NET any -> 10.0.1.48 $AD (flow: to_server; ...)` is clearly narrower than `reject http $HOME_NET any -> any any (http.host; pcre; ...)` and should not be flagged
- **Real-World Impact**: On the tgw-attached-fw.suricata test file, these fixes eliminate the majority of false positive protocol layering conflicts (previously 276 findings) involving east-west AD traffic rules vs HTTP/TLS application-layer rules
- **No Legitimate Findings Lost**: Both fixes only suppress false positives — rules that genuinely lack flow keywords or are genuinely broader continue to be flagged

## Version 1.30.6 - February 13, 2026

### Rules Analysis Engine Bug Fix (v1.10.4) - IPONLY Rule Conflict Detection
- **Fixed Missing IPONLY Protocol Layering Conflicts**: Corrected critical bug where pure IPONLY rules (no keywords) were not being detected as conflicting with more specific APPLAYER rules
  - **Root Cause**: Overly restrictive filtering logic prevented detection of broad IPONLY rules that shadow specific TLS/HTTP rules with domain matching
  - **Impact**: Rules like `drop ip any any -> any any` (pure IPONLY, no keywords) were not flagged as shadowing specific `pass tls ... (tls.sni; content:".example.com")` rules, creating security policy violations
  - **Three-Part Solution**:
    1. **Extended Conflict Types**: Added detection for DROP/REJECT vs ALERT and DROP/REJECT vs DROP/REJECT conflicts
    2. **IPONLY vs PKT Distinction**: Only flags pure IPONLY rules (no keywords) or PKT rules without flow keywords - does not flag PKT rules with flow keywords (they work correctly with app-layer rules)
    3. **AWS Category Filtering**: Added detection for AWS category keywords (`aws_url_category`, `aws_domain_category`) to prevent false positives when comparing category-based rules vs domain-specific rules
  - **False Positive Elimination**: Enhanced `has_only_flow_keywords()` to recognize AWS category keywords as content matching, preventing early exit before proper validation
- **Best Practices Compatibility**: Changes maintain zero false positives on AWS best practices template file (only 1 legitimate conflict detected)

### Flow Tester Bug Fix (v1.1.1) - IPONLY Rule Matching
- **Fixed Missing IPONLY Rules in Flow Tests**: Corrected bug where IPONLY rules were not appearing in matched rules during flow testing
  - **Root Cause**: FLOW-scope rules (IPONLY and APPLAYER types) were only being added to matched_rules at the end of processing, but since they stop all further processing, the storage code may not execute properly
  - **Impact**: Pure IPONLY rules like `drop ip any any -> any any` did not appear in flow test results even though they would match and block the traffic
  - **Solution**: Modified `_test_flow_phase()` to immediately add FLOW-scope rules to matched_rules when they match, before setting the flag that stops all tier processing
  - **Enhanced PKT Matching**: Updated `_flow_state_matches()` to allow PKT rules with `flow:to_server` to match during handshake phase (TCP SYN is to_server)

### User Impact
- **Accurate Conflict Detection**: Rule analyzer now correctly identifies when broad IPONLY rules shadow specific application-layer rules
- **Complete Flow Test Results**: Flow tester now shows all matching rules including critical IPONLY rules that would block traffic
- **Production Safety**: Prevents deploying rule sets where broad drop rules unintentionally block specific allow rules

## Version 1.30.6 - February 13, 2026 (continued)

### Bug Fix: SID Extraction from Message Text
- **Fixed SID Renumbering During Paste Operations**: Corrected critical bug where SIDs were incorrectly extracted from message text instead of the actual SID field, causing false duplicate detection and unnecessary renumbering
  - **Root Cause**: The SID extraction regex `sid:(\d+)` in `suricata_rule.py` matched the FIRST occurrence of `sid:` in the options string, which could be inside message text rather than the actual SID field
  - **Impact**: Rules with message text referencing other SIDs (e.g., `msg:"Pass rules don't alert, alert is on sid:100044"`) were incorrectly parsed, causing false duplicate detection and renumbering during paste operations
  - **Solution**: Changed SID extraction to use the LAST occurrence of `sid:\d+` pattern, which is always the actual SID field (never in message text)
  - **Technical Fix**: Modified `from_string()` method in `suricata_rule.py` to use `re.finditer()` and select the last match instead of first match
  - **Additional Enhancement**: Improved `assign_safe_sids()` in `suricata_generator.py` to build complete SID inventory from paste batch before renumbering, preventing renumbered SIDs from conflicting with later rules
- **User Impact**: Paste operations now preserve original SIDs for all unique rules, only renumbering actual duplicates. Rules with message text containing SID references no longer trigger false duplicate detection.

---

## Version 1.30.5 - February 12, 2026

### Bug Fix: Domain Importer Error Handling
- **Fixed UnboundLocalError in Domain Rule Insertion**: Corrected critical bug preventing domain rule insertion via "Insert Domain Allow Rule" button
  - **Root Cause**: Redundant `import os` statements inside conditional blocks in two functions created variable scoping conflicts where Python treated `os` as a local variable
  - **Impact**: When clicking "Insert Domain Allow Rule" button, users received `UnboundLocalError: cannot access local variable 'os' where it is not associated with a value` error
  - **Solution**: Removed redundant local `import os` statements from `on_insert()` and `on_import()` functions, relying on module-level import
  - **Affected Methods**:
    - `insert_domain_rule()` in domain_importer.py (line ~1312)
    - `show_bulk_import_dialog()` in domain_importer.py (line ~627)
  - **Technical Fix**: Module-level `import os` (line 6) is sufficient for all uses throughout the file

### Enhancement: Domain Rule Keyword Removal
- **Removed "nocase" Keyword from Domain Rules**: Eliminated nocase keyword from all domain rule generation to improve rule clarity
  - **Impact**: All 16 instances of `; nocase` keyword removed from generated domain rules
  - **Affected Rules**: Pass rules with alert keyword, alert/pass rule pairs, and drop/reject/alert rules for both TLS and HTTP protocols
  - **User Request**: Change implemented per user feedback to remove unnecessary keyword from domain matching rules

---

## Version 1.30.4 - February 12, 2026

### Bug Fix: Traffic Analysis Hostname Aggregation and Drill-Down
- **Fixed Split Destination Display in Internet Traffic Tab**: Corrected bug where flows to the same destination IP were displayed as separate entries when some flows had hostname data and others didn't
  - **Root Cause**: The `aggregate_by_hostname()` method aggregated each flow independently - flows with hostnames grouped by hostname, flows without hostnames grouped by IP:port - even when both went to the same destination IP
  - **Impact**: Traffic to a destination appeared split across multiple table rows (e.g., "arkansasrazorbacks.com" and "130.211.43.98:443") even though all traffic went to 130.211.43.98
  - **Real-World Example**: 
    - Flow 0123456789012345: dest_ip 130.211.43.98, hostname "arkansasrazorbacks.com" (from alert log)
    - Flow 0123456789012346: dest_ip 130.211.43.98, hostname "(No hostname)" (no alert match)
    - **Before Fix**: Appeared as two separate destinations in Internet Traffic tab
    - **After Fix**: Both flows now aggregate under "arkansasrazorbacks.com"
  - **Two-Part Solution**:
    1. **Aggregation Fix** (`traffic_analyzer.py`): Build IP-to-hostname lookup table before aggregation, allowing flows without hostnames to inherit known hostnames from other flows to the same dest_ip
    2. **Drill-Down Fix** (`traffic_analyzer_ui.py`): When drilling down on a hostname, include ALL flows to associated dest_ips (both flows with hostname and flows with "(No hostname)")
  - **Multi-IP Support**: If multiple IPs have flows with the same hostname, all are correctly grouped (requires at least one flow per IP to have hostname data for correlation)

### Technical Implementation
- **traffic_analyzer.py**: Enhanced `aggregate_by_hostname()` with IP-to-hostname lookup table built from all flows before aggregation begins
- **traffic_analyzer_ui.py**: Modified `_show_drilldown_tab1()` to find all dest_ips for clicked hostname and include flows with "(No hostname)" matching those IPs
- **No Breaking Changes**: Flows maintain original hostname values in underlying data; only aggregation and drill-down display logic changed

### User Impact
- **Unified Destination View**: All traffic to a destination now appears under single hostname entry (when hostname data available from any flow)
- **Complete Flow Visibility**: Drill-down shows ALL flows to destination including those without individual hostname data
- **Better Traffic Analysis**: More accurate representation of where traffic is actually going
- **Improved Reporting**: Export and statistics now correctly reflect consolidated traffic patterns

---

## Version 1.30.3 - February 11, 2026

### Bug Fix: MacOS Insert Category Dialog - Python 3.13 Compatibility and Layout
- **Fixed Two MacOS-Specific Issues**: Resolved tkinter compatibility error and persistent button visibility problem in Insert Category dialog
  - **Issue 1 - Python 3.13 trace() Syntax Error**: 
    - **Root Cause**: Used deprecated `.trace('w', callback)` syntax causing `TclError: bad option "variable"` on Python 3.13
    - **Impact**: MacOS users on Python 3.13 encountered immediate error when clicking "Insert Category" button
    - **Solution**: Updated to modern `.trace_add('write', callback)` syntax in `show_category_picker_dialog()` method
    - **Technical Fix**: Changed `search_var.trace('w', filter_categories)` to `search_var.trace_add('write', filter_categories)` (line 14448)
  - **Issue 2 - Buttons Still Not Visible**:
    - **Root Cause**: While v1.30.2 fixed the listbox container, the parent `select_frame` was still set to `expand=True`, causing it to consume all available space
    - **Impact**: Even after v1.30.2 fix, MacOS users still couldn't see Preview section and Insert/Cancel buttons when resizing
    - **Solution**: Changed `select_frame` from `fill=tk.BOTH, expand=True` to `fill=tk.X, expand=False`
    - **Technical Fix**: Modified `select_frame.pack()` parameters in `show_category_picker_dialog()` method (line 14521)
  - **Complete Fix**: Both `select_frame` and its child `list_frame` now use `expand=False` to maintain fixed sizes
- **Same Pattern as Template Dialogs**: Follows the proven fix pattern from v1.24.5 and v1.24.6 (use `expand=False` to prevent widget expansion)
- **Cross-Platform Compatibility**: Ensures consistent behavior across Python 3.7-3.13 on Windows, MacOS, and Linux

### User Impact
- **Python 3.13 Support**: MacOS users on latest Python can now use Insert Category feature without errors
- **Full UI Visibility**: Preview section and buttons now properly visible on MacOS at all window sizes
- **Professional Experience**: Insert Category dialog works reliably across all platforms and Python versions

---

## Version 1.30.2 - February 10, 2026

### Bug Fix: MacOS Insert Category Dialog Display
- **Fixed Missing Buttons on MacOS**: Resolved UI layout issue where Preview section and buttons were not visible in the Insert Category dialog on MacOS
  - **Root Cause**: Category listbox container was set to `expand=True`, causing it to consume all available vertical space when the dialog was resized on MacOS, pushing the Preview section and Insert/Cancel buttons below the visible area
  - **Impact**: Mac users could not see the Preview section or click Insert/Cancel buttons in the category picker dialog when using the "Insert Category" button in the main editor
  - **Solution**: Changed listbox container from `expand=True` to `expand=False` to maintain fixed size
  - **Technical Fix**: Modified `show_category_picker_dialog()` method in `ui_manager.py` line 14527
  - **Consistency**: Same fix pattern as version 1.24.5 (MacOS template dialog) - using `expand=False` prevents widget expansion on window resize
- **User Impact**: MacOS users can now fully use the Insert Category feature with all UI elements visible and accessible

---

## Version 1.30.1 - February 10, 2026

### Bug Fix: Python 3.7-3.11 Compatibility
- **Fixed f-string Backslash Syntax Error**: Corrected Python version compatibility issue causing SyntaxError on Python versions earlier than 3.12
  - **Root Cause**: Line 120 in `domain_importer.py` used backslash inside f-string expression (`filename.split('/')[-1].split('\\')[-1]`), which is only supported in Python 3.12+
  - **Impact**: Users running Python 3.7-3.11 encountered `SyntaxError: f-string expression part cannot include a backslash` when importing the domain_importer module
  - **Solution**: Replaced inline backslash operation with `os.path.basename(filename)` call outside the f-string
  - **Before Fix**: `source_description = f"Text File ({filename.split('/')[-1].split('\\')[-1]})"`
  - **After Fix**: `basename = os.path.basename(filename)` followed by `source_description = f"Text File ({basename})"`
  - **Benefits**: More readable, cross-platform compatible (handles both `/` and `\` automatically), uses standard library function
- **Confirmed Compatibility**: Program now runs successfully on Python 3.7 through 3.12+
- **No Feature Changes**: This is a pure compatibility fix with no changes to functionality

### Technical Implementation
- Modified `domain_importer.py` line 120 to extract basename outside f-string expression
- Leverages existing `os` module import (no new dependencies)
- Cross-platform solution handles Windows and Unix path separators automatically

### User Impact
- **Broader Python Support**: Users running Python 3.7-3.11 can now use the program without syntax errors
- **MacOS Compatibility**: Resolves reported issues from MacOS users running Python versions earlier than 3.12
- **No Breaking Changes**: Users on Python 3.12+ experience no changes in functionality

---

## Version 1.30.0 - February 5, 2026

### Flow Tester Major Enhancement (v1.1.0) - Strict Order Mode with SIG Type Precedence
- **Accurate AWS Network Firewall Flow Simulation**: Complete rewrite of flow testing engine to properly simulate AWS Network Firewall strict order mode processing with SIG type precedence
  - **SIG Type Precedence Implementation**: Flow tester now processes rules by Suricata SIG type tier, then by line order within each tier
    - **Tier 1**: SIG_TYPE_IPONLY rules (in line order) - Basic IP/protocol rules without keywords
    - **Tier 2**: SIG_TYPE_PKT rules (in line order) - Rules with flow keywords
    - **Tier 3**: SIG_TYPE_APPLAYER rules (in line order) - Rules with application-layer keywords
    - **Processing Logic**: Each tier evaluated independently, all tiers contribute to final action determination
  - **Strict Order Mode Compliance**: Once an action rule (PASS/DROP/REJECT) matches in any tier, no further rules are evaluated in that tier
    - **Critical Change**: Alert rules after action rules are NOT evaluated (matches AWS NFW behavior)
    - **Before Fix**: Alert rules continued processing after PASS rules (incorrect)
    - **After Fix**: Processing stops at first action rule match per tier (correct)
  - **Duplicate Rule Prevention**: Enhanced deduplication logic prevents same rule from appearing multiple times in matched rules list
    - Fixes edge case where category-based rules could be listed twice
    - Ensures clean, accurate results display
  - **Enhanced User Guidance**: Added explanatory text to dialog: "Rules with categories are excluded from the test and shown in Orange in the results"
  - **Increased Window Height**: Dialog increased from 900px to 920px to accommodate additional explanatory text
  - **Category Rule Display**: Rules with aws_domain_category/aws_url_category properly shown in orange with "UNKNOWN" status indicator

### Technical Implementation
- **Major Refactoring**: Complete rewrite of `_test_flow_phase()` method in flow_tester.py
  - Changed from flat line-order processing to hierarchical tier-based processing
  - Implemented per-tier action tracking with `tier_action_taken` flag
  - Each tier stops independently but all tiers are evaluated
- **Deduplication Logic**: Added line number tracking and duplicate prevention in ui_manager.py
- **Dialog Enhancement**: Added category rules explanatory label and increased window height

### User Impact
- **Accurate Flow Predictions**: Flow tester now correctly simulates how AWS Network Firewall will actually process your rules
- **Proper Rule Ordering**: Respects both SIG type precedence and strict order mode for accurate results
- **Eliminates False Results**: No more incorrect matches where alert rules appear after action rules should have stopped processing
- **Category Rule Visibility**: Category-based rules clearly indicated as requiring AWS database lookup
- **Professional Quality**: Flow tester behavior now matches actual AWS Network Firewall processing precisely

### Breaking Change Note
- **Alert Rule Behavior Change**: Alert rules appearing after action rules in the same tier will NO LONGER appear in results
  - This is the CORRECT behavior for AWS Network Firewall strict order mode
  - Previous versions incorrectly continued processing alert rules after action rules
  - Update your test expectations accordingly

## Version 1.30.0 - February 5, 2026

### Flow Tester Enhancement (v1.0.5) - AWS Category Keyword Support
- **Enhanced Flow Testing for Category-Based Rules**: Updated flow tester to properly handle rules with AWS category keywords without falsely blocking all traffic
  - **Category Keyword Detection**: Flow tester now detects `aws_url_category` and `aws_domain_category` keywords and marks these rules as "unknown" rather than attempting to evaluate them
  - **Problem Solved**: Previously, category rules would match all traffic of the protocol type, incorrectly showing flows as BLOCKED when they should depend on AWS category database lookup
  - **Real-World Example**: 
    - Rule: `drop tls $HOME_NET any -> any any (msg:"Block Education"; aws_domain_category:Education; sid:100;)`
    - URL tested: "www.google.com"
    - **Before Fix**: Flow tester showed traffic as BLOCKED (false positive - google.com is not in Education category)
    - **After Fix**: Flow tester marks rule as UNKNOWN and shows in flow diagram with special indicator
  - **Unknown Rule Tracking**: New `unknown_rules` array in test results tracks rules that require external database lookups
    - Category-based rules (aws_url_category, aws_domain_category)
    - Geolocation rules (geoip - already skipped, now consistent handling)
    - Rules with flowbits:isnotset (stateful dependencies)
  - **Flow Diagram Display**: Unknown rules will be displayed in the flow diagram with:
    - Special color indicator (different from matched/alert rules)
    - "UNKNOWN" status label indicating evaluation requires external data
    - Line number and rule details for reference
  - **Conservative Evaluation**: Flow tester skips category rules when determining final action, allowing subsequent rules to be evaluated
  - **No False Blocks**: Category rules no longer incorrectly block all traffic - they're acknowledged as "cannot evaluate" instead
- **Technical Implementation**: Modified `_rule_matches_flow()` to return tuple `(matches, status)` where status is 'match', 'no_match', or 'unknown'
- **User Impact**: Flow tester now provides accurate results for rulesets with category keywords, eliminating false positives where all traffic appeared blocked by broad category rules

### Rules Analysis Engine Enhancement (v1.10.3) - AWS Category Keyword Validation
- **Added Protocol Validation for AWS Category Keywords**: Enhanced rule analyzer to validate protocol compatibility with new AWS category filtering keywords
  - **New Keywords Supported**: `aws_url_category` and `aws_domain_category` (introduced in main program v1.30.0)
  - **Protocol Requirements Enforced**:
    - `aws_url_category`: Only supports HTTP protocol
    - `aws_domain_category`: Supports TLS or HTTP protocols
  - **Automatic Detection**: Analyzer now scans rules for category keywords and validates protocol compatibility
  - **Warning Severity**: Protocol mismatches flagged as WARNING in protocol/keyword mismatch section
  - **Real-World Examples**:
    - `drop tcp ... (aws_url_category:Malware)` → WARNING: aws_url_category only supports HTTP protocol
    - `drop udp ... (aws_domain_category:Phishing)` → WARNING: aws_domain_category only supports TLS or HTTP protocols
  - **Clear Guidance**: Error messages specify current protocol, required protocol(s), and remediation steps
  - **Integrated Reporting**: Category keyword violations appear in existing "⚠️ PROTOCOL/KEYWORD MISMATCH" section alongside other protocol validation issues
- **Consistent with Save Validation**: Analyzer checks match the save-time validation already implemented in main program (ensures users can't save invalid category/protocol combinations)
- **User Impact**: Proactive detection of category keyword misuse during rule analysis, preventing deployment failures and improving rule quality

### Rules Analysis Engine Bug Fix (v1.10.2) - Variable Resolution
- **Fixed AttributeError in Variable Resolution**: Corrected critical bug causing rule analyzer to crash when analyzing rules with network variables
  - **Root Cause**: The `_parse_network_specification()` method attempted to call `.strip()` on a dictionary object when resolving variables from .var files
  - **Impact**: Rule analyzer would crash with `AttributeError: 'dict' object has no attribute 'strip'` when analyzing files using variables stored in .var file format
  - **Solution**: Enhanced variable resolution to detect dictionary format and extract the 'definition' key containing the actual network specification
  - **Technical Fix**: Added type checking in `_parse_network_specification()` method (lines 327-333) to handle both string and dictionary variable formats
  - **Backward Compatible**: Works with both legacy string format and enhanced dictionary format (.var files with descriptions)
- **User Impact**: Rule analyzer now successfully completes analysis without crashes when processing rules with network variables and descriptions

---

## Version 1.30.0 - February 4, 2026

### Major New Feature: AWS Network Firewall URL and Domain Category Filtering
- **AWS Category-Based Traffic Filtering**: New comprehensive category filtering feature enables blocking or allowing traffic based on AWS-maintained content categories without manual domain list maintenance
  - **51 Predefined Categories**: Leverage AWS's automatically-updated category database spanning security threats, productivity, lifestyle, business, financial, and restricted content
    - **Security Threats** (10 categories): Malware, Phishing, Command and Control, Hacking, Malicious, Spam, and more
    - **Restricted Content** (8 categories): Adult and Mature Content, Child Abuse, Gambling, Violence and Hate Speech, and more
    - **Productivity** (9 categories): Social Networking, Entertainment, Online Ads, Shopping, Email, and more
    - **Lifestyle** (14 categories): Health, Travel, Pets, Food and Dining, Fashion, Sports and Recreation, and more
    - **Business/Professional** (8 categories): AI and Machine Learning, Education, Government and Legal, Military, and more
    - **Financial** (2 categories): Cryptocurrency, Financial Services
  - **Two AWS Keywords**: Support for both URL-level and domain-level category filtering
    - **aws_url_category**: Evaluates complete URLs and domains (HTTP protocol only, requires TLS inspection for HTTPS effectiveness)
    - **aws_domain_category**: Evaluates domain-level information from TLS SNI or HTTP host headers (works without TLS inspection)
  - **Three Access Methods**: Multiple ways to work with categories for different skill levels and use cases
    - **1. Rule Templates** (Primary): File → Insert Rules From Template → Block URL Categories or Block Domain Categories
      - Two-panel selection UI with category grouping
      - Select multiple categories at once from organized groups
      - Generates 1 rule with comma-separated categories
      - Includes test mode support
    - **2. Insert Category Button** (Secondary): Quick insertion from main program editor
      - Available when protocol is HTTP or TLS
      - HTTP protocol: Choose between URL or Domain category via radio buttons
      - TLS protocol: Automatically uses Domain category
      - Multi-select support (Ctrl+click for multiple categories)
      - Auto-populates message field with descriptive text
    - **3. Advanced Editor** (Tertiary): Autocomplete support for power users
      - Type-to-search through all 51 categories
      - Real-time syntax validation
      - Protocol mismatch detection with red squiggles
  - **Multi-Select Support**: Select multiple categories to generate efficient comma-separated syntax
    - Single rule handles multiple categories: `aws_domain_category:Malware,Phishing,Command and Control`
    - Smart message generation: "Block Malware" or "Block Malware, Phishing, and 1 more"
  - **Protocol Validation**: Comprehensive validation prevents invalid category/protocol combinations
    - Save validation in main editor prevents accidentally saving invalid rules
    - Advanced editor shows real-time red squiggles for protocol mismatches
    - Clear error messages with remediation steps
  - **Automatic Updates**: Categories maintained by AWS - no manual updates needed as threat landscape evolves

### Business Value
- **Simplified Security Management**: Block entire threat categories without maintaining domain lists manually
- **Automatic Updates**: AWS updates category database automatically as new threats emerge
- **Flexible Control**: Choose between URL-level (path inspection) or domain-level (SNI inspection) filtering
- **Productivity Controls**: Block time-wasting categories (social media, entertainment, shopping) to improve focus
- **Compliance Support**: Block restricted content categories for legal and HR compliance

### User Impact
- **Faster Rule Creation**: Generate category-based rules in seconds instead of manually researching and entering domains
- **Better Coverage**: AWS's constantly-updated database provides broader threat protection than manual lists
- **Multiple Workflows**: Choose template for bulk operations, editor button for quick additions, or advanced editor for power users
- **Clear Organization**: 6 category groups make finding the right categories intuitive
- **Smart Defaults**: Message auto-population and protocol detection reduce manual typing

---

## Version 1.29.0 - February 1, 2026

### Major New Feature: Analyze Traffic Costs
- **AWS Network Firewall Cost Analysis and VPC Endpoint Recommendations**: New comprehensive traffic analysis feature helps identify where firewall costs are coming from and provides intelligent VPC endpoint recommendations for cost savings
  - **Three-Tab Cost Analysis Dashboard**: 
    - **Internet Traffic**: Analyze non-AWS traffic patterns with hostname/SNI visibility, cost breakdowns, and source IP drill-down
    - **AWS Service Traffic**: Smart VPC endpoint recommendations with break-even analysis, regional pricing, and monthly savings projections
    - **Internal Traffic**: VPC-to-VPC communication costs with source IP breakdowns
  - **Intelligent VPC Endpoint Recommendations**: Cost-benefit analysis determines when endpoints are worth deploying
    - **Gateway Endpoints**: Always recommended for S3/DynamoDB (FREE, eliminates firewall costs)
    - **Interface Endpoints**: Only recommended when traffic volume exceeds break-even threshold
    - **Regional Pricing**: Accurate cost calculations using region-specific firewall data processing rates
    - **Cross-Region Analysis**: Identifies cross-region traffic with alternative optimization suggestions
  - **CloudWatch Logs Integration**: Correlates FLOW logs (traffic volumes) with ALERT logs (hostnames/SNI)
    - Queries millions of log entries with efficient CloudWatch Logs Insights queries
    - Handles large datasets with automatic pagination (>10K flows)
    - Progress tracking with cancellation support
  - **Data Caching**: Save analysis results to avoid CloudWatch charges on repeat views
    - Results cached in .stats companion files
    - Instant loading of cached data with age indicators
    - Option to refresh for updated analysis
  - **Custom Date Ranges**: Flexible time period selection (7, 15, 30, 60, 90 days or custom range)
  - **Expandable Drill-Down**: Click any row to see source IP breakdown, expand to see individual flows with timestamps
  - **CSV Export**: Export analysis results for offline review and reporting
  - **Cost Transparency**: Shows estimated CloudWatch query costs before running analysis

### Business Value
- **Cost Optimization**: Identify opportunities to reduce AWS Network Firewall data processing costs through VPC endpoints
- **Traffic Visibility**: See exactly where bandwidth is going with hostname/domain resolution
- **Actionable Insights**: Smart recommendations only suggest endpoints when cost-effective
- **ROI Clarity**: Break-even analysis shows exact traffic thresholds where endpoints make financial sense

### User Impact
- **Reduce AWS Bills**: Potential savings of $50-200/month through strategic VPC endpoint deployment
- **Better Visibility**: Understand traffic patterns with HTTP/TLS hostname correlation
- **Smart Decisions**: Data-driven recommendations prevent wasteful endpoint deployments
- **Easy Setup**: Works with existing CloudWatch logs, no additional AWS configuration needed

---

## Version 1.28.3 - January 29, 2026

### Enhancement: Analyze Rule Usage - Auto-Query Log Groups
- **Automatic Log Group Discovery**: Enhanced "Analyze Rule Usage" feature with automatic CloudWatch log group discovery and selection
  - **Auto-Populated Dropdown**: Changed from manual text entry to dropdown menu that automatically queries CloudWatch for available log groups
    - Queries and displays up to 100 log groups in selected region
    - Alphabetically sorted for easy navigation
    - Real-time status indicators (✓ success, ⚠️ warnings/errors)
  - **Region-Aware Querying**: Log groups automatically refresh when AWS region is changed
    - Eliminates typos and incorrect log group names
    - Shows only log groups that actually exist in the selected region
  - **Enhanced Label**: Renamed "Log Group" to "Alert Log Group" for clarity
    - Clarifies this field is specifically for Alert logs (not Flow logs)
  - **Smart Error Handling**: Graceful handling of AWS credential issues, permission errors, and connection failures
    - Clear color-coded status messages guide users to solutions
    - Helps users quickly identify and resolve configuration issues
  - **Improved Dialog Layout**: Increased dialog height from 550x600 to 550x700
    - Ensures Analyze and Cancel buttons always visible
    - Accommodates new region selector and log group status indicators

### Technical Implementation
- **CloudWatch Integration**: Uses boto3 `describe_log_groups` API with pagination support
- **Session Preferences**: Selected log groups remembered during session for convenience
- **Loading States**: Visual feedback during log group query with status messages
- **Auto-Load on Open**: Log groups automatically load when dialog opens (200ms delay for smooth UX)

### User Impact
- **Easier Configuration**: No more manual typing of log group names
- **Reduced Errors**: Dropdown prevents typos and shows only existing log groups
- **Multi-Region Support**: Easy switching between regions with automatic log group refresh
- **Consistent Experience**: Matches the polished UX of other AWS integration features
- **Professional Quality**: Auto-discovery is expected in modern AWS tools

---

## Version 1.28.2 - January 27, 2026

### Bug Fix: Flow Tester Variable Resolution
- **Fixed AttributeError in Flow Tester**: Corrected critical bug causing AttributeError when testing flows with network variables
  - **Root Cause**: The `_ip_matches_network()` method in flow_tester.py assumed `self.variables.get()` would always return a string, but it could sometimes return a dict object
  - **Impact**: Users received "AttributeError: 'dict' object has no attribute 'strip'" when using the Test Flow feature with rules containing network variables
  - **Solution**: Added type checking after variable resolution to detect dict objects and handle them gracefully
    - If resolved value is a dict, the method returns True (conservative matching) to prevent crashes
    - Explicitly converts resolved values to strings before recursive calls
  - **Technical Fix**: Modified `_ip_matches_network()` method in flow_tester.py (line ~635)

### Technical Implementation
- Added `isinstance(resolved, dict)` check after variable resolution
- Returns True (allows match) when dict detected to prevent AttributeError
- Ensures all resolved values converted to string via `str(resolved)` before recursion

### User Impact
- **Working Test Flow Feature**: Flow testing now works correctly without crashes when rules contain network variables
- **Graceful Error Handling**: Dict resolution handled smoothly without breaking the test
- **Production Ready**: Flow tester behavior remains accurate while handling edge cases

---

## Version 1.28.1 - January 21, 2026

### Bug Fix: Change Tracking Header Display
- **Fixed Last Modified Timestamp Not Updating in UI**: Corrected issue where the "Last Modified" timestamp in the change tracking header was being updated in the file but not displayed in the rule window until the file was reopened
  - **Root Cause**: The timestamp was being correctly updated during file save operations, but the rule table was not refreshing to display the new value
  - **Impact**: Users couldn't see the updated "Last Modified" timestamp in the rule window after saving, making it appear as though the timestamp wasn't being updated (even though it was updated in the actual file)
  - **Solution**: Added `refresh_table(preserve_selection=True)` call after successful file save to update the UI display
  - **User Experience**: Last Modified timestamp now immediately visible in rule window after each save operation, providing instant feedback that the file was saved successfully

### Technical Implementation
- Modified `save_rules_to_file()` method in `suricata_generator.py` to refresh the table after successful save
- Preserved user's rule selection during refresh for seamless workflow continuation
- Table refresh updates all header comment lines including the Last Modified timestamp

### User Impact
- **Immediate Visual Feedback**: Users now see the updated timestamp in the rule window right after saving
- **Better Awareness**: Clear indication that change tracking is working properly
- **Eliminated Confusion**: No need to close and reopen files to see updated timestamps

---

## Version 1.28.0 - January 21, 2026

### New Feature: AWS Tags Support
- **Tag Management for Rule Groups**: New comprehensive tagging system for AWS Network Firewall rule groups enables better resource organization, cost allocation, and compliance tracking
  - **AWS Tags Tab**: New dedicated tab in Editor section for managing tags with intuitive key-value interface
    - Two-column table showing tag keys and values
    - Add, edit, and delete tags through user-friendly UI
    - Double-click to edit existing tags
    - Real-time AWS validation with compliant requirements (1-128 char keys, 0-256 char values)
  - **Export Integration**: Tags automatically applied during all export operations with zero additional steps
    - **Terraform Export**: Tags added to resource tags block
    - **CloudFormation Export**: Tags added to Tags array in template
    - **AWS Direct Deploy**: Tags included in API call to Network Firewall
  - **Import Integration**: Tags imported when loading rule groups from AWS
    - AWS-managed tags (aws: prefix) automatically filtered
    - User-defined tags loaded into AWS Tags tab for editing
  - **Persistent Storage**: Tags saved in companion .var file format alongside variables
    - Enhanced v2.0 .var format with separate "variables" and "tags" sections
    - Backward compatible with legacy v1.0 format (auto-migration on first save)
    - Tags persist across file open/save operations
  - **Default Tag**: New files and v1.0 upgrades automatically include "ManagedBy: SuricataGenerator" tag
    - Helps identify tool-managed resources in AWS console
    - User can edit or delete this tag if desired
  - **AWS Compliance**: Full validation against AWS tagging requirements
    - Key: 1-128 characters with valid characters only
    - Value: 0-256 characters (empty allowed)
    - Reserved prefix detection (aws:)
    - Duplicate key prevention
  - **Change Tracking**: All tag operations logged when change tracking enabled
    - Tag additions, modifications, and deletions tracked
    - Complete audit trail in Change History tab

### Business Value
- **Cost Allocation**: Track rule group costs by team/project using CostCenter and Project tags
- **Resource Organization**: Identify rule groups by environment using Environment tags
- **Compliance Support**: Document ownership and compliance requirements with Owner and Compliance tags
- **Automation Ready**: ManagedBy tag identifies tool-managed resources for automated policy enforcement

### User Impact
- **Better AWS Organization**: Tags enable filtering and searching in AWS Console
- **Zero Learning Curve**: Familiar table-based UI matches Variables tab pattern
- **Seamless Integration**: Tags automatically included in exports with no extra steps
- **Professional Experience**: Full AWS validation prevents deployment errors

---

## Version 1.27.8 - January 20, 2026

### Bug Fix: IP Set References Status Bar Tracking
- **Fixed IP Set References Counter Not Updating**: Corrected bug where the status bar's "IP Set References: X/5" counter did not update when new @variables were added to the Rule Variables tab
  - **Root Cause**: Counter was only counting @variables used in rules, not all @variables defined in the Variables tab
  - **Impact**: Users could add IP Set Reference variables (@ALLOW_LIST, @VPC_CIDR, etc.) but the status bar counter remained at 0/5, making it impossible to track progress toward AWS's 5 reference limit
  - **Solution**: Changed counter to count all @variables in `self.variables` dictionary (defined references) instead of only those in `used_vars` (references used in rules)
  - **AWS Compliance**: AWS Network Firewall's 5 reference limit applies to defined references in the rule group, not just those currently used in rules
  - **Technical Fix**: Modified `calculate_rule_statistics()` method in `suricata_generator.py` line 272-274

### User Impact
- **Accurate Tracking**: Status bar now correctly displays IP Set References count as variables are added/edited in the Variables tab
- **Real-Time Updates**: Counter updates immediately when @variables are added, deleted, or modified
- **AWS Quota Visibility**: Users can now properly monitor their progress toward the 5 reference limit

---

## Version 1.27.7 - January 18, 2026

### New Feature: AWS Domain List Import
- **Import Domain Lists Directly from AWS Network Firewall**: New capability to browse and import Domain List rule groups from your AWS account without requiring manual CLI exports
  - **Source Selection Dialog**: Enhanced "Import Domain List" menu item now presents import source options (text file or AWS Domain List)
  - **AWS Browser Integration**: Visual browser for Domain List rule groups with search, region selection, and expandable details
    - Filters to show only Domain List type rule groups (grays out 5-tuple/Suricata format groups)
    - Real-time search filtering by rule group name
    - Expandable rows show capacity, domain count, target types, action, description, and ARN
    - **Multi-Select Support**: Select multiple Domain List rule groups to combine in a single import
      - Use Ctrl+Click or Shift+Click to select multiple rule groups
      - Combined domains automatically deduplicated by consolidation algorithm
      - Mixed action detection (ALLOWLIST + DENYLIST) with default to first selected
      - Protocol union (HTTP_HOST + TLS_SNI combined from all selections)
      - Comprehensive metadata listing all source rule groups
  - **Protocol Selection**: Enhanced bulk import dialog with HTTP/TLS protocol checkboxes
    - Pre-checked based on AWS TargetTypes (HTTP_HOST → HTTP, TLS_SNI → TLS)
    - User can override selections (uncheck unwanted protocols)
    - Validation prevents importing with zero protocols selected
    - Rule count preview updates dynamically based on protocol selection
  - **AWS Configuration Mapping**: Automatic mapping from AWS Domain List format to Suricata rules
    - ALLOWLIST → pass action (default), DENYLIST → drop action (default)
    - HTTP_HOST → generates HTTP protocol rules with http.host matching
    - TLS_SNI → generates TLS protocol rules with tls.sni matching
    - Both targets → generates both HTTP and TLS rules (user can customize)
  - **Domain Normalization**: Strips leading dots from AWS wildcard format (`.example.com` → `example.com`) before consolidation algorithm
    - Critical for consolidation to work correctly (AWS uses `.domain` format, algorithm expects `domain` format)
    - Generated rules use `dotprefix; content:".domain"` to preserve wildcard matching behavior
  - **Metadata Preservation**: Automatically adds metadata comment header with:
    - Original rule group name and ARN
    - AWS action (ALLOWLIST/DENYLIST)
    - Target types (HTTP_HOST, TLS_SNI)
    - Evaluation order conversion (DNSORDER → STRICT_ORDER)
    - Domain normalization note
  - **Full Feature Integration**: Works seamlessly with all existing bulk import features
    - Domain consolidation algorithm (reduces rule count)
    - Alert on pass option (for logging)
    - Strict domain matching option
    - SID management
    - Change tracking
    - Undo support
  - **Graceful Degradation**: AWS import option automatically grayed out when boto3 not installed - text file import always available
  - **Consistent UI**: Browser layout matches existing "Import Stateful Rule Group" pattern for familiar user experience

### Technical Implementation
- **New Module**: `domain_list_importer.py` with DomainListImporter class
- **Enhanced Module**: Updated `domain_importer.py` to support AWS imports via optional parameters
  - Modified `show_bulk_import_dialog()` signature to accept pre-loaded domains, protocols, metadata
  - Enhanced `generate_domain_rules()` with protocol filtering parameter
- **Main Application**: Added `import_domain_list()` method to route between file and AWS imports
- **UI Integration**: Updated menu handler in `ui_manager.py` to call new routing method
- **Architecture**: Follows established pattern from stateful rule group importer (separate AWS module)

### User Impact
- **Streamlined Workflow**: Import Domain Lists in seconds instead of minutes with CLI commands
- **No AWS CLI Required**: Direct import through AWS SDK (boto3)
- **Protocol Flexibility**: Customize which protocols to generate (HTTP only, TLS only, or both)
- **Visual Discovery**: Browse and search Domain List rule groups with expandable details
- **Production Ready**: Complete metadata preservation and robust error handling
- **Zero Learning Curve**: Familiar interface matching existing AWS import features

---

## Version 1.27.6 - January 16, 2026

### Enhancement: Health Score Optimization
- **Improved Health Score Formula**: Optimized the rule group health score calculation to provide better incentives for rule quality and monitoring coverage
  - **Multi-Component Formula**: Balanced scoring system with base points, positive rewards, and targeted penalties
    - **Formula**: `Score = Base + Effectiveness + Usage - Broad Penalty - Visibility Penalty`
    - **Base Points**: 20 points for using Suricata formatted rules
    - **Effectiveness Component**: 0-50 points = `(Medium + High rules / Logged rules) × 50`
      - Rewards quality rules that trigger regularly (medium/high frequency)
      - Removes unused and low-frequency rules from numerator to focus on effective rules
    - **Usage Component**: 0-30 points = `(Rules with hits / Logged rules) × 30`
      - Rewards ANY rule usage (even if low frequency)
      - Separate from effectiveness to distinguish "rarely used" from "never used"
    - **Broad Rule Penalty**: 0-15 points = `min(15, broad_rule_count × 4)`
      - Penalizes rules handling >10% of total traffic (security risk)
      - Maximum -15 points (capped at ~4 broad rules)
    - **Visibility Penalty**: 0-15 points = Balanced hybrid approach
      - Formula: `min(15, (absolute_count × 1.0 + percentage × 0.5) / 2)`
      - Combines absolute count (1pt per unlogged rule) with percentage (0.5pt per %)
      - Penalizes monitoring blind spots from unlogged rules (pass without 'alert', drop/reject with 'noalert')
      - Maximum -15 points
      - Example: 10 unlogged rules at 20% = 10 points penalty
  - **Why It's Better**: Separates effectiveness (quality) from usage (any activity) for more nuanced scoring
    - Removing unused rules improves BOTH effectiveness (+50 pts potential) and usage (+30 pts potential)
    - Low-frequency rules improve usage score but not effectiveness score (encourages optimization)
    - Unlogged rules now explicitly penalized (were previously excluded from calculations)
  - **Grading Scale**: Intuitive score interpretation
    - 80-100: Excellent (outstanding rule group health)
    - 60-79: Good (solid rule group with minor optimization opportunities)
    - 40-59: Fair (acceptable but room for improvement)
    - 0-39: Poor (needs significant optimization work)
  - **UI Updates**: Enhanced Summary tab with comprehensive scoring breakdown
    - **Your Current Score Breakdown**: Shows all 5 components with actual point calculations
    - **Scoring Formula**: Complete mathematical formulas with explanations
    - **How to Improve Your Score**: Specific recommendations with projected point gains
    - **Category Labels Updated**: Added hits/day criteria for clarity (e.g., "High-Traffic Rules (≥10 hits/day)")
    - **Removed Outdated Text**: Eliminated misleading note about unlogged rules being "excluded from calculations" (they're now included via visibility penalty)

### Technical Implementation
- **rule_usage_analyzer.py**: Completely rewrote `_calculate_health_score()` with five-component formula
- **ui_manager.py**: Enhanced `_populate_scoring_explanation()` with detailed component breakdowns and recommendations
- **ui_manager.py**: Updated Quick Statistics labels with hits/day thresholds for user clarity
- **Backward Compatible**: New formula applies automatically to cached results without requiring re-analysis

### User Impact
- **Better Incentives**: Score always rewards removing unused/low-frequency rules and fixing broad rules
- **Clearer Categories**: Hits/day thresholds make tier classifications immediately understandable
- **Monitoring Best Practices**: Visibility penalty encourages enabling logging for all rules
- **Actionable Insights**: "How to Improve" section shows exactly which actions will increase score and by how many points
- **No Confusion**: Removed outdated text that incorrectly stated unlogged rules were excluded from calculations

---

## Version 1.27.5 - January 15, 2026

### Bug Fixes: Search/Replace and Comment Toggle
- **Fixed Search/Replace IndexError**: Corrected critical bug causing IndexError when performing find and replace operations
  - **Root Cause**: After a replacement, code attempted to delete from `search_results` list using an index that became out of range after table refresh
  - **Impact**: Users received IndexError exception when clicking "Replace" button during search operations, preventing successful replacements
  - **Solution**: Removed problematic `del self.search_results[self.current_search_index]` line since search results are rebuilt after table refresh anyway
  - **Technical Fix**: Modified `replace_current()` method in `search_manager.py` to rely on search result rebuilding rather than manual list deletion
- **Fixed Comment Toggle and Uncomment Validation**: Enhanced spacebar toggle and find/replace to properly validate uncommenting operations
  - **Root Cause**: Toggle function only attempted to uncomment rules with directional indicators (-> or <>), and find/replace didn't validate syntax when removing comment markers
  - **Impact**: Users couldn't use spacebar to uncomment valid rules, and bulk find/replace to remove "#" markers would leave invalid rules as active (causing deployment failures)
  - **Solution**: Implemented comprehensive validation for all uncommenting operations
    - Added `_validate_parsed_rule()` method to validate action, protocol, and port fields
    - Enhanced `toggle_rule_disabled()` to always attempt parsing and validate before uncommenting
    - Enhanced `_replace_in_rule()` in search_manager to detect, parse, and validate when replacements remove comment markers
  - **Smart Error Handling**: Invalid rules remain commented with descriptive error markers
    - `# [VALIDATION ERROR: invalid action 'pasz'] pasz tcp any any -> any any (...)`
    - `# [PARSE ERROR] malformed rule text`
  - **Bulk Operation Support**: Handles thousands of lines gracefully with individual validation for each uncommented line
  - **User Feedback**: Shows detailed summary of successful toggles and failed validations with line numbers and specific errors

### Technical Implementation
- **search_manager.py**: Fixed `replace_current()` method index management
- **search_manager.py**: Enhanced `_replace_in_rule()` with uncomment detection and validation
- **suricata_generator.py**: Added `_validate_parsed_rule()` validation method
- **suricata_generator.py**: Enhanced `toggle_rule_disabled()` with comprehensive parsing and validation

### User Impact
- **Working Replace Function**: Find and replace operations complete successfully without errors
- **Reliable Comment Toggle**: Spacebar now properly uncomments valid rules while protecting against invalid syntax
- **Safe Bulk Operations**: Find/replace removing "#" markers across thousands of lines validates each line individually
- **Clear Error Reporting**: Users see exactly which lines failed validation and why
- **Production Safety**: Invalid rules prevented from becoming active, avoiding AWS deployment failures

---

## Version 1.27.4 - January 15, 2026

### Enhancement: CloudWatch Analysis Region Selector
- **AWS Region Selection for Rule Usage Analysis**: Added region selector to the "Configure Rule Usage Analysis" window for multi-region CloudWatch analysis
  - **Region Dropdown**: New region selector positioned at the top of the configuration dialog, above the CloudWatch Log Group section
  - **Common Regions**: Dropdown includes 11 commonly-used AWS regions (us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1, eu-central-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, ca-central-1, sa-east-1)
  - **Smart Defaults**: Automatically detects default region from boto3 session or uses last selected region from current session
  - **Session Memory**: Selected region remembered during session (same behavior as other analysis parameters)
  - **Consistent Design**: Region selector matches the implementation used in Import/Export Rule Group features
- **Multi-Region Support**: Users can now analyze CloudWatch Logs from different AWS regions without changing their default AWS credentials configuration
- **Dialog Sizing**: Increased window height from 540 to 600 pixels to accommodate the new region selector section while ensuring all buttons remain visible

### Technical Implementation
- **Region Parameter**: Added `region` parameter to `analyze_rules()` method in rule_usage_analyzer.py
- **CloudWatch Client**: CloudWatch Logs client now accepts region override: `boto3.client('logs', region_name=region)`
- **Data Flow**: Region selection passes through entire call chain: configuration dialog → run_usage_analysis() → analyze_rules()
- **Fallback Support**: Falls back to default credentials region if no region specified for backward compatibility

### User Impact
- **Multi-Region Flexibility**: Analyze rule usage across different AWS regions from a single application instance
- **Simplified Workflow**: No need to change AWS CLI configuration or environment variables to analyze different regions
- **Professional Quality**: Region selector matches AWS console patterns and user expectations

---

## Version 1.27.3 - January 14, 2026

### New Feature: Direct Rule Group Import from AWS
- **Import Rule Groups Directly from AWS Network Firewall**: New capability to browse and import rule groups from your AWS account without requiring manual CLI exports
  - **Unified Import Dialog**: Enhanced "Import Stateful Rule Group" menu item now presents import source options (JSON file or AWS direct)
  - **Browse AWS Rule Groups**: Visual browser with search, sorting, and expandable details for rule groups in your AWS account
    - Shows STATEFUL rule groups (STATELESS grayed out and non-selectable)
    - Expandable rows with on-demand details (capacity, rule count, last modified, description)
    - Real-time search filtering and sortable columns (Name, Type)
  - **Import Preview**: Comprehensive preview dialog shows rule group metadata, rules, and variables before importing
  - **Graceful Degradation**: AWS import option automatically disabled when boto3 not installed - JSON file import always available
  - **Streamlined Workflow**: Eliminates 4-step manual CLI process (export → navigate → select → import) with single menu selection
- **AWS Setup Guide Updates**: Enhanced Help > AWS Setup documentation to cover both CloudWatch analysis and rule group import
  - Updated IAM policy includes network-firewall:ListRuleGroups and network-firewall:DescribeRuleGroup permissions
  - Connection test now validates both CloudWatch Logs and Network Firewall access

### User Impact
- **Faster Workflow**: Browse and import rule groups in seconds instead of minutes with CLI commands
- **No AWS CLI Required**: Direct import works through AWS SDK (boto3) without requiring AWS CLI installation
- **Visual Discovery**: Search and browse rule groups with expandable details for informed selection
- **Production Ready**: Complete metadata preservation and robust error handling for enterprise use

---

## Version 1.27.2 - January 14, 2026

### New Feature: AWS Network Firewall Direct Deploy Export
- **Deploy Rule Groups Directly to AWS**: New AWS export option enables deploying rule groups directly to AWS Network Firewall without intermediate IaC
  - **File Menu Integration**: Added "AWS Network Firewall (Direct Deploy)" option to File > Export dialog
  - **Smart Name Sanitization**: Automatically converts filenames to AWS-compliant rule group names
  - **Real-Time Validation**: Name field validation with instant feedback (✓ valid or ✗ invalid with specific error)
  - **Deployment Summary**: Pre-deployment summary shows rules count, export mode (test or prod), capacity, and target region
  - **Overwrite Detection**: Detects existing rule groups and shows confirmation dialog before overwriting
  - **Format Conversion**: Automatic conversion from AWS standard 5-tuple format to Suricata format when overwriting (when applicable)
  - **Critical Warnings**: Bold red "CRITICAL:" warnings when rule group is attached to live firewalls
  - **Success Dialog**: Confirmation dialog with clickable hyperlink to AWS console for immediate verification
    - Rule group name is a blue underlined link that opens AWS console to the Rule Groups page
    - Region automatically detected from AWS credentials
    - Hover effect on link for enhanced UX
  - **Test Mode Support**: Works with existing test mode feature (converts all actions to 'alert')
  - **Change Tracking**: Export operations logged in change history when tracking enabled
- **AWS Setup Guide**: Updated Help > AWS Setup documentation to include export feature requirements
  - Added CreateRuleGroup and UpdateRuleGroup permissions to IAM policy
  - Updated permission breakdown and security notes sections
  - Enhanced connection testing to verify export permissions

### Technical Implementation
- **Modular Design**: New export path alongside existing Terraform and CloudFormation exports
- **boto3 Integration**: Uses AWS SDK for direct API calls to Network Firewall service
- **Comprehensive Error Handling**: Graceful handling of credentials, permissions, limits, and network issues
- **Variable Conversion**: Automatic conversion of $ and @ variables to AWS RuleVariables and ReferenceSets
- **Zero Breaking Changes**: All existing export functionality preserved

### User Impact
- **Streamlined Workflow**: Deploy to AWS with fewer steps (no intermediate .tf or .cft files needed)
- **Instant Verification**: Clickable link enables immediate confirmation in AWS console
- **Safer Overwrites**: Clear warnings prevent accidental modifications to live firewalls
- **Professional Experience**: Visual emphasis on important values and critical warnings

---

## Version 1.27.1 - January 12, 2026

### Enhancement: Rule Usage Analysis - Double-Click Navigation
- **Double-Click to Jump to Rule**: Added double-click navigation from analysis results tables back to the main program
  - **Seamless Navigation**: Double-click any rule in analysis tables to instantly jump to that rule in the main editor
  - **Closes Results Window**: Analysis window automatically closes when navigating to rule for uncluttered workflow
  - **Selects and Focuses Rule**: Target rule is automatically selected, focused, and scrolled into view in main program
  - **Multiple Table Support**: Works across all relevant analysis tabs:
    - **Unused Rules**: All 3 sub-tabs (Confirmed Unused, Recently Deployed, Unknown Age)
    - **Low-Frequency Tab**: Rules with <10 hits or <1 hit/day
    - **Effectiveness Tab**: Top 20 performing rules (Pareto analysis)
    - **Unlogged Tab**: Rules that don't write to CloudWatch logs
  - **Quick Editing**: Enables rapid workflow of identify-in-analysis → jump-to-rule → edit → save
  - **Professional UX**: Standard double-click behavior familiar from file browsers and IDEs

### Technical Implementation
- **Reusable Helper Method**: Added `_jump_to_rule_in_main_editor()` method in ui_manager.py
- **Four Double-Click Handlers**: Added handlers to each table in specified tabs
- **Consistent Behavior**: All handlers extract line number from appropriate column and call helper method
- **Window Management**: Properly closes results window, brings main window to front, and ensures focus

### User Impact
- **Improved Workflow**: Eliminates manual searching for rules identified in analysis results
- **Time Savings**: Single double-click replaces multi-step "note SID → close window → find rule" process
- **Enhanced Usability**: Makes rule usage analysis feature more actionable and productive
- **Natural Interaction**: Double-click is intuitive and requires no additional training

---

## Version 1.27.0 - January 11, 2026

### Major New Feature: CloudWatch Rule Usage Analysis
- **AWS Integration for Rule Effectiveness Analysis**: New comprehensive CloudWatch Logs integration provides deep insights into which rules are actually triggering in production
  - **Direct CloudWatch Integration**: Query AWS CloudWatch Logs Insights to analyze rule usage patterns across your deployed rule groups
    - Single-click analysis from Tools menu with optional boto3 dependency
    - Queries millions of log entries server-side, returns aggregated results (~10-60 seconds)
    - Analyzes 7, 30, 60, or 90-day time windows for comprehensive usage patterns
  - **Ten Analytical Views**: Results window with comprehensive tabs for actionable insights
    - **Summary Dashboard**: Rule group health score (0-100) with visual gauge, quick stats, and priority recommendations
    - **Unused Rules - Confirmed Unused**: Rules ≥14 days old with 0 hits - safe to remove with bulk action support
    - **Unused Rules - Recently Deployed**: Rules <14 days old with 0 hits - too new to judge
    - **Unused Rules - Never Observed**: Unknown age with 0 hits - manual review recommended
    - **Low-Frequency Rules**: Identifies rarely-triggered rules (<10 hits) with color-coded staleness indicators
    - **Rule Effectiveness**: Pareto analysis showing top performers and overly-broad rules handling excessive traffic
    - **Efficiency Tiers**: Distribution visualization (Critical/High/Medium/Low/Unused) with bar charts
    - **Search**: Quick SID lookup with detailed statistics and contextual analysis
    - **Unlogged Rules**: Shows rules that don't write to CloudWatch (pass without 'alert', drop/reject with 'noalert')
    - **Untracked Rules**: Shows SIDs in CloudWatch logs not in your file (deleted rules, AWS default policy rules)
  - **Right-Click Quick Lookup**: Instant CloudWatch statistics for any rule from main table context menu
    - Shows hits, percentage of traffic, last hit timestamp, and rule age
    - Cached results enable instant lookups without re-querying CloudWatch
    - Automatic refresh available when needed
  - **Persistent Statistics Storage**: Save and auto-load analysis results for offline access
    - **Save Button**: Manually save analysis results to `.stats` companion file
    - **Automatic Loading**: Stats file automatically loaded when opening rule files
    - **Offline Analysis**: Stats file allows viewing usage statistics offline
    - **Session Persistence**: Loaded statistics cached until new analysis run
    - **Same Prompt Behavior**: "View cached or run new" dialog appears with saved data
  - **Deployment-Aware Analysis**: Integrates with existing change tracking for intelligent unused rule classification
    - Recently deployed rules (<14 days) flagged separately from confirmed unused rules
    - Rule age calculated from revision history for accurate confidence levels
    - Never removes rules - only provides recommendations with confidence indicators
  - **Actionable Recommendations**: Priority-ranked suggestions with expected impact
    - Remove confirmed unused rules (capacity optimization)
    - Review low-frequency rules (potential shadowing detection)
    - Split overly-broad rules (security improvement)
    - Monitor critical high-traffic rules (change management)
  - **Export Capabilities**: HTML and plain text reports with comprehensive statistics and visualizations
  - **In-App Help System**: Complete setup guide accessible from Help menu
    - Prerequisites tab (boto3 installation, CloudWatch logging requirements)
    - IAM Permissions tab (copy-paste ready policy with security notes)
    - Credentials tab (AWS CLI, environment variables, IAM role options)
    - Testing tab (connection test with detailed validation results)
  - **Professional Error Handling**: Comprehensive error detection for all AWS scenarios
    - boto3 not installed, AWS credentials missing, log group not found
    - Access denied (IAM), query timeout, rate limiting, network errors
    - All errors link to relevant help section for quick resolution

### Business Value
- **Extends AWS Network Firewall Monitoring**: Builds upon AWS Network Firewall's traffic statistics dashboard by adding rule-level efficiency analytics
- **Identify Unused Rules**: Find rules with 0 hits without flagging recently deployed rules
- **Capacity Optimization**: Stay within AWS 30,000 rule limit by removing unused rules
- **Shadow Rule Detection**: Low-frequency rules may be partially blocked by earlier rules in evaluation order
- **Security Improvement**: Detect overly-broad rules handling excessive traffic percentages

### Technical Implementation
- **New Module**: `rule_usage_analyzer.py` with RuleUsageAnalyzer class (~1,500 lines)
- **CloudWatch Logs Insights Query**: Server-side aggregation with single efficient query
  - Query returns ~200KB for 10,000 rules (vs millions of raw log entries)
  - Handles pagination automatically for result sets >10,000 rules
- **Optional Dependency**: boto3 required only for this feature (graceful degradation without it)
- **UI Integration**: Progress dialog, results window with six tabs, right-click context menu
- **Help System**: Four-tab setup guide with IAM policy, credential configuration, and connection testing
- **Zero Breaking Changes**: All existing functionality preserved - feature is purely additive

### User Impact
- **Invaluable Production Insights**: Know exactly which rules are effective vs. unused
- **Data-Driven Decisions**: Remove rules confidently with deployment-aware analysis
- **Capacity Management**: Optimize rule count to maximize available capacity
- **Security Validation**: Identify rules that need refinement based on actual traffic patterns
- **AWS-Native Workflow**: Direct integration with CloudWatch Logs (standard AWS observability)

---

## Version 1.26.0 - January 3, 2026

### Major New Feature: Alert-Only Test Mode for Safe Production Testing
- **Export for Testing Without Risk**: New test mode converts all actions to 'alert' for safe production testing while preserving original actions in CloudWatch logs
  - **Export Options Dialog**: Choose format (Terraform/CloudFormation) and enable test mode with checkbox
  - **Live Preview**: Shows first 3 converted rules with [TEST-ACTION] prefixes
  - **Action Preservation**: Original actions embedded in message prefix for instant CloudWatch visibility
    - [TEST-PASS], [TEST-DROP], [TEST-REJECT], [TEST-ALERT]
  - **Zero Risk**: Source file never modified - conversion happens only at export
  - **Smart Defaults**: Auto-suggests _test suffix (e.g., network-firewall-rules_test.tf)
  - **Comprehensive Warnings**: Dialog, file comments, and success message explain AWS policy requirements
- **AWS Policy Prerequisites (CRITICAL)**: Policy must have NO default drop action for test mode to work
  - Required: No 'Drop all', 'Drop established', or 'Application Layer drop established'
  - Optional: 'Alert all' or 'Alert established' for enhanced visibility
  - Alert rules only log traffic - with no default drop, traffic flows normally
- **Professional Workflow**: Industry-standard testing pattern (alert → validate → enforce)
  - Export with test mode → Deploy → Monitor CloudWatch → Fix false positives → Export production → Deploy

### User Impact
- **Safe Testing**: Validate rules against real traffic without service disruption
- **Clear Logs**: See intended actions in CloudWatch without cross-referencing
- **Fast Iteration**: No manual editing needed for testing
- **Confidence**: Prove accuracy before enforcement

---

## Version 1.25.1 - January 1, 2026

### Bug Fix: Missing Revision History for Non-Placeholder Rule Insertion Methods
- **Fixed Missing Revision History Across All Rule Entry Methods**: Corrected bug where newly added rules did not show revision history in the Rev dropdown when change tracking was enabled on a blank file and rules were added via methods other than placeholder
  - **Root Cause**: When enabling tracking on a blank file (no existing rules), baseline snapshots only exist in `pending_history` (not written to disk yet). Five rule insertion methods were checking if history file exists on disk, and when it didn't, they created a RevisionManager that defaulted to v1.0 format, causing `detect_format_and_upgrade_needed()` to return `(True, '1.0')`, so no snapshot was created
  - **Impact**: Rules added via Insert Rule button, paste, domain import, and template insertion did NOT show revision history in Rev dropdown, while placeholder method worked correctly (Bug #21 fix was only applied to `save_rule_changes()` and `insert_new_rule_from_editor()`, not to other insertion methods)
  - **Affected Methods**:
    - ❌ Insert Rule button (`insert_rule()`) - Rev dropdown empty
    - ❌ Paste from clipboard (`paste_rules()`) - Rev dropdown empty
    - ❌ Insert Domain Allow Rule button (`insert_domain_rule()`) - Rev dropdown empty
    - ❌ Import Domain List (`show_bulk_import_dialog()`) - Rev dropdown empty
    - ❌ Template insertion (`show_template_preview_dialog()`) - Rev dropdown empty (both dual and standard)
    - ✅ Placeholder / Save Changes (`insert_new_rule_from_editor()`, `save_rule_changes()`) - Already worked
  - **Complete Solution**: Applied the same `has_pending_snapshots` check logic from Bug #21 fix to all 5 affected insertion methods
    - Check if history file exists on disk
    - **Check if baseline snapshots exist in `pending_history`** (critical addition)
    - If either indicates v2.0 mode, create snapshots with GUIDs
    - Rev dropdown now shows complete revision history for all insertion methods

### Technical Implementation
- **suricata_generator.py** (3 methods fixed):
  - `insert_rule()` - Added `has_pending_snapshots` check before creating RevisionManager
  - `paste_rules()` - Added `has_pending_snapshots` check before creating RevisionManager
  - `show_template_preview_dialog()` - Added `has_pending_snapshots` check (both dual and standard insertion code paths)
- **domain_importer.py** (2 methods fixed):
  - `insert_domain_rule()` - Added `has_pending_snapshots` check before creating RevisionManager
  - `show_bulk_import_dialog()` - Added `has_pending_snapshots` check before creating RevisionManager
- **Consistent Pattern**: All 5 methods now use identical logic:
  ```python
  has_pending_snapshots = any(
      'rule_snapshot' in entry.get('details', {})
      for entry in self.pending_history
  )
  # Determine if we should create snapshot based on file existence AND pending_history
  ```
- **Maintains Deferred Write**: Snapshots stored in `pending_history` until file save, per v2.0 format design

### User Impact
- **Universal Revision History**: Rev dropdown now works correctly for ALL rule insertion methods on new files with tracking enabled
- **Consistent Behavior**: No matter how you add a rule (button, paste, import, template), revision history is always available
- **Improved Reliability**: Rev dropdown functionality no longer depends on which method was used to add the rule
- **Complete Feature Parity**: All rule entry workflows now have identical revision tracking capabilities

---

## Version 1.25.0 - December 31, 2025

### Major Enhancement: Per-Rule Revision History & Rollback
- **Rule Versioning with Rollback Capability**: Enhanced change tracking feature now enables viewing and restoring individual rules to previous revisions
  - **Rev Dropdown UI**: When change tracking is enabled, the Rev field becomes an interactive dropdown showing all available revisions for the selected rule
    - Displays revision numbers with timestamps (e.g., "Rev 3 (Current) - 2025-12-26 14:30")
    - Shows complete revision history for each rule by SID
    - Only available when change tracking is enabled - read-only text field when disabled
  - **Side-by-Side Comparison**: Before rollback, view detailed comparison of current vs selected revision
    - Compare all rule fields (action, protocol, networks, ports, message, content)
    - See full rule syntax for both versions
    - Changed fields highlighted in red for easy identification
    - Review changes before committing rollback
  - **Non-Destructive Workflow**: Rollback populates the Rule Editor without immediately changing the rule
    - Review rolled-back values in editor before saving
    - Click "Save Changes" to commit rollback
    - Cancel by selecting another rule or closing editor without saving
    - Full Ctrl+Z undo support for all rollback operations
  - **Linear History Model**: All revisions preserved permanently - old versions never deleted
    - Rolling back to Rev 2 creates a new Rev 5 (with Rev 2's content)
    - Complete audit trail maintained for compliance
    - Can rollback to any previous revision at any time
  - **Optimized Storage**: Rule snapshots embedded inline with change log entries
    - No duplicate storage - snapshots stored with the changes that created them
    - Each snapshot ~500 bytes embedded in existing .history structure
    - Efficient for typical use (100 rules × 10 revisions = ~500KB)
  - **Backward Compatible**: Existing .history files continue to work without changes
    - Legacy format (v1.0) still fully supported
    - Optional upgrade prompt for existing files to enable rollback
    - New files automatically created in enhanced format (v2.0)
    - Upgrade creates baseline snapshots for all current rules
  - **Change History Integration**: Rollback operations logged in History tab
    - Shows "rule_rolled_back" entries with source and target revision numbers
    - Maintains complete audit trail of all rollback actions
    - Includes original timestamp of rolled-back revision
  - **Automatic Baseline Snapshots**: When enabling tracking on existing files
    - Creates baseline snapshots for all current rules
    - Enables rollback capability from the point tracking was enabled forward
    - Upgrade prompt shown once per file session for legacy .history files

### Technical Implementation
- **Enhanced .history Format**: Version 2.0 format with inline rule snapshots
  - Snapshots stored in `rule_snapshot` field within change entries
  - Complete rule state captured (action, protocol, networks, ports, message, content, rev)
  - SID indexing for O(1) revision lookups (performance optimization)
- **RevisionManager Module**: Complete revision history management system (new revision_manager.py)
  - `get_revisions()` - Retrieve all revisions for a specific SID
  - `restore_revision()` - Restore rule to specific historical state
  - `upgrade_history_format()` - Convert legacy files to enhanced format
  - `transfer_sid_history()` - Maintain history when SID changes
- **UI Enhancements**: Rev dropdown and rollback confirmation dialog (ui_manager.py)
  - Conditional dropdown vs text field based on tracking status
  - Comprehensive side-by-side comparison dialog before rollback
  - Real-time revision list population as rules are selected
- **Integration Points**: Snapshots automatically saved during all rule modifications
  - Rule edits via editor panel
  - New rule insertion
  - Bulk operations (templates, domain import)
  - SID renumbering operations

### User Impact
- **Safety Net**: Roll back individual rules that were modified incorrectly
- **Audit Trail**: Complete revision history for each rule for compliance requirements
- **Experimentation**: Try changes knowing you can easily revert to any previous version
- **Documentation**: Review how specific rules evolved over time
- **Learning**: See exactly what changed between revisions
- **Zero Breaking Changes**: Existing functionality completely preserved - rollback is purely additive

---

## Version 1.24.7 - December 28, 2025

### Bug Fix: SID Suggestion Consistency with Change Tracking
- **Fixed Inconsistent SID Suggestions**: Corrected bug where enabling change tracking caused the program to suggest different starting SIDs
  - **Root Cause**: SID calculation code in 10 locations was not filtering out comment and blank lines when determining the next available SID
  - **Impact**: When change tracking was enabled (which adds 4 header comment lines), the program would suggest SID 2 instead of the expected SID 100 for new rule files
  - **Solution**: Updated all SID calculation code to filter out comments and blank lines before calculating max SID:
    - Changed from: `max([rule.sid for rule in self.rules], default=99)`
    - Changed to: `max([rule.sid for rule in self.rules if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False)], default=99)`
  - **Locations Fixed** (10 total):
    - `suricata_generator.py`: 6 instances (add_rule, insert_rule, on_tree_click, insert_new_rule_from_editor, copy_selected_rules, paste_rules)
    - `ui_manager.py`: 2 instances (on_rule_select, on_tree_click)
    - `domain_importer.py`: 2 instances (show_bulk_import_dialog, insert_domain_rule)
  - **Comprehensive Fix**: All code paths that suggest SIDs now behave consistently
- **User Impact**: Starting SID suggestion is now consistently 100 for new rule files, regardless of whether change tracking is enabled or disabled

---

## Version 1.24.6 - December 25, 2025

### Bug Fix: tkinter Compatibility for MacOS
- **Fixed tkinter trace() Method Compatibility**: Resolved Python version compatibility issue causing errors on MacOS when using template dialogs
  - **Root Cause**: Older `.trace('w', callback)` syntax is deprecated in newer Python versions and causes `TclError: bad option "variable"` on MacOS
  - **Impact**: Mac users encountered errors when opening the template preview dialog, specifically when trace callbacks were registered for Test Mode checkbox and Starting SID field
  - **Error Message**: `_tkinter.TclError: bad option "variable": must be add, info, or remove`
  - **Complete Solution**: Updated all 6 `.trace('w', ...)` calls to modern `.trace_add('write', ...)` syntax
  - **Locations Fixed**:
    - SID Management dialog: 4 trace callbacks for conflict detection preview
    - Template Preview dialog: 2 trace callbacks for real-time preview updates
  - **Compatibility**: Modern syntax works on all Python 3.x versions across Windows, MacOS, and Linux

### Technical Implementation
- Modified `show_sid_management()` method in `suricata_generator.py`
  - Updated `start_var.trace()`, `increment_var.trace()`, `scope_var.trace()`, `action_var.trace()` to use `trace_add('write', ...)`
- Modified `show_template_preview_dialog()` method in `suricata_generator.py`
  - Updated `test_mode_var.trace()` and `sid_var.trace()` to use `trace_add('write', ...)`

### User Impact
- **MacOS Functionality Restored**: Mac users can now use template feature without encountering tkinter errors
- **Cross-Platform Compatibility**: Application now uses modern tkinter API that works reliably across all platforms
- **Future-Proof**: Ensures compatibility with current and future Python versions

---

## Version 1.24.5 - December 24, 2025

### Bug Fix: MacOS Template Dialog - Complete Fix
- **Fixed Preview Frame Expansion Issue**: Resolved root cause where Rule Preview area was consuming all available space when dialog was resized on MacOS
  - **Root Cause**: Preview frame was set to `expand=True`, causing it to grow and push the Starting SID field and buttons below the visible area when window was resized
  - **Impact**: Even after increasing window height in v1.24.4, Mac users still couldn't see Cancel/Apply buttons because the preview kept expanding
  - **Complete Solution**: Changed preview frame from `expand=True` to `expand=False` to maintain fixed size
  - **Technical Details**: Preview frame now maintains its fixed height (12 lines) regardless of window size, ensuring buttons remain visible
  - **Result**: Starting SID field and Apply/Cancel buttons now remain visible and accessible on MacOS at all window sizes

### Technical Implementation
- Modified `show_template_preview_dialog()` method in `suricata_generator.py`
- Changed preview frame pack parameters: `preview_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 15))`
- Window remains resizable (from v1.24.4) with height of 700x650 for optimal display

### User Impact
- **MacOS Functionality Restored**: Mac users can now properly interact with template preview dialog buttons
- **Consistent Behavior**: Dialog layout remains stable when window is resized
- **Cross-Platform Parity**: Template feature now works reliably on MacOS, Windows, and Linux

---

## Version 1.24.4 - December 24, 2025

### Bug Fix: MacOS Template Dialog Display
- **Fixed Missing Buttons on MacOS**: Resolved UI issue where Cancel and Apply buttons were not visible in the template preview dialog on MacOS
  - **Root Cause**: Template preview dialog window height (700x500) was too short for MacOS to display all content including buttons at the bottom
  - **Impact**: Mac users could not see or click Cancel/Apply buttons in the final window of File | Insert Rules From Template feature
  - **Solution**: Increased window height from 500px to 650px (+150px) and made window resizable
  - **Platform Compatibility**: Fix ensures consistent experience across Windows, MacOS, and Linux
  - **User Control**: Resizable window allows users to adjust size based on their display preferences

### Technical Implementation
- Modified `show_template_preview_dialog()` method in `suricata_generator.py`
- Changed window geometry from "700x500" to "700x650"
- Changed resizable setting from `(False, False)` to `(True, True)`

### User Impact
- **MacOS Usability**: Mac users can now see and interact with all template dialog buttons
- **Flexibility**: Resizable window accommodates different screen sizes and user preferences
- **Cross-Platform Consistency**: Template feature now works reliably on all operating systems

---

## Version 1.24.3 - December 24, 2025

### AWS Quota Compliance Validation
- **Network Firewall Quota Enforcement**: Added comprehensive validation to prevent rules that would be rejected by AWS Network Firewall
  - **Rule Length Validation**: Validates total rule length including expanded variable values against AWS' 8,192 character limit
    - Expands all variables ($HOME_NET, @ALLOW_LIST, etc.) to their actual values before checking length
    - Blocks rules exceeding limit with clear error message showing actual expanded length
    - Warns when approaching limit (7,693-8,192 chars) with remaining character count
  - **IP Set Reference Limit**: Enforces AWS' 5 IP Set Reference (@variable) limit per rule group
    - Counts unique @ references across all rules in rule group
    - Blocks adding rules that would exceed 5 total references
    - Warns when at limit (5 references) to prevent accidental violations
    - Smart exclusion logic prevents false positives when modifying existing rules
  - **Integration Points**: Validation automatically runs when saving/inserting rules via editor panel or dialogs
- **CloudFormation Template Size Validation**: Added three-tier validation for CloudFormation export to prevent deployment failures
  - **Hard Limit (1 MB)**: Blocks export of templates exceeding S3 limit with error message and alternatives
  - **S3 Required (51.2 KB - 1 MB)**: Warns templates require S3 upload before deployment, provides instructions, asks confirmation
  - **Approaching Limit (45-51.2 KB)**: Info warning when getting close to direct API limit
  - **Real Limits Tested**: Maximum ~380 rules for direct API, ~7,700 rules with S3, 8,000+ rules blocked

### Technical Implementation
- **New Validation Methods**: Added `validate_total_rule_length()` and `validate_ip_set_references()` to main application
- **Export Enhancement**: Enhanced `export_file()` with CloudFormation template size checks
- **User-Friendly Errors**: All errors provide specific measurements, limits, and actionable solutions
- **Zero Breaking Changes**: Validations are additive - existing functionality completely preserved

### User Impact
- **Prevents Deployment Failures**: Catches quota violations before attempting AWS deployment
- **Clear Guidance**: Error messages explain the issue and provide specific solutions
- **Improved Confidence**: Users can trust their rules will deploy successfully to AWS
- **Terraform Recommendation**: Large rule sets automatically guided toward Terraform export (no size limits)

---

## Version 1.24.2 - December 22, 2025

### Bug Fix: AWS Best Practices Template Load
- **Fixed Cancel Button Behavior**: Corrected bug where clicking "Cancel" on the save changes dialog would still load the AWS template and overwrite unsaved work
  - **Root Cause**: Incorrect return value handling in `load_aws_template()` method
  - **Impact**: Users who clicked "Cancel" expecting to abort the operation would lose their unsaved changes
  - **Solution**: Simplified logic to properly abort template loading when user cancels the save dialog
  - **User Impact**: Cancel button now works as expected - clicking Cancel preserves current work and aborts the template load operation

---

## Version 1.24.1 - December 21, 2025

### Rules Analysis Engine Bug Fixes (v1.10.1)
- **Four Critical False Positive Fixes**: Comprehensive bug fix release addressing incorrect conflict detection in multiple scenarios
  - **Bug Fix 1 - Same-Action Shadowing**: Fixed DROP/REJECT rules incorrectly flagged as "security bypass" when shadowing other DROP/REJECT rules
    - **Root Cause**: Logic checked `if upper_rule.action in ['pass', 'drop', 'reject']` instead of just checking for 'pass'
    - **Impact**: False "CRITICAL" warnings for rules with same blocking actions
    - **Solution**: Changed to `if upper_rule.action == 'pass'` - security bypass only when PASS shadows DROP/REJECT
    - **Result**: DROP/REJECT shadowing DROP/REJECT now correctly classified as "info" (redundant), not "critical"
  - **Bug Fix 2 - TLS Version Restriction**: Fixed ssl_version rules incorrectly flagged as conflicting with domain-based rules
    - **Root Cause**: Analyzer didn't recognize ssl_version makes rules MORE specific (targets old TLS versions only)
    - **Impact**: Rules blocking old TLS versions incorrectly flagged as conflicting with domain allow-listing
    - **Example**: `ssl_version:sslv2,sslv3,tls1.0,tls1.1` vs `tls.sni; content:"amazonaws.com"` don't conflict
    - **Solution**: Added early return in `is_content_equal_or_broader()` when ssl_version present
    - **Enhanced Detection**: Added ssl_version vs domain detection to `uses_different_detection_mechanisms()`
  - **Bug Fix 3 - Negated GeoIP Detection**: Fixed negated geoip patterns not recognized as broader than specific countries
    - **Root Cause**: `has_geographic_specificity()` treated all geoip rules as "different detection"
    - **Impact**: Broad negated patterns like `geoip:dst,!KH,!CN` not flagged as shadowing specific `geoip:dst,BT`
    - **Solution**: Enhanced to detect negated vs non-negated and return False (allow conflict detection)
    - **Country Comparison**: Added regex extraction and set comparison for specific country codes
  - **Bug Fix 4 - Same-Country GeoIP**: Fixed identical country rules not detected as conflicting
    - **Root Cause**: Both rules using specific countries returned True (different detection), stopping analysis
    - **Impact**: `geoip:dst,BT` (DROP) not flagged as shadowing `geoip:dst,BT` (PASS)
    - **Solution**: Return False when both use specific countries (same detection mechanism)
    - **Comprehensive Fix**: Check both content and original_options fields for geoip keywords

### Technical Implementation
- **Modified Methods in rule_analyzer.py**:
  - `check_rule_conflict()` - Fixed security bypass logic (line ~210)
  - `is_content_equal_or_broader()` - Added ssl_version early return + geoip comparison logic
  - `uses_different_detection_mechanisms()` - Added ssl_version, JA3/JA4 vs domain detection
  - `has_geographic_specificity()` - Enhanced for negated geoip + same-country detection

### User Impact
- **Eliminated False Positives**: No more incorrect "CRITICAL" warnings for valid rule configurations
- **Accurate GeoIP Analysis**: Negated and specific country patterns now correctly analyzed
- **Better ssl_version Handling**: Version-specific rules no longer conflict with domain rules
- **Cleaner Reports**: Only real conflicts flagged, reducing noise and confusion

---

## Version 1.24.1 - December 21, 2025

### Variable Management Enhancement: Add Common Ports Feature
- **Pre-Configured Port Variables Library**: New comprehensive library of common port variables categorized for rapid creation
  - **One-Click Addition**: Add industry-standard port variables with descriptions via "Add Common Ports" button
  - **Category Organization**: Port variables grouped by service type for easy navigation
  - **Description Support**: All variables include descriptive text explaining their purpose and included ports
    - Descriptions display in Variables tab for easy reference
    - Helps teams understand variable contents without memorizing port numbers
  - **Conflict Detection**: Warns if variable name already exists before overwriting
  - **User-Extensible**: Edit `common_ports.json` to add custom port variables without code changes
  - **Backward Compatible**: Enhanced variable format compatible with existing .var files
    - Old .var files load seamlessly and auto-upgrade to new format
    - New description field optional - empty string if not provided
    - Legacy string format automatically converted to new dictionary format

### Variable Data Structure Enhancement
- **Description Field**: Variables now support optional description text
  - Internal format: `{"definition": "[80,443]", "description": "Standard HTTP/HTTPS"}`
  - Displayed in Variables tab for documentation
  - Preserved in .var files for persistence
- **Hybrid Format Support**: File loading handles both legacy and enhanced formats
  - Legacy format: `{"$WEB_PORTS": "[80,443]"}` (string)
  - New format: `{"$WEB_PORTS": {"definition": "[80,443]", "description": "..."}}`
  - Automatic conversion on load, always saves in new format

### User Interface Updates
- **Add Common Ports Button**: New button in Variables tab between "Add Reference" and "Edit"
- **Description Column**: New column in Variables tab displays variable descriptions
- **Enhanced Dialogs**: Variable add/edit dialogs include description textbox
- **Category Selection**: Common ports dialog shows checkboxes organized by service category

### Technical Implementation
- **New Data File**: `common_ports.json` with pre-configured port variables
- **Enhanced File Manager**: Updated variable loading/saving to handle description field
- **UI Manager Updates**: Enhanced dialogs and table display for description support
- **Seamless Migration**: Existing workflows unaffected, descriptions optional

### User Impact
- **Faster Variable Creation**: Select from common port definitions instead of manual entry
- **Better Documentation**: Descriptions explain variable purpose and included ports
- **Reduced Errors**: Pre-configured port lists ensure correct port numbers
- **Team Collaboration**: Descriptions improve understanding across team members
- **Extensibility**: Custom port variables easily added to common_ports.json
- **Zero Breaking Changes**: All existing functionality preserved with enhanced capabilities

---

## Version 1.24.0 - December 21, 2025

### Major New Feature: Rule Templates Library
- **Pre-Built Security Rule Templates**: New comprehensive template library with 14 ready-to-use templates for common security patterns and policy enforcement
  - **Rapid Rule Generation**: Generate complete, production-ready Suricata rules from templates with minimal input
  - **Category Organization**: Templates grouped into 6 security categories for easy navigation
    - **Protocol Enforcement** (5 templates): Force DNS resolver, enforce HTTPS, enforce TLS versions, protocol port usage, block file sharing
    - **Cloud Security** (1 template): Enforce HTTPS for AWS services
    - **Threat Protection** (4 templates): Block cryptocurrency mining, block malware C2 ports, block direct-to-IP connections
    - **Geographic Control** (1 template): GeoIP-based country filtering with 36 countries across 6 regions
    - **Application Control** (1 template): JA3 TLS fingerprint matching
    - **Default Deny** (2 templates): Comprehensive egress and ingress default-deny rulesets
  - **Two Template Types**:
    - **Policy Templates** (6 templates): One-click rule generation with no configuration needed
    - **Parameterized Templates** (8 templates): Customizable templates with user input for specific scenarios
  - **Six Parameter Types**: Flexible configuration options for parameterized templates
    - **Radio Buttons**: Select one option (e.g., TLS 1.2+ or TLS 1.3+)
    - **Checkboxes**: Boolean options (e.g., bidirectional enforcement)
    - **Text Input**: Free-form entry with validation (e.g., JA3 hash)
    - **Multi-Select Port**: Choose from multiple ports with descriptions
    - **Multi-Select Protocol**: Select protocols with transport/port metadata display
    - **Multi-Select Country**: Regional country selection with grouping (Asia, Americas, Africa, Middle East, Europe, Oceania)
  - **Test Mode Feature**: Universal safety feature for all templates
    - Convert all generated rule actions to 'alert' for safe testing
    - Adds [TEST] prefix to rule messages
    - Validate rule behavior before deploying blocking rules
  - **Smart Features**:
    - **Preview Dialog**: Review generated rules before insertion with scrollable preview
    - **Smart SID Suggestions**: Automatically suggests next available SID (Default Deny templates use 999991-999999 range)
    - **Variable Auto-Detection**: Templates using variables trigger automatic detection and population in Variables tab
    - **Atomic Insertion**: All template rules inserted together with all-or-none guarantee
    - **Undo Support**: Complete undo capability (Ctrl+Z removes all template rules)
    - **Change Tracking**: Template applications logged in change history when tracking enabled
  - **Complex Template Support**:
    - **Conditional Rules**: Templates can generate different rule sets based on parameter selections
    - **Multi-Rule Generation**: Multi-select parameters generate 1 rule per selection
    - **Insertion Control**: Default Deny templates automatically insert at end of ruleset
    - **Regional Grouping**: Country selection organized by geographic region with Select All/None controls

### Access and Usage
- **Menu Access**: File > Insert Rules From Template
- **Workflow**: Select Template → Configure Parameters (if needed) → Preview Rules → Apply with SID
- **Category Filtering**: Browse templates by security function category
- **Complexity Indicators**: Beginner, Intermediate, or Advanced labels guide template selection

### Template Examples

**Simple Policy Template:**
```
Force Route 53 Resolver
- No parameters required
- Generates 1 rule blocking direct DNS
- Use case: Force VPC Route 53 usage
```

**Parameterized Template:**
```
Enforce TLS Version
- Parameter: Radio (TLS 1.2+ or TLS 1.3+)
- Generates 1 rule blocking old SSL/TLS versions
- Use case: Security compliance enforcement
```

**Complex Multi-Select Template:**
```
Geographic Country Control
- Parameter 1: Radio (Block mode or Allow mode)
- Parameter 2: Multi-select country (36 countries with regional grouping)
- Generates 1 rule per selected country
- Use case: Geographic access control with GeoIP
```

**Default Deny Template:**
```
Default Egress Block Rules
- No parameters required
- Generates 7 rules with flowbits coordination
- Automatically inserts at end of ruleset (SID 999991-999997)
- Use case: Comprehensive deny-all egress policy
```

### Technical Implementation
- **New Module**: `template_manager.py` with TemplateManager class for template loading and rule generation
- **Template Library**: `rule_templates.json` containing all 14 template definitions with parameters and metadata
- **UI Integration**: Category-organized template selection dialog with parameter collection and preview
- **Data-Driven Design**: Templates defined in JSON for easy extension without code changes
- **Zero Breaking Changes**: All existing functionality preserved - templates are purely additive

### User Impact
- **Faster Rule Development**: Generate multiple rules in seconds instead of manual creation
- **Best Practices Built-In**: Templates embody security best practices and common patterns
- **Reduced Errors**: Pre-validated rule patterns minimize syntax and logic errors
- **Consistency**: Standardized rule patterns across teams and deployments
- **Educational**: Learn Suricata rule patterns from working examples
- **Production Ready**: Test Mode enables safe validation before deploying blocking rules
- **Time Savings**: Complex rulesets (like Default Deny with 7 coordinated rules) generated instantly

---

## Version 1.23.1 - December 18, 2025

### Flow Tester Critical Bug Fixes (v1.0.4)
- **Four Critical Flow Testing Bugs Fixed**: Comprehensive bug fix release addressing flow matching logic issues with connectionless protocols, port matching, and application layer validation
  - **Bug Fix 1 - ICMP/UDP Flow Direction Matching**: Fixed rules with `flow:to_server`/`flow:to_client` not matching connectionless protocols
    - **Root Cause**: Flow direction keywords incorrectly required `flow_state=='established'`, preventing ICMP/UDP flows (which use `flow_state=='all'`) from matching
    - **Impact**: ICMP/UDP rules with direction keywords never matched in flow tests, showing incorrect "undetermined" results
    - **Real-World Example**: `pass icmp $HOME_NET any -> any any (flow:to_server; sid:202501035;)` failed to match ICMP flows
    - **Solution**: Updated `_flow_state_matches()` to allow `to_server`/`to_client` to match both 'established' and 'all' states
  - **Bug Fix 2 - Port-Specific Rules Matching ICMP**: Fixed connectionless protocols incorrectly matching rules with specific port numbers
    - **Root Cause**: When `flow_port="any"` (ICMP doesn't have ports), logic incorrectly returned `True` for any rule port specification
    - **Impact**: ICMP flows matched rules for ports 53, 1389, [4444,666,3389] even though ICMP doesn't use ports
    - **Solution**: Updated `_port_matches()` so when `flow_port="any"`, only matches if rule also has `port="any"`
  - **Bug Fix 3 - Pcre Pattern Validation Missing**: Fixed application layer rules with pcre patterns not being properly validated
    - **Root Cause**: When rules had both `content:` and `pcre:` keywords, only content was checked, ignoring the pcre regex validation
    - **Impact**: Rules like (direct-to-IP detection: `content:"."; pcre:"/IP_REGEX/"`) matched any domain with a dot, not just IPs
    - **Real-World Example**: HTTP flow to "www.example.com" incorrectly matched direct-to-IP detection rule
    - **Solution**: Enhanced `_extract_keyword_value()` and `_matches_pattern()` to extract and validate pcre patterns (pcre takes precedence)
  - **Bug Fix 4 - TLD Checking Rules Matching IP Addresses**: Fixed domain TLD validation rules incorrectly matching direct-to-IP connections
    - **Root Cause**: TLD-checking rules (looking for suspicious domain suffixes like .ru, .cn) applied to IP addresses in http.host/tls.sni
    - **Impact**: Flow tests with IP addresses in URL field (e.g., "1.2.1.2") incorrectly matched TLD validation rules
    - **Solution**: Added logic to detect when host/SNI is an IP address and skip TLD-checking rules for those cases

### Technical Implementation
- **Enhanced Functions**: Modified four core functions in `flow_tester.py`
  - `_flow_state_matches()` - Fixed flow direction keyword matching for connectionless protocols
  - `_port_matches()` - Fixed port matching logic for protocols without ports
  - `_extract_keyword_value()` and `_matches_pattern()` - Added pcre pattern extraction and validation
  - `_check_application_layer_match()` - Added IP address detection and TLD rule filtering
- **New Helper Functions**: Added `_is_ip_address()` and `_is_tld_checking_rule()` for enhanced validation
- **Comprehensive Testing**: Validated against multiple test scenarios (ICMP, HTTP with domain, HTTP with IP, TLS with IP)

### User Impact
- **Accurate Flow Testing**: Flow tester now correctly predicts how Suricata/AWS Network Firewall will process flows
- **Proper Protocol Handling**: Connectionless protocols (ICMP, UDP) now match rules correctly without false positives
- **Application Layer Precision**: HTTP/TLS rules with pcre patterns now validate correctly against provided domains/IPs
- **Production Ready**: Flow tester behavior matches actual Suricata processing for all tested scenarios

---

## Version 1.23.1 - December 17, 2025

### Rules Analysis Engine Enhancement (v1.10.0) - AWS Network Firewall Compliance
- **Three New AWS-Specific Validation Checks**: Enhanced rule analyzer with comprehensive AWS Network Firewall limitations and caveats validation
  - **Unsupported Keywords Detection (CRITICAL)**: Identifies keywords not supported by AWS Network Firewall
    - **Datasets**: Flags `dataset` and `datarep` keywords
    - **IP Reputation**: Detects `iprep:` keyword usage
    - **File Extraction**: Identifies file keywords (`filestore`, `filemagic:`, `filename:`, `fileext:`, `filesize:`, `filemd5:`, `filesha1:`, `filesha256:`) - Note: `file.data` and `file.name` ARE supported
    - **Thresholding**: Catches `threshold:` and `detection_filter:` keywords
    - **Impact**: AWS will reject rules containing these keywords when creating/updating rule groups
  - **PCRE Restrictions Validation (CRITICAL)**: Validates proper usage of `pcre` keyword
    - **AWS Requirement**: `pcre` only allowed with companion keywords: `content:`, `tls.sni`, `http.host`, or `dns.query`
    - **Detection**: Flags `pcre` usage without any allowed companions
    - **Impact**: AWS will reject rules violating this restriction
  - **Priority Keyword Detection (WARNING)**: Identifies unsupported `priority:` keyword usage (for NFW strict rule ordering)
    - **AWS Behavior**: Strict evaluation order (file order) means `priority` keyword is ignored
    - **Recommendation**: Remove `priority` keyword and rely on file position for rule precedence
- **Documentation Reference**: All checks reference official AWS Network Firewall limitations documentation
  - Source: https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html
- **Enhanced Reports**: Three new dedicated sections in both text and HTML analysis reports
  - "🚨 AWS UNSUPPORTED KEYWORDS - CRITICAL"
  - "🚨 AWS PCRE RESTRICTIONS - CRITICAL"  
  - "⚠️ AWS PRIORITY KEYWORD - WARNING"
- **Comprehensive Coverage**: Analyzer now validates against all major AWS Network Firewall restrictions listed in AWS documentation

### Technical Implementation
- **Three New Methods**: Added `check_unsupported_keywords()`, `check_pcre_restrictions()`, and `check_priority_strict_order()` to RuleAnalyzer class
- **Conflict Categories**: Added three new categories to conflicts dictionary: 'unsupported_keywords', 'pcre_restrictions', 'priority_strict_order'
- **Report Integration**: Enhanced both `generate_analysis_report()` and `generate_html_report()` with AWS-specific validation sections
- **Validation Timing**: All checks run after existing conflict detection but before report generation

### User Impact
- **Pre-Deployment Validation**: Catches AWS-specific syntax errors before attempting to deploy to AWS Network Firewall
- **Clear Remediation**: Specific line numbers and actionable suggestions for each violation
- **Deployment Success**: Prevents rule group creation failures due to unsupported features
- **Time Savings**: Identifies compatibility issues during development rather than at deployment time

---

## Version 1.23.0 - December 16, 2025

### Major Enhancement: Advanced Editor Migration to wxPython/Scintilla
- **Professional Code Editor Experience**: Upgraded Advanced Editor from tkinter to wxPython with Scintilla component for native code folding and enhanced text editing capabilities
  - **Native Code Folding**: New collapsible code sections for grouping related rules and comments
    - Click +/- icons in the left margin to expand/collapse rule groups
    - Groups automatically detected between blank lines
    - Supports collapsing comments, rules, or mixed comment+rule groups
    - Visual tree structure with fold markers
  - **Enhanced Text Editing**: Leverages Scintilla's professional editor component used by modern IDEs
    - Superior text rendering and performance
    - Better cursor handling and selection behavior
    - Improved undo/redo functionality
    - Smooth scrolling and zooming (Ctrl+MouseWheel)
  - **Improved Validation Display**: Better visual indicators for errors and warnings
    - Red squiggles for errors with semi-transparent red background highlights
    - Orange squiggles for warnings with semi-transparent orange background highlights
    - Enhanced tooltip system for better error information display
  - **Optional Dependency**: wxPython is optional - main program works perfectly without it
    - If wxPython not installed, Advanced Editor shows helpful error message with installation instructions
    - All other features (rule editing, analysis, export, flow testing) work normally
    - Users can install wxPython anytime: `pip install wxPython`
- **Same Powerful Features**: All existing Advanced Editor capabilities preserved
  - Real-time syntax validation
  - Smart auto-complete with content keyword suggestions
  - Find and Replace with field-specific filtering
  - Auto-close brackets/quotes
  - Smart comment toggle
  - Keyboard shortcuts (Ctrl+F, Ctrl+G, Ctrl+/, F3)
- **Backward Compatibility**: Files work identically between versions - no format changes

### Technical Implementation
- **New Dependency**: Added wxPython (optional) for wxPython/Scintilla editor component
- **Graceful Degradation**: Main application has zero wxPython imports - only advanced_editor.py uses it
- **Subprocess Architecture**: Advanced Editor launches as separate subprocess for clean isolation
- **Error Handling**: Comprehensive error detection and user-friendly messages if wxPython missing

### User Impact
- **Better Organization**: Code folding makes working with large rule files significantly easier
- **Professional Experience**: Editor quality matches expectations from modern IDEs
- **Seamless Upgrade**: Existing users continue working normally - code folding is immediately available
- **No Breaking Changes**: Main program unchanged - Advanced Editor remains an optional power tool
- **Easy Installation**: Clear documentation and error messages guide users through wxPython installation if needed

---

## Version 1.22.1 - December 14, 2025

### Enhancement: Blank Line Insertion
- **Enter Key Blank Line Insertion**: Added ability to insert blank lines using the Enter key for improved rule organization
  - **Simple Workflow**: Select any line in the rules table and press Enter to insert a blank line at that position
  - **Automatic Shifting**: All subsequent lines automatically shift down to maintain proper line numbering
  - **Filter Protection**: Feature only available when no filters are active to ensure predictable line numbering
    - Clear informative message shown if user attempts to insert blank line with active filters
    - User directed to clear filters first before inserting blank lines
  - **Focus-Aware**: Only activates when rules table has focus (won't interfere with text entry in editor fields)
  - **Undo Support**: Full Ctrl+Z support - blank line insertion can be undone
  - **File Modification Tracking**: Properly marks file as modified when blank line inserted
  - **Navigation Enhancement**: After insertion, selection automatically moves to line after inserted blank line
- **Consistent with Existing Features**: Complements existing comment insertion and rule insertion functionality
- **Professional Quality**: Seamless integration with existing table management, filtering system, and undo functionality

### Technical Implementation
- **UI Manager**: Added `on_enter_key()` method with comprehensive filter checking and line insertion logic
- **Import Addition**: Added `from suricata_rule import SuricataRule` to ui_manager.py
- **Key Binding**: Registered `<Return>` key binding in setup_ui() method
- **Filter Detection**: Uses existing `rule_filter.is_active()` method to check filter state
- **Blank Line Creation**: Creates SuricataRule object with `is_blank = True` attribute
- **Integration**: Works seamlessly with existing blank line handling in file save/load operations

### User Impact
- **Improved Organization**: Easy way to add visual separation between rule sections
- **Keyboard Efficiency**: No need to use Insert Comment button for simple spacing
- **Predictable Behavior**: Clear rules about when feature is available (no filters active)
- **Professional Workflow**: Standard Enter key behavior familiar from text editors

---

## Version 1.22.0 - December 14, 2025

### Major New Feature: Rule Filtering and Hiding
- **Non-Destructive Rule Filtering**: New capability to temporarily hide rules from the main table view based on multiple criteria without deleting them
  - **Filter by Action**: Show/hide rules based on action type (Pass, Drop, Reject, Alert) with individual checkboxes
  - **Filter by Protocol**: Select specific protocols to display using multi-select dropdown (TCP, UDP, HTTP, TLS, DNS, etc.)
  - **Filter by SID Range**: Filter rules within or outside a specific SID range
    - Enter "From" and "To" SID values to define range
    - "Exclude" checkbox inverts filter to hide rules in range and show rules outside range
  - **Filter by Variable**: Show only rules using specific network variables ($HOME_NET, @ALLOW_LIST, etc.)
    - Dropdown auto-populated with variables used in current file
    - Updates dynamically as rules are edited
  - **Collapsible Filter Bar**: Space-efficient design starts collapsed by default
    - Click to expand and access all filter controls
    - Shows active filter summary when collapsed
    - Two-line layout when expanded (~45px) with minimal impact on visible rules
  - **Real-Time Filtering**: Changes apply instantly for Actions/Protocol with Apply button for SID/Variable filters
  - **Clear Status Indication**: Status bar shows "Showing X of Y rules" with active filter details
  - **Smart Filter Clearing**: Filters automatically clear when edited rules don't match current filter criteria
- **Large Rule Set Management**: Essential for working with files containing 100+ rules, improving navigation and focus
- **Professional Quality**: Filter bar preserves original line numbers, handles blank lines intelligently, and includes comprehensive validation

### Technical Implementation
- **New Module**: Created `rule_filter.py` with RuleFilter class providing core filtering logic
  - `matches()` method validates rules against all active filter criteria
  - `get_used_variables()` dynamically extracts variables from current rule set
  - `is_active()` and `get_filter_description()` for status tracking
- **UI Integration**: Enhanced `ui_manager.py` with collapsible filter bar controls
- **Main Application**: Integrated filter instance in `suricata_generator.py` with filtered table refresh logic
- **Index Mapping Fix**: Corrected critical bug where tree position was used instead of actual line numbers when filters active

### User Impact
- **Improved Navigation**: Focus on relevant rules when editing large rule sets
- **Troubleshooting Aid**: Isolate specific rule types for debugging
- **Workflow Efficiency**: Reduce cognitive load by hiding irrelevant rules temporarily
- **Zero Data Loss**: Filtered rules remain in file and are saved/exported normally

---

## Version 1.21.0 - December 11, 2025

### Major Enhancement: Unified Find and Replace
- **Unified Find and Replace Functionality**: Consolidated search and replace features across both main program and Advanced Editor with consistent behavior
  - **Main Program Enhancement**: Upgraded search-only dialog to full Find and Replace capability
    - Dialog title changed from "Enhanced Search" to "Find and Replace"
    - Added Replace, Replace All, and Find Next buttons
    - Supports field-specific replacement (e.g., replace only in Message field)
  - **Advanced Editor Enhancement**: Added "Include comments" checkbox to match main program functionality
    - Previously only available in main program's search
    - Now both dialogs have identical options for consistent experience
  - **Dynamic Filter Updates**: Real-time responsiveness to filter changes during active search
    - Change action filters (Pass, Drop, Reject, Alert) mid-search and results update automatically
    - Switch field selection and see results refresh immediately
    - Toggle case sensitivity or other options on-the-fly
    - No need to close and reopen dialog to refine search
  - **Identical User Experience**: Both dialogs now titled "Find and Replace" with matching layout and options
  - **Smart Field Filtering**: When specific fields selected (Message, Content, etc.), comments are appropriately excluded from results

### Technical Implementation
- **search_manager.py**: Added complete replace functionality with `replace_current()`, `replace_all()`, and `_replace_in_rule()` methods
- **advanced_editor.py**: Enhanced with "Include comments" checkbox and dynamic filter detection in all callback functions
- **Filter Detection**: Smart comparison logic detects checkbox changes and triggers automatic re-search
- **Proper Initialization**: Fixed dropdown initialization to display "All fields" by default in both contexts

### User Impact
- **Powerful Replace Operations**: Find and replace text across all rule fields or specific fields
- **Real-Time Control**: Dynamically adjust search filters without restarting search
- **Consistent Experience**: Same functionality whether working in main program or Advanced Editor
- **Improved Productivity**: Bulk text replacements with regex, case sensitivity, and whole word options

---

## Version 1.20.1 - December 7, 2025

### Bug Fix: Port Set Variable Validation
- **Fixed Port Set Validation Error**: Corrected critical bug where IP Set (CIDR) validation was incorrectly being applied to Port Set variables
  - **Root Cause**: Validation logic was checking variable usage analysis before checking the explicit `var_type` parameter, causing new Port Sets to default to IP Set validation
  - **Impact**: Users attempting to add Port Set variables received "Invalid CIDR definition" error instead of proper port validation
  - **Three-Part Fix**:
    1. **Add New Port Sets**: Modified validation to check `var_type` parameter first, ensuring immediate port validation
    2. **Edit Unused Port Sets**: Added intelligent type detection that examines definition format to identify port patterns (colons, brackets, port numbers 1-1024)
    3. **Variables Table Display**: Enhanced display logic to show correct "Port Set" type even when variable hasn't been used in rules yet
  - **Helper Method**: Added `_looks_like_port_definition()` to distinguish port specifications from CIDR blocks
  - **User Experience**: Improved cursor positioning in variable dialogs - cursor now positioned after "$" for immediate typing
- **Validation Now Works Correctly**: Port Sets validate port numbers/ranges with brackets, IP Sets validate CIDR blocks
- **Technical Implementation**: Modified `show_variable_dialog()`, `edit_variable()`, `on_variable_double_click()` in ui_manager.py and `refresh_variables_table()` in suricata_generator.py

### User Impact
- **Working Port Sets**: Users can now successfully create and edit Port Set variables without false CIDR validation errors
- **Correct Type Display**: Variables table shows accurate "Port Set" or "IP Set" classification
- **Better UX**: Cursor positioning improvement makes variable creation more efficient

---

## Version 1.20.0 - December 5, 2025

### New Feature: Suricata SIG Type Classification For Rules
- **Full 10-Type Classification Display**: New educational feature shows Suricata's internal rule type classification
  - **Main Table Integration**: Optional SIG Type column displays between Line and Action columns (75px width)
    - Toggle visibility via Tools → Show SIG Type Classification
    - Displays abbreviated labels: DE-Only, IP-Only, Like-IP, PD-Only, Packet, Pkt-Strm, Stream, App-Lyr, App-TX
    - Hidden by default with no state persistence between sessions
  - **Advanced Editor Display**: Status bar shows full SIG_TYPE_* name when editing rules
    - Format: "Rule 4/42 | SIG_TYPE_PKT | Modified"
    - Works at any cursor position within a rule line
  - **Educational Help Dialog**: Help → About SIG Types explains processing order and rule type definitions
    - Detailed descriptions of all 9 active types (DE-Only through App-TX)
    - Processing order explanation (1-9, where 1 processes first)
    - Key insights about protocol layering conflicts
    - Clickable link to official Suricata documentation
  - **10 Official Types Supported**:
    1. **DE-Only** (Decoder Events) - Rules with decode-event keyword or pkthdr protocol
    2. **IP-Only** (Basic IP) - Simple IP/protocol rules without keywords
    3. **Like-IP** (Negated IP) - IP rules with negated addresses (!, [!10.0.0.0/8])
    4. **PD-Only** (Protocol Detection) - Rules with app-layer-protocol keyword
    5. **Packet** (Flow) - Rules with flow keywords (flow:established, flowbits:isset)
    6. **Pkt-Strm** (Packet-Stream) - Content with anchoring (startswith, depth)
    7. **Stream** (Stream) - Unanchored content matching
    8. **App-Lyr** (Application Layer) - Application protocol field (http, tls, dns)
    9. **App-TX** (Application Transaction) - Sticky buffers (http.host, tls.sni)
- **Hybrid Architecture for Compatibility**: Maintains backward compatibility while providing detailed classification
  - **Display**: Full 10-type classification for educational purposes
  - **Conflict Detection**: Continues using proven simplified 3-tier system (IPONLY, PKT, APPLAYER)
  - **Test Flow Compatible**: No changes to flow testing logic - maps 10 types to 3 tiers internally
  - **Zero Breaking Changes**: All existing functionality preserved
- **Fast Performance**: Classification calculation adds < 0.001 seconds per rule
  - 100 rules: Imperceptible delay
  - 1000 rules: < 0.1 seconds
  - No progress bars needed
- **Understanding Protocol Layering**: Helps users understand why IP-Only rules process before App-TX rules
  - Explains unexpected shadowing conflicts
  - Shows how to elevate IP-Only rules to Packet type by adding flow keywords
  - Links directly to 'Review Rules' feature for detecting conflicts

### Technical Implementation
- **Classification Logic** (`rule_analyzer.py`): Four new methods implementing comprehensive type detection
  - `get_detailed_suricata_rule_type()` - Determines one of 10 types using keyword analysis
  - `_has_negated_addresses()` - Detects negated network specifications
  - `map_detailed_to_simplified()` - Maps 10 types to 3-tier system
  - `get_display_label_for_type()` - Returns abbreviated display labels
- **UI Changes** (`ui_manager.py`): New menu items and toggle functionality
  - Updated table structure from 4 to 5 columns
  - Added Tools menu checkbox for visibility toggle
  - Added Help menu item with comprehensive educational dialog
- **Main Application** (`suricata_generator.py`): Conditional display logic
  - Always uses 5-column structure (prevents display bugs)
  - Calculates SIG type only when column visible
  - Proper handling for blank lines and comments
- **Advanced Editor** (`advanced_editor.py`): Status bar enhancement
  - Parses full current line for classification
  - Displays full SIG_TYPE_* constant name
  - Robust error handling for parse failures

### User Impact
- **Educational Tool**: Helps users understand Suricata's internal processing order
- **Protocol Layering Insight**: Explains why certain conflicts occur and how to fix them
- **Zero Overhead**: Feature is opt-in with no performance impact when disabled
- **Professional Documentation**: Direct link to official Suricata documentation for deeper learning

---

## Version 1.19.4 - December 1, 2025

### Rules Analysis Engine Bug Fix (v1.9.3) - Asymmetric Flow Policy False Positives
- **Fixed False Positives with Alert Rules**: Corrected bug where alert rules were incorrectly triggering ASYMMETRIC FLOW POLICIES warnings
  - **Root Cause**: Analyzer was treating alert rules as "allowing" traffic when checking for asymmetric flow policies
  - **Impact**: Alert rules (which only log/observe traffic) were incorrectly flagged as creating asymmetric flow policies when paired with blocking rules
  - **Real-World Example**: 
    - Line 12: `alert tls ... (ja3.hash; content:!"xxx"; noalert; flow:to_server; ...)` - Only logs, doesn't affect traffic
    - Line 16: `reject http ... (msg:"HTTP direct to IP"; http.host; flow:to_server; ...)` - Actual blocking rule
    - **Before Fix**: Flagged as CRITICAL asymmetric flow policy (false positive)
    - **After Fix**: Correctly skipped - alert rules don't make allow/block decisions
  - **Solution**: Added early filter in `check_asymmetric_flow_pair()` to skip ALL alert rules
  - **Rule Purpose Distinction**: Alert rules only log/observe traffic - they never block or allow. Only pass/drop/reject rules affect traffic flow decisions
- **Enhanced Detection Accuracy**: Asymmetric flow check now only analyzes rules that actually make allow/block decisions
  - **Still Checked**: Pass rules, drop rules, reject rules
  - **Now Skipped**: All alert rules (with or without noalert)
- **User Impact**: Eliminates confusing false positive warnings about alert rules, focusing analysis on actual security policy conflicts between pass/drop/reject rules

---

## Version 1.19.4 - December 1, 2025

### Rules Analysis Engine Enhancement (v1.9.2) - AWS Network Firewall Syntax Validation
- **Reject on IP Protocol Detection**: New critical validation check identifies rules that use REJECT action with IP protocol, which is not supported by AWS Network Firewall
  - **AWS Restriction**: AWS Network Firewall does not allow reject actions on IP protocol rules; such rules must use drop, pass, or alert instead
  - **Real-World Example**: Rule `reject ip any any -> any any (msg:"default drop"; sid:111;)` will be rejected by AWS as invalid syntax
  - **Automatic Detection**: Analyzer now scans all rules and flags IP protocol + reject action combinations as CRITICAL issues
  - **Report Integration**: New dedicated section "🚨 REJECT ON IP PROTOCOL - CRITICAL" in both text and HTML analysis reports
  - **Clear Guidance**: Each detected issue includes specific line number, full rule text, and actionable suggestion to change action to 'drop'
  - **Pre-Deployment Safety**: Catches this configuration error before attempting to deploy to AWS Network Firewall

### File Save Validation Enhancement
- **Save-Time Validation**: Added pre-save validation check to prevent saving files with reject on IP protocol rules
  - **Blocking Validation**: File save operation will fail with clear error message if invalid rules are detected
  - **Error Message Format**: "AWS Network Firewall does not allow REJECT action on IP protocol rules. Invalid rules found at line(s): [numbers]. Change action to 'drop' instead."
  - **Specific Line Numbers**: Error message lists all line numbers with invalid rules for quick identification and correction
  - **Consistent Pattern**: Validation follows same pattern as existing duplicate SID check (runs immediately after SID validation, before variable validation)
  - **User Safety**: Prevents accidentally saving and deploying invalid configurations to AWS

### Technical Implementation
- **Rule Analyzer**: Added `check_reject_on_ip_protocol()` method to scan rules for IP protocol + reject action combination
- **Conflict Categories**: Added 'reject_ip_protocol' category to conflicts dictionary for proper tracking and display
- **Report Generation**: Enhanced both `generate_analysis_report()` and `generate_html_report()` with reject on IP protocol section
- **File Manager**: Added validation check in `save_rules_to_file()` method that raises ValueError if invalid rules detected
- **Integration Points**: Validation triggered in two locations for comprehensive coverage:
  1. Rule analyzer - Non-blocking advisory check during rule analysis
  2. File save - Blocking check preventing invalid configuration from being saved

### User Impact
- **Deployment Safety**: Prevents invalid rules from being deployed to AWS Network Firewall
- **Clear Feedback**: Users receive immediate, specific guidance on which rules need to be corrected
- **Two-Phase Detection**: Advisory check in analyzer + mandatory check on save provides flexibility while ensuring safety
- **Time Savings**: Catches configuration errors before attempting AWS deployment, avoiding deployment failures

---

## Version 1.19.3 - November 27, 2025

### Flow Tester Bug Fix (v1.0.3) - Line Order Deconfliction
- **Fixed Incorrect Rule Precedence in Flow Testing**: Corrected critical bug where flow tester was not considering line order when applying Suricata deconfliction logic
  - **Root Cause**: Deconfliction logic (packet-scope DROP/REJECT vs flow-scope PASS) was applied without considering which rule appeared first in the file
  - **Impact**: Later rules could incorrectly override earlier rules, causing flow tester to show traffic as blocked when it should be allowed
  - **Real-World Example**: 
    - Line 3: `pass http ... (http.host; content:"example.com"; endswith; sid:102;)` - Flow scope PASS
    - Line 5: `drop ip ... (flow:established,to_server; sid:104;)` - Packet scope DROP
    - **Before Fix**: Packet DROP won (incorrect) → Traffic shown as BLOCKED
    - **After Fix**: Line 3 came first → Flow PASS wins (correct) → Traffic shown as ALLOWED
  - **Solution**: Enhanced deconfliction logic to track line numbers and give precedence to whichever action rule appeared first in the file
- **Proper Suricata Behavior**: Flow tester now correctly implements line-order-aware deconfliction
  - **Deconfliction Rule**: When both packet-scope DROP/REJECT and flow-scope PASS match, the rule that appears first in the file (lower line number) takes precedence
  - **Scenario 1**: Packet DROP first (line 1) → Flow PASS later (line 2) → DROP wins (Suricata deconfliction)
  - **Scenario 2**: Flow PASS first (line 3) → Packet DROP later (line 5) → PASS wins (file order priority)
  - **AWS Network Firewall Compatibility**: Behavior matches strict order processing used by AWS Network Firewall

### Technical Implementation
- **Line Number Tracking**: Modified `_test_flow_phase()` method to track line numbers for both packet-scope and flow-scope actions
- **Enhanced Deconfliction**: Updated deconfliction logic to compare line numbers before applying packet/flow scope precedence rules
- **Preserved Logic**: All existing action scope and rule type classification logic remains unchanged
- **Bug Reference**: Per Suricata bug #7653 (https://redmine.openinfosecfoundation.org/issues/7653) fixed

### User Impact
- **Accurate Test Results**: Flow tester now correctly predicts traffic behavior based on actual rule order in file
- **Eliminates False Negatives**: Rules that should allow traffic no longer incorrectly show as blocked
- **Better Rule Development**: Users can trust flow tester results when ordering rules for desired behavior

---

## Version 1.19.3 - November 26, 2025

### Rules Analysis Engine Bug Fix Release (v1.9.1)
- **Comprehensive Rule Analysis Corrections**: Fixed multiple critical bugs and false positives in rule conflict detection to better align with official Suricata documentation
  - **Documentation Alignment**: Corrected rule type classification to match Suricata's documented behavior at https://docs.suricata.io/en/latest/rules/rule-types.html
    - Fixed incorrect "elevation" logic for TCP/IP rules with flow keywords
    - Any `flow:` keyword now correctly forces packet-level classification (SIG_TYPE_PKT) for IP-only rules
    - `flow:established`/`flow:not_established` correctly force packet-level classification for app-layer protocols
  - **Handshake vs Application Layer False Positives Eliminated**: Rules with `flow:not_established` (TCP handshakes) no longer falsely conflict with HTTP/TLS rules
    - Enhanced mutual exclusivity detection recognizes handshake packets never reach app-layer parsing
    - `not_established` + `flowbits:isnotset` correctly identified as mutually exclusive
  - **Broad Shadowing Detection Improved**: Flow-only rules now correctly detected as shadowing specific rules with flowbits/content
    - Added `has_only_flow_keywords()` method to identify rules lacking app-layer restrictions
    - Flowbits now properly treated as content restrictions (not "flow-only")
    - Example: `drop tcp ... (flow:to_server;)` now correctly detected as shadowing `reject tls ... (ssl_state; ja4.hash; flowbits:set;)`
  - **Reverse Shadowing False Positives Eliminated**: Disabled reverse shadowing checks for strict order mode
    - Later rules can no longer falsely flag earlier rules as "unreachable"
    - Correct for AWS Network Firewall strict order mode (file order processing)
  - **noalert Rule Detection Restored**: Rules with `noalert` keyword now properly analyzed
    - Previously skipped entirely, even when setting important flowbits
    - Now correctly detected as WARNING when shadowed (missing flowbit tracking)

### Technical Implementation
- **Six Major Corrections**: Rule type classification, geographic filtering, flow state exclusivity, flowbits handling, reverse shadowing, and noalert processing
- **New Helper Method**: Added `has_only_flow_keywords()` to distinguish flow-only from content-matching rules
- **Enhanced Exclusivity Detection**: Multiple improvements to `flow_states_are_mutually_exclusive()` and `is_content_equal_or_broader()`
- **Filter Logic Refinements**: Reordered and refined all content matching filters for correct precedence
- **Comprehensive Testing**: Validated against both best_practices.suricata and non_best_practices.suricata test files

### User Impact
- **Fewer False Positives**: Eliminates incorrect warnings for geoip rules, handshake rules, and reverse shadowing scenarios
- **More Accurate Detections**: Now catches broad flow-only rules shadowing specific rules that were previously missed
- **Better Severity Classification**: Clear distinction between CRITICAL (security policy violations), WARNING (missing logs), and INFO (optimizations)
- **AWS Network Firewall Optimized**: All corrections maintain full compatibility with strict order mode
---

## Version 1.19.3 - November 25, 2025

### Enhancement: Message Keyword Ordering
- **msg Keyword Now Appears First**: Modified rule generation to place the `msg` keyword first within rule parentheses (when defined)
  - **New Keyword Order**: msg → content keywords → sid → rev
  - **Before**: `pass tcp any any -> any any (flow: to_server; msg:"Test"; sid:100; rev:1)`
  - **After**: `pass tcp any any -> any any (msg:"Test"; flow: to_server; sid:100; rev:1)`
  - **Consistency**: Aligns with common Suricata rule formatting conventions
  - **All Rule Paths**: Applied to new rules, edited rules, imported rules, and all rule generation functions

### Critical Bug Fix: Nested Parentheses in Message Fields
- **Fixed Rule Parsing Failure**: Resolved critical bug preventing AWS best practices template rules from loading
  - **Root Cause**: Parser regex `r'\(([^)]*)\)$'` stopped at first `)` character, even when inside quoted msg fields
  - **Impact**: Rules with parentheses in msg fields (e.g., `msg:"text (with parens)"`) failed to parse and were dropped during import
  - **Real-World Example**: AWS template rules like `msg:"HTTP direct to IP via http host header (common malware download technique)"` were being dropped
  - **Solution**: Implemented quote-aware parser that tracks when inside quotes and only matches the last opening `(` outside of quotes
  - **Technical Fix**: Replaced simple regex with intelligent character-by-character parsing that respects quote boundaries

### Technical Implementation
- **Modified Files**:
  - `suricata_rule.py`: Updated `to_string()` method to reorder keywords with msg first
  - `suricata_rule.py`: Fixed `from_string()` parser to handle nested parentheses in quoted strings
  - `suricata_generator.py`: Updated 4 locations where `original_options` is reconstructed to match new ordering
- **Parsing Enhancement**: Quote-aware parser prevents false matches on parentheses inside quoted strings
- **Backward Compatibility**: Parser still handles rules in any keyword order when loading from files

### User Impact
- **Improved Rule Quality**: msg-first ordering matches common Suricata conventions
- **AWS Template Loading**: AWS best practices template now loads completely without dropping rules
- **No Data Loss**: All rules with parentheses in msg fields now parse correctly
- **Seamless Operation**: Changes are transparent to users - rules just work correctly now

---

## Version 1.19.2 - November 25, 2025

### Rules Analysis Engine Enhancement (v1.9.0)
- **Domain Matching Bug Fixes**: Corrected two critical bugs in domain shadowing detection that caused false positive conflict warnings
  - **Bug Fix 1 - Domain Boundary Detection**: Fixed analyzer incorrectly flagging unrelated domains as conflicting
    - **Root Cause**: Domain comparison using simple string `endswith()` without checking domain boundaries
    - **Impact**: Domains like `c.s-example.com` incorrectly detected as subdomain of `example.com` (ends with string "example.com" but not domain ".example.com")
    - **Real-World Example**: Rules for `example.com` flagged as conflicting with rules for `c.s-example.com` (false positive)
    - **Solution**: Enhanced domain comparison to check for proper domain boundaries using dot separator
    - **Technical Fix**: Changed from `domain2.endswith(domain1)` to `domain2.endswith('.' + domain1)` in `is_content_equal_or_broader()`
  - **Bug Fix 2 - Exact vs Wildcard Domain Matching**: Fixed analyzer not distinguishing between exact domain matches and wildcard patterns
    - **Root Cause**: Analyzer treated all domain rules identically regardless of `startswith` vs `dotprefix` modifiers
    - **Impact**: Exact domain rules (e.g., `docs.aws.amazon.com` with `startswith;endswith`) incorrectly flagged as conflicting with other exact domains (e.g., `contentrecs-api.docs.aws.amazon.com`)
    - **Pattern Recognition**: 
      - **Exact Match**: `startswith;endswith` = matches ONLY that specific domain
      - **Wildcard Match**: `dotprefix;endswith` or just `endswith` = matches domain and all subdomains
    - **Solution**: Added `has_exact_domain_match()` method to detect exact matching patterns and compare appropriately
    - **Technical Fix**: Enhanced domain comparison logic to handle four scenarios (both exact, both wildcard, mixed exact/wildcard, mismatched)
- **Progress Bar for Large Rule Sets**: Added visual progress indicator when analyzing rules to provide user feedback during long operations
  - **Modal Progress Dialog**: Displays during analysis with title "Analyzing Rules"
  - **Real-Time Updates**: Shows percentage complete and current rule being analyzed (e.g., "45% (Analyzing rule 23/100)")
  - **Performance Optimized**: Updates approximately every 1% of total comparisons (not every single comparison)
    - 100 rules: ~50 updates instead of 4,950 = 99% fewer GUI refreshes
    - 500 rules: ~1,247 updates instead of 124,750 = 99% fewer GUI refreshes
  - **Fast Analysis**: Optimized update frequency provides smooth visual feedback without slowing down analysis
  - **Consistent Design**: Progress bar styling matches existing progress indicators (domain import, SID renumbering)
  - **Automatic Cleanup**: Dialog closes automatically when analysis completes

### Technical Implementation
- **Domain Boundary Fix**: Modified domain comparison in `is_content_equal_or_broader()` to use `'.' + domain` for proper subdomain matching
- **Exact Match Detection**: Added `has_exact_domain_match()` method to identify `startswith;endswith` patterns
- **Enhanced Logic**: Updated domain comparison to handle mixed exact/wildcard scenarios correctly
- **Progress Bar Integration**: Added optional progress parameters to `analyze_rule_conflicts()` method
- **Smart Updates**: Calculates total operations and updates UI at strategic intervals (every 1% of pairs)
- **UI Code Update**: Modified `review_rules()` in main application to create progress dialog and pass parameters to analyzer

### User Impact
- **Accurate Analysis**: Eliminates false positive warnings that confused users about legitimate rule configurations
- **Clearer Results**: Analysis reports now correctly identify only actual conflicts, not unrelated domain rules
- **Better Experience**: Large rule sets (500+ rules) now provide visual progress feedback during analysis
- **Time Savings**: Users no longer need to manually verify false positive warnings about domain conflicts
- **Professional Quality**: Progress bar matches expectations from modern applications

---

## Version 1.19.2 - November 24, 2025

### Bug Fix: Paste Validation for Invalid Rule Syntax
- **Enhanced Clipboard Paste Validation**: Fixed critical bug where rules with invalid syntax were being pasted without being commented out
  - **Root Cause**: The `parse_clipboard_text()` method only validated structural parsing (7 tokens + direction) but didn't check semantic validity of parsed fields
  - **Impact**: Invalid rules could be pasted directly into the rule set, potentially causing AWS Network Firewall deployment failures
  - **Invalid Patterns Previously Allowed**:
    - Misspelled actions (e.g., "pasz" instead of "pass")
    - Invalid protocols (e.g., "tcpp" instead of "tcp")
    - Malformed network addresses (e.g., invalid CIDR blocks)
    - Invalid port specifications (e.g., ports > 65535)
    - Malformed variable syntax (e.g., "$$var" instead of "$var")
  - **Solution**: Enhanced paste validation to verify all rule components against Suricata/AWS requirements
- **Comprehensive Validation Added**: Now validates all critical rule fields during paste operations
  - **Actions**: Must be pass, alert, drop, or reject
  - **Protocols**: Must be one of 21 supported protocols (tcp, udp, http, tls, dns, etc.)
  - **Network Addresses**: Must be valid CIDR, IP addresses, proper variables, or 'any'
  - **Port Specifications**: Must be valid port numbers (1-65535), ranges, or proper variables
  - **Variable Syntax**: Enhanced validation for $-prefixed and @-prefixed variables
    - Rejects double prefix ($$, @@)
    - Validates alphanumeric/underscore format
    - Applies to network fields, port fields, and bracketed expressions
- **Smart Error Handling**: Invalid rules automatically commented out with descriptive error messages
  - **Example**: `# [VALIDATION ERROR: invalid action 'pasz', invalid destination network '$$var'] pasz tcp any any -> $$var 80 (...)`
  - **Preserves Original**: Original rule text kept in comment for manual correction
  - **Multiple Errors**: All validation errors listed in single comprehensive message
- **Silent Validation**: No intrusive error dialogs during paste - invalid rules silently commented with inline explanations

### Technical Implementation
- **Enhanced Methods** (suricata_generator.py):
  - `parse_clipboard_text()`: Added comprehensive validation for actions, protocols, networks, and ports
  - `_validate_single_network_item()`: Enhanced to detect $$/@@  prefixes and validate variable format
  - `validate_port_list()`: Enhanced to validate variable format and reject $$ prefix
  - `_validate_bracketed_port_content()`: Enhanced to validate variables inside port brackets
  - `validate_network_field()`: Updated to use proper variable validation helper
- **Validation Flow**: Structural parsing → semantic validation → comment out if invalid → insert into rule table
- **Consistent Behavior**: Same validation logic used throughout application (paste, edit, insert operations)

### User Impact
- **Prevents Invalid Rules**: Catches syntax errors before they can cause deployment issues
- **Improved Quality**: Rules pasted from external sources automatically validated against Suricata/AWS requirements
- **Clear Feedback**: Descriptive error messages help users understand exactly what's wrong
- **Time Savings**: Eliminates need to manually find and fix invalid rules after pasting
- **Production Safety**: Prevents invalid rules from being saved to files and exported to AWS

---

## Version 1.19.1 - November 22, 2025

### Bug Fix: Domain Consolidation Algorithm
- **Critical Domain Consolidation Fix**: Fixed bug where domain consolidation was selecting overly broad parent domains instead of the most specific common parent
  - **Root Cause**: Algorithm was using greedy processing that selected subset groups before supersets, preventing optimal consolidation
  - **Impact**: Domain lists like `['one.two.three.server.appstate.edu', 'five.three.server.appstate.edu', 'server.appstate.edu', 'two.server.appstate.edu']` were incorrectly consolidated to multiple groups instead of single optimal parent
  - **Solution**: Implemented maximal group filtering that prioritizes largest consolidation groups and eliminates subset groups
  - **Before Fix**: Consolidated to `['three.server.appstate.edu', 'server.appstate.edu']` (2 groups)
  - **After Fix**: Consolidated to `['server.appstate.edu']` (1 group covering all 4 domains)
  - **Algorithm Enhancement**: Now groups parents by exact children sets, filters subsets, then selects most specific parent for each maximal group

### Feature Removal: PCRE Optimization
- **Removed PCRE Functionality**: Eliminated PCRE optimization feature as it became redundant with improved domain consolidation
  - **Analysis**: After fixing consolidation bug, determined PCRE only provided benefit for TLD variations (e.g., `example.com`, `example.edu`)
  - **Consolidation Achievement**: Default consolidation now achieves same results as PCRE for subdomain grouping (most common use case)
  - **Simpler Codebase**: Removed ~240 lines of PCRE-specific code including UI elements, methods, and logic
  - **Removed Components**:
    - PCRE checkbox and info label from import dialog
    - `analyze_domains_for_pcre()` method
    - `generate_domain_rules_with_pcre()` method
    - `generate_pcre_group_rules()` method
  - **User Impact**: Simplified import dialog, reduced complexity, same or better consolidation results
  - **Future-Proofing**: Users needing TLD variation patterns can manually create PCRE rules via Advanced Editor

### Technical Implementation
- **Maximal Group Algorithm**: Uses frozenset-based grouping with subset filtering for O(p²) complexity where p is number of parent groups
- **Efficient Processing**: Handles thousands of domains efficiently with intelligent parent selection
- **Cleaner Code**: Removal of redundant PCRE functionality improves maintainability

### User Impact
- **More Accurate Consolidation**: Domain consolidation now finds optimal common parents consistently
- **Simpler Interface**: Removed unnecessary PCRE option that didn't add value over improved consolidation
- **Better Performance**: Smart consolidation provides maximum rule reduction without PCRE complexity

---

## Version 1.19.0 - November 21, 2025

### Major New Feature: Advanced Editor
- **IDE-Style Text Editor for Rules**: New advanced editor provides a powerful IDE-like interface for users who prefer text-based rule editing
  - **Access Methods**: Available via Tools > Advanced Editor (Ctrl+E)
  - **Full Text Control**: Direct editing of all rule components with complete flexibility
  - **Modal Window**: 1000x700 resizable window with line numbers, scrollbars, and status bar
  - **Scope**: Edits all rules in current file with variables displayed as-is (e.g., $HOME_NET, @REFERENCE_SET)

#### Real-Time Syntax Validation
- **Two-Level Validation System**: Distinguishes between errors (red highlighting) and warnings (orange highlighting)
  - **Errors**: Invalid actions, protocols, networks, ports, direction, malformed syntax, missing SID
  - **Warnings**: Unknown content keywords, undefined variables, duplicate SIDs
  - **Live Feedback**: Validation occurs as you type (500ms delay) with status bar showing error/warning counts
  - **Hover Tooltips**: Mouse over underlined text to see detailed error information with suggestions
  - **Auto-Comment**: Rules with errors automatically commented out with `# [SYNTAX ERROR]` marker when saving back to main application

#### Smart Auto-Complete
- **Context-Aware Suggestions**: Intelligent auto-complete based on cursor position
  - **Actions**: alert, pass, drop, reject, # (comment)
  - **Protocols**: All Network Firewall protocols supported (tcp, udp, tls, http, dns, etc.)
  - **Networks/Ports**: Suggestions include "any", common CIDRs, port ranges, and defined variables
  - **Content Keywords**: Loaded from external `content_keywords.json` file with 50+ Suricata keywords
  - **Multi-Value Keywords**: Auto-complete shows valid values for keywords like flow:to_server, flow:established
- **Trigger Methods**: Auto-appears while typing or manual trigger with Ctrl+Space
- **Accept Suggestions**: Tab or Enter key, navigate with Up/Down arrows

#### Advanced Editing Features
- **Auto-Close Characters**: Typing `(` `[` `"` automatically inserts matching closing character with cursor positioned between
- **Smart Tab Navigation**: Tab key jumps to next semicolon in rule options section for rapid keyword entry
- **Smart Backspace**: Deleting opening bracket/quote also deletes matching closing character
- **Comment Toggle**: Ctrl+/ to comment/uncomment selected lines or current line
- **Clipboard Operations**: Standard Ctrl+X/C/V for cut/copy/paste with system clipboard integration
- **Undo/Redo**: Full multi-level undo (Ctrl+Z) and redo (Ctrl+Y) support
- **Go to Line**: Ctrl+G for quick navigation to specific line numbers

#### Find and Replace
- **Comprehensive Search**: Unified Find and Replace dialog (Ctrl+F) with advanced options
  - **Field-Specific Search**: Search in all fields, message, content, networks, ports, SID, or protocol
  - **Action-Based Filtering**: Include/exclude pass, drop, reject, alert rules and comments from search
  - **Advanced Options**: Case-sensitive, whole word matching, and regular expression support
  - **Visual Highlighting**: Current match highlighted in yellow, other matches in gray
  - **Navigation**: F3 for next match, Shift+F3 for previous match
  - **Replace Operations**: Replace current match or Replace All with detailed confirmation

#### User Interface
- **Line Numbers**: Always visible in left gutter for easy reference
- **Status Bar**: Real-time display of cursor position (Ln/Col), total lines, current rule number, modification status, and validation status
- **Synchronized Scrolling**: Line numbers scroll in sync with editor content
- **Right-Click Context Menu**: Quick access to cut/copy/paste, select all, find/replace, toggle comment, and error details
- **Keyboard Shortcuts Dialog**: Complete reference guide accessible from "Shortcuts" button

#### Content Keywords Customization
- **External JSON File**: `content_keywords.json` contains Suricata keyword definitions
  - **Hot Reload**: File loaded each time Advanced Editor opens (edit JSON, reopen to see changes)
  - **Easy Customization**: Add new keywords without modifying program code
  - **Comprehensive Coverage**: Includes syntax, valid values, descriptions, and categories for each keyword
  - **Graceful Degradation**: If file missing/corrupted, editor continues with basic auto-complete functionality
- **Future-Proof Design**: Unknown keywords generate warnings (not errors) to support new Suricata features

#### Save and Validation Workflow
- **Comprehensive Validation**: When clicking OK, all rules validated and categorized
  - **Error Rules**: Auto-commented with `# [SYNTAX ERROR]` prefix
  - **Warning Rules**: Preserved as-is (unknown keywords, undefined variables allowed)
  - **Confirmation Dialog**: Shows detailed summary of errors, warnings, and actions to be taken
- **Auto-Create Variables**: Undefined variables automatically created with empty definitions
- **Cancel Protection**: Unsaved changes prompt confirmation before discarding

### Technical Implementation
- **New Module**: `advanced_editor.py` with AdvancedEditor class (2,600+ lines)
- **Content Keywords**: `content_keywords.json` with extensible keyword definitions
- **Integration**: Seamless integration with existing validation, variable management, and rule parsing
- **Zero Dependencies**: Built entirely with tkinter/ttk (no external dependencies added)
- **Non-Breaking**: All existing functionality preserved - Advanced Editor is purely additive

### User Impact
- **Power User Tool**: Provides text-based workflow for users comfortable with Suricata syntax
- **Bulk Editing**: Efficient for large-scale rule modifications, copy/paste operations, and multi-line edits
- **Professional IDE Experience**: Auto-complete, syntax validation, find/replace match expectations from modern code editors
- **Safety Net**: Real-time validation and auto-commenting prevent invalid rules from breaking rule sets
- **Flexibility**: Coexists with GUI editor - users can choose the best tool for each task

---

## Version 1.18.12 - November 19, 2025

### Rules Analysis Engine Bug Fix (v1.8.2) - Flow Keyword Detection
- **Fixed False Positive in Contradictory Flow Detection**: Corrected bug where `to_server` and `to_client` keywords were incorrectly treated as implying "established" state
  - **Root Cause**: Flow keyword validation logic was treating directional qualifiers (`to_server`, `to_client`) as if they implied an established connection state
  - **Impact**: Rules using `flow:not_established, to_server` or `flow:not_established, to_client` were incorrectly flagged as having contradictory flow keywords
  - **Real-World Example**: TCP handshake allowance rules like `pass tcp $HOME_NET any -> any any (flow:not_established, to_server; sid:202501021;)` were incorrectly flagged
  - **Fix**: Updated contradiction detection to only check for literal `established` vs `not_established` keywords, not directional qualifiers
  - **Technical Details**: Modified `check_contradictory_flow_keywords()` method to remove `to_server` and `to_client` from established state check
- **User Impact**: Eliminates false positive warnings on valid Suricata rules using directional flow qualifiers with `not_established` state

---

## Version 1.18.12 - November 17, 2025

### Flow Tester Enhancement (v1.0.2) - Suricata Deconfliction Logic
- **Modifying for Suricata Analysis**: Implemented deconfliction logic matching current Suricata behavior for packet-scope DROP/REJECT vs flow-scope PASS conflicts
  - **Background**: Reviewed Suricata bug #7653 (https://redmine.openinfosecfoundation.org/issues/7653) that was fixed in version 8.0
  - **The Issue**: In previous versions of Suricata <8.0, packet-scope DROP/REJECT and flow-scope PASS had ambiguous/conflicting behavior
  - **The Fix**: Added deconfliction logic where packet-scope DROP/REJECT blocks flow-scope PASS from being applied
- **Enhanced Action Processing**: Updated flow tester to correctly simulate Suricata deconfliction behavior
  - **Deconfliction Rule**: When packet-scope DROP/REJECT matches, flow-scope PASS is skipped (blocked)
  - **Normal Case**: Flow-level actions continue to take precedence in non-conflicting scenarios

### Rules Analysis Engine Enhancement (v1.8.1) - Packet/Flow Action Conflict Detection
- **New Conflict Detection**: Added specialized warning for packet-scope DROP/REJECT + flow-scope PASS conflicts
  - **Pattern Detection**: Identifies when packet-scope DROP/REJECT rules conflict with flow-scope PASS rules
  - **Root Cause**: Per Suricata bug #7653, these conflicts have ambiguous behavior in <8.0 and deconfliction in 8.0+
  - **Warning Severity**: Flagged as WARNING with clear explanation linking to bug report
  - **Example Conflict**: `reject tcp ... (flow:established)` vs `pass tls ... (tls.sni; content:"amazon.com")`
- **Enhanced Analysis Reports**: New dedicated section for packet/flow action conflicts
  - **Report Section**: "⚠️ PACKET/FLOW ACTION CONFLICTS (previous Suricata behavior)"
  - **Detailed Information**: Shows line numbers, actions, protocols, and full rule text
  - **Educational Value**: Explains Suricata processing model and why conflicts occur
  - **Actionable Guidance**: Recommends rule reordering or using consistent action scopes
- **Future-Proofing Recommendations**: Helps users prepare better rulesets
  - **Behavior Change Warning**: Alerts users to rules that may behave differently after bug fix
  - **Version Context**: Documentation references Suricata bug report and version-specific behavior

### Technical Implementation
- **Flow Tester**: Added deconfliction logic in `_test_flow_phase()` method (lines ~377-397)
  - Checks if packet-scope action is DROP/REJECT and flow-scope action is PASS
  - Applies packet-scope action when deconfliction occurs
  - Preserves normal flow-level precedence for non-conflicting scenarios
- **Rule Analyzer**: Added `check_packet_drop_flow_pass_conflict()` method
  - Compares all rule pairs for packet vs flow scope conflicts
  - Uses rule type classification (SIG_TYPE_PKT vs SIG_TYPE_APPLAYER)
  - Validates if rules could match same traffic before flagging conflict
- **Report Integration**: Enhanced both text and HTML reports with packet/flow conflict section
- **Version Updates**: Flow Tester v1.0.2, Rule Analyzer v1.8.1, Main v1.18.12

### User Impact
- **Accurate Test Results**: Flow tester now correctly predicts how Suricata 8.0+ will process conflicting rules
- **Enhanced Rule Quality**: Proactive detection helps create more robust rulesets
- **Educational Value**: Detailed explanations help users understand Suricata's action scope model

---

## Version 1.18.11 - November 16, 2025

### Rules Analysis Engine Major Enhancement (v1.8.0)
- **Three New Rule Quality Checks**: Comprehensive additions to catch common configuration errors and improve rule quality

#### 1. Port/Protocol Mismatch Detection
- **Protocol on Unexpected Ports**: Identifies when protocols are used on non-standard ports
  - **Common Errors Detected**:
    - HTTP protocol on SSH port 22 → INFO
    - TLS/HTTPS protocol on HTTP port 80 → INFO
    - SSH protocol on HTTP port 80 → INFO
    - DNS protocol on non-53 ports → INFO
  - **Typical Port Mapping**: Validates against standard port assignments for 15 protocols
    - HTTP: 80, 8080, 8000, 8888, 3000, 5000
    - TLS/HTTPS: 443, 8443, 465, 587, 993, 995, 636
    - SSH: 22, FTP: 20/21, SMTP: 25/465/587, DNS: 53
    - And more for DHCP, NTP, SNMP, TFTP, POP3, IMAP, SMB, RDP
  - **Real-World Example**:
    - `pass http ... -> any 22 (http.host; ...)` → "HTTP typically uses ports: 80, 8080, 8000..."
  - **Severity**: INFO (might be intentional, worth verifying)
  - **Smart Skipping**: Only checks simple numeric destination ports, skips 'any' and variables

#### 2. Contradictory Flow Keywords Detection
- **Mutually Exclusive Flow States**: Catches impossible flow keyword combinations
  - **Detected Contradictions**:
    - `flow:to_server,to_client` → Flow cannot be in both directions simultaneously
    - `flow:established,not_established` → Cannot be both established and not established
    - `flow:to_server,not_established` → to_server implies established connection
  - **Real-World Impact**: Rules with contradictory flow keywords will NEVER match any traffic
  - **Example**: `pass tcp ... (flow:to_server,to_client; ...)` → "Rule will never match in its current state"
  - **Severity**: WARNING (rule is broken, needs immediate correction)
  - **Clear Guidance**: Suggests removing one of the contradictory keywords

#### 3. Missing nocase on Domain Matching
- **Case-Insensitive Domain Validation**: Detects domain matching without nocase modifier
  - **Pattern Detected**: tls.sni or http.host with content but no nocase keyword
  - **Problem**: Domain names are case-insensitive, so matches should use nocase
    - Without nocase: content:"Amazon.com" won't match "amazon.com" or "AMAZON.COM"
    - With nocase: content:"Amazon.com"; nocase; matches all case variations
  - **Common Mistake**: Users forget DNS is case-insensitive, leading to missed matches
  - **Example**: `pass tls ... (tls.sni; content:"Amazon.com"; endswith; ...)` → Missing nocase!
  - **Severity**: WARNING (likely causes production issues with missed matches)
  - **Suggestion**: Add nocase; modifier after content keyword

### Technical Implementation
- **New Detection Methods**: Added three comprehensive validation methods to RuleAnalyzer class
  - `check_port_protocol_mismatch()` - Port validation with 15 protocol mappings
  - `check_contradictory_flow_keywords()` - Flow state contradiction detection
  - `check_missing_nocase_on_domains()` - Domain case-sensitivity validation
- **Report Integration**: All three checks integrated into both text and HTML analysis reports
  - Port/Protocol Mismatch displayed in INFO section
  - Contradictory Flow Keywords displayed in WARNING section  
  - Missing Nocase displayed in WARNING section
- **Conflict Categories**: Added three new categories to analysis results dictionary
- **Preserved Architecture**: All existing analysis logic remains unchanged, new checks are purely additive

### User Impact
- **Catches Configuration Errors**: Identifies common mistakes before deployment
- **Prevents Match Failures**: Contradictory flow keywords and missing nocase cause rules to fail matching
- **Improves Rule Quality**: Port validation helps identify potential protocol misconfigurations
- **Educational Value**: Helps users learn about typical ports and proper domain matching
- **Production Ready**: All checks have appropriate severity levels (WARNING for errors, INFO for suggestions)

---

## Version 1.18.10 - November 16, 2025

### Rules Analysis Engine Major Enhancement (v1.7.2)
- **Transport Layer Hierarchy System**: Comprehensive protocol compatibility validation using transport layer hierarchy
  - **Protocol Transport Mapping**: Complete mapping of 26 supported protocols to their transport layers (TCP, UDP, ICMP, IP)
  - **Cross-Protocol Keyword Detection**: NEW - Detects when application-layer protocols use keywords from different application-layer protocols
    - **HTTP with TLS keywords** (tls.sni, ja3.hash, ja4.hash) → Flagged as WARNING
    - **TLS with HTTP keywords** (http.host, http.uri, http.method) → Flagged as WARNING
    - **DNS with HTTP/TLS keywords** → Flagged as WARNING
  - **Transport Layer Validation**: Detects when protocol's transport layer is incompatible with keyword requirements
    - **DHCP with TLS keywords** (DHCP uses UDP, TLS requires TCP) → WARNING
    - **QUIC with HTTP keywords** (QUIC uses UDP, HTTP requires TCP) → WARNING
    - **Any UDP protocol with TCP-only keywords** → WARNING
- **Three-Tier Detection System**: Hierarchical validation catches all incompatible combinations
  1. **Cross-Protocol Check**: App-layer protocol using different app-layer keywords (e.g., HTTP with tls.sni)
  2. **Transport Layer Check**: Protocol's transport incompatible with keyword requirements (e.g., DHCP with tls.sni)
  3. **Optimization Check**: Low-level protocol when specific is better (e.g., TCP with tls.sni) - INFO level
- **Comprehensive Coverage**: All 26 protocols validated against all application-layer keywords
  - **TCP-based**: tcp, tls, http, http2, https, ssh, smtp, ftp, smb, dcerpc, krb5, imap, pop3, msn, ikev2, rdp
  - **UDP-based**: udp, dns, dhcp, ntp, tftp, snmp, quic, syslog, radius, nfs
  - **Other**: icmp, ip (universal - skips transport checks)
- **Real-World Examples**:
  - `pass http ... (tls.sni; content:"amazon.com")` → "HTTP traffic does not contain TLS data - this rule will never match"
  - `pass dhcp ... (tls.sni; content:"amazon.com")` → "TLS requires TCP transport but DHCP uses UDP - this rule will never match"
  - `pass tcp ... (tls.sni; content:"amazon.com")` → "Consider using 'tls' protocol instead for better clarity and performance"

### Technical Implementation
- **Protocol Hierarchy Tables**: Added `protocol_transport_layer` dictionary mapping all protocols to transport layers
- **Keyword Requirements**: Added `keyword_transport_requirements` dictionary mapping keyword families to required transports
- **Enhanced Detection Logic**: Multi-stage validation checks cross-protocol mismatches before transport compatibility
- **Preserved Complexity**: All existing Suricata rule type classification and action scope logic remains unchanged
- **Additive Architecture**: New checks supplement existing analysis without disrupting proven conflict detection

### User Impact
- **Catches More Errors**: Identifies rules that will never match due to protocol/keyword incompatibility
- **Professional Analysis**: Transport layer validation matches enterprise security team expectations
- **Clear Messaging**: Distinguishes between invalid combinations (WARNING) and optimization suggestions (INFO)
- **Educational Value**: Helps users understand protocol relationships and proper keyword usage

---

## Version 1.18.9 - November 16, 2025

### Rules Analysis Engine Enhancement (v1.7.1)
- **Protocol/Keyword Mismatch Detection**: New informational check identifying suboptimal protocol choices when using application-layer keywords
  - **Best Practice Guidance**: Detects when low-level protocols (tcp, udp) are used with application-layer sticky buffers
  - **Common Patterns Detected**:
    - TCP protocol with TLS keywords (tls.sni, ja3.hash, ja4.hash) → Suggests using TLS protocol
    - TCP protocol with HTTP keywords (http.host, http.uri, http.method) → Suggests using HTTP protocol
    - UDP protocol with DNS keywords (dns.query, dns.answer) → Suggests using DNS protocol
  - **INFO Severity**: Categorized as informational (not warning/critical) since rules are syntactically valid and functionally correct
  - **Performance Benefits**: Using specific protocols allows Suricata to skip non-matching traffic earlier in the inspection pipeline
  - **Clarity Benefits**: Protocol field immediately indicates the traffic type being inspected
  - **Real-World Example**:
    - Current: `pass tcp any any -> any any (tls.sni; content:"amazon.com"; ...)`
    - Suggested: `pass tls any any -> any any (tls.sni; content:"amazon.com"; ...)`
    - Both rules match identical traffic, but TLS protocol is clearer and slightly more efficient
- **Comprehensive Coverage**: Detects mismatches for all major application protocols including TLS, HTTP, DNS, SSH, SMTP, FTP, SMB, DCERPC, and Kerberos
- **Smart Detection**: Only flags when app-layer protocol actually runs over the low-level protocol (e.g., won't suggest DNS for TCP since DNS typically uses UDP)
- **Clear Messaging**: Shows which keywords were detected and provides specific protocol recommendation
- **Report Integration**: New "ℹ️ PROTOCOL/KEYWORD MISMATCH (INFO)" section in both text and HTML analysis reports

### Technical Implementation
- **New Detection Method**: Added `check_protocol_keyword_mismatch()` method with comprehensive protocol-to-keyword mappings
- **Transport Layer Mapping**: Intelligent mapping of low-level carriers (TCP carries TLS/HTTP/SSH/SMTP/FTP/SMB/DCERPC, UDP carries DNS)
- **Keyword Detection**: Scans rule content for 30+ application-layer sticky buffer keywords across 9 protocols
- **Single Report Per Rule**: Only reports once per rule even if multiple app-layer keywords detected (focuses on primary protocol)
- **Analysis Integration**: Integrated into main `analyze_rule_conflicts()` pipeline as separate validation category

### User Impact
- **Educational Value**: Helps users learn Suricata best practices for protocol selection
- **Improved Rule Quality**: Encourages use of most specific protocol when application-layer keywords are present
- **Non-Intrusive**: INFO severity means these are suggestions, not errors requiring immediate action
- **Professional Standards**: Aligns with Suricata community recommendations for protocol selection

---

## Version 1.18.8 - November 16, 2025

### Flow Tester Bug Fix (v1.0.1)
- **Critical Rule Classification Fix**: Fixed flow tester incorrectly showing TLS traffic as BLOCKED when it should be ALLOWED
  - **Root Cause**: Rule classification logic in `rule_analyzer.py` was checking `flow:established` keyword before checking for application-layer sticky buffers like `tls.sni`
  - **Impact**: Rules with both `flow:established` and application-layer keywords (e.g., `tls.sni`) were incorrectly classified as `SIG_TYPE_PKT` (packet scope) instead of `SIG_TYPE_APPLAYER` (flow scope)
  - **Real-World Example**: 
    - Rule 1: `drop tcp any any -> any any (flow:established; sid:1000002;)` - Packet scope
    - Rule 2: `pass tls any any -> any any (tls.sni; content:"amazon.com"; nocase; flow:established; sid:1000001;)` - Should be flow scope
    - **Before Fix**: Both rules classified as packet scope → DROP wins → Traffic BLOCKED
    - **After Fix**: Rule 2 correctly classified as flow scope → PASS wins → Traffic ALLOWED
- **Enhanced Classification Logic**: Reordered rule type detection to check application-layer indicators first
  - **Priority 1**: Check for app-layer sticky buffers (tls.sni, http.host, etc.)
  - **Priority 2**: Check for app-layer protocols (tls, http, dns, etc.)
  - **Priority 3**: Check for app-layer-protocol keyword
  - **Priority 4**: Then check for flow:established (only forces packet-level if not app-layer)
- **Action Scope Implementation**: Flow tester now correctly implements Suricata's action scope model
  - **Packet Scope (SIG_TYPE_PKT)**: Rules with `flow:established` but no app-layer keywords
  - **Flow Scope (SIG_TYPE_APPLAYER)**: Rules with app-layer sticky buffers or protocols
  - **Precedence Rule**: Flow-scope actions take precedence over packet-scope actions
- **Technical Implementation**: Updated both `rule_analyzer.py` (classification) and `flow_tester.py` (action scope processing) for accurate Suricata behavior simulation

### User Impact
- **Accurate Test Results**: Flow tester now correctly predicts whether traffic will be allowed or blocked
- **AWS Compatibility**: Flow tester behavior better matches actual AWS Network Firewall processing

---

## Version 1.18.7 - November 15, 2025

### Major New Feature: Import Standard Rule Group
- **AWS Stateful Rule Group Import**: New capability to import existing AWS Network Firewall rule groups directly into the Suricata Generator
  - **File Menu Integration**: Added "Import Stateful Rule Group" menu option
  - **JSON Format Support**: Parses output from AWS CLI command `aws network-firewall describe-rule-group`
  - **Complete Data Import**: Imports rules, variables (IPSets and PortSets), and metadata from AWS rule groups
  - **Metadata Preservation**: Automatically adds comment header with original rule group attributes:
    - RuleGroupArn (AWS ARN for the rule group)
    - RuleGroupName (original AWS rule group name)
    - RuleGroupId (unique identifier)
    - Description (rule group description)
  - **Format Conversion**: Converts AWS 5-tuple format to Suricata format with proper field mappings:
    - ANY → any
    - FORWARD → ->
    - Action names to lowercase (DROP → drop, PASS → pass, REJECT → reject)
  - **Variable Import**: Automatically imports RuleVariables as $-prefixed variables in Variables tab
    - IPSets mapped to IP Set variables (e.g., HOME_NET → $HOME_NET)
    - PortSets mapped to Port Set variables (e.g., SSL → $SSL)
  - **Smart Validation**: Validates rule group type is STATEFUL before import (rejects STATELESS groups with clear error)
  - **SID Management**: Automatically detects and renumbers duplicate SIDs within imported JSON (if any exist)
  - **Preview Dialog**: Shows comprehensive import preview before execution:
    - Source file path
    - Rule group name and description
    - Rule count and variable count
    - First 10 rules preview
    - Warning about clearing current content
  - **Variable Preservation**: Enhanced auto_detect_variables() to preserve imported variables even when not used in rules
- **Seamless Round-Trip**: Enables export from AWS → import to Generator → edit → export back to AWS workflow
- **Force New File**: Import clears current rules and variables for clean starting state

### Technical Implementation
- **New Module**: Created `stateful_rule_importer.py` with StatefulRuleImporter class
- **JSON Parsing**: Comprehensive parser for AWS describe-rule-group output structure
  - Handles StatefulRules (5-tuple) format
  - Parses RuleOptions array into SuricataRule components
  - Converts RuleVariables (IPSets/PortSets) to application format
- **UI Integration**: Added menu item in ui_manager.py File menu
- **Main Application**: Initialized StatefulRuleImporter instance in suricata_generator.py
- **Variable Fix**: Modified auto_detect_variables() to preserve variables with definitions even if unused

### User Impact
- **Enhanced Flexibility**: Users can now import existing Stateful AWS rule groups for editing and enhancement
- **Simplified Workflow**: Import → Edit → Export round-trip enables iterative rule development
- **Metadata Tracking**: Original AWS Network Firewall rule group attributes preserved as comments for reference
- **No Breaking Changes**: All existing functionality preserved, new feature adds capability without disrupting current workflows

---

## Version 1.17.7 - November 13, 2025

### User Experience Enhancements

#### Keyboard Shortcuts Cheatsheet
- **Help > Keyboard Shortcuts Menu**: New comprehensive keyboard shortcuts reference dialog accessible from Help menu
  - **Organized by Category**: Shortcuts grouped into logical categories (File Operations, Editing & Selection, Navigation, Search, Rules Table Interactions)
  - **Professional Formatting**: Clean layout with monospace font for shortcuts and clear descriptions
  - **Quick Reference**: Easy-to-scan format showing all available keyboard shortcuts in one convenient location
  - **Context-Aware Tip**: Helpful reminder that most shortcuts require rules table focus to function
  - **Zero Learning Curve**: Instantly accessible help for both new and experienced users

#### Progress Bar for Bulk Operations
- **Visual Progress Feedback**: Added animated progress bars to long-running bulk operations for better user experience
  - **Domain Import Progress**: Shows real-time progress when importing domain lists with percentage complete and domain count (e.g., "45% (23/50 domains)")
  - **SID Renumbering Progress**: Displays progress during bulk SID management operations with percentage and rule count (e.g., "75% (150/200 rules)")
  - **Professional Appearance**: Modal progress dialogs with clean layout and status updates
  - **Prevents UI Freeze Concerns**: Clear visual indication that application is working during large operations
  - **Automatic Cleanup**: Progress dialogs automatically close upon completion

### Technical Implementation
- **Zero Dependencies**: Both features implemented using standard tkinter/ttk components already in use
- **UIManager Enhancement**: Added `show_keyboard_shortcuts()` method to UIManager class
- **DomainImporter Integration**: Enhanced `generate_domain_rules()` and `generate_domain_rules_with_pcre()` methods with progress bar parameters
- **SID Management Integration**: Added progress bar to `show_sid_management()` operation in main application
- **Non-Breaking Changes**: All existing functionality preserved - progress bars are additive enhancements
- **Performance Optimized**: Progress updates don't significantly slow down bulk operations

### User Impact
- **Improved Discoverability**: Keyboard shortcuts now easy to find and reference via Help menu
- **Enhanced User Confidence**: Progress indicators eliminate uncertainty during long-running operations
- **Professional Polish**: Features commonly expected in enterprise applications now included
- **Productivity Boost**: Users can learn shortcuts quickly and work more efficiently

---

## Version 1.16.7 - November 12, 2025

### Major Enhancement: Automatic Domain Consolidation
- **Intelligent Domain Consolidation**: New automatic domain consolidation feature significantly reduces rule count by grouping related domains
  - **Automatic Grouping**: Analyzes domain lists and consolidates domains sharing common parents (e.g., `subdomain1.example.com`, `subdomain2.example.com` → `example.com`)
  - **Rule Reduction**: Achieves up to 40-90% rule count reduction for typical domain lists with related domains
  - **Minimum Threshold**: Only consolidates when 2+ domains share a common parent, avoiding over-generalization
  - **Shortest Common Parent**: Consolidates to the least specific parent (e.g., all `*.example.com` subdomains → `example.com`)
  - **Same Rule Syntax**: Uses existing `dotprefix; content:".domain.com"` pattern (no syntax changes required)
  - **Default Behavior**: Consolidation automatically enabled when "Strict domain list" is unchecked
  - **Strict Mode Preserved**: When "Strict domain list" is checked, consolidation is disabled (maintains exact domain matching)
- **Enhanced Import Dialog Preview**: Smart consolidation preview shows detailed information before import
  - **Savings Display**: Shows exact rule count savings with consolidation (e.g., "Saves 70 rules!")
  - **Breakdown Statistics**: Displays number of consolidated groups vs individual domains
  - **Smart Details**: Shows first 3 consolidation groups with covered domains
  - **Large List Handling**: For lists with many consolidations, shows summary with note about details in post-import comment
  - **Consolidation Comment**: Adds informative comment header to imports showing consolidation summary
- **Mixed Domain Handling**: Intelligently handles domain lists with multiple unrelated organizations
  - **Example**: `['a.example.com', 'b.example.com', 'google.com']` → Creates `example.com` rule + `google.com` rule
  - **Preservation**: Keeps domains without siblings as individual rules (no unnecessary consolidation)
  - **PCRE Compatibility**: Consolidation runs independently of PCRE optimization
  - **History Tracking**: Consolidation details captured in change history
  - **Undo Support**: Full undo capability via Ctrl+Z

### Technical Implementation
- **Consolidation Algorithm**: New `consolidate_domains()` method with intelligent parent-child relationship analysis
  - **TLD Protection**: Avoids consolidating to bare TLDs (e.g., won't consolidate to just `.com`)
  - **Tree Analysis**: Builds domain hierarchy tree and finds optimal consolidation points
  - **Least Specific Strategy**: Processes parents from shortest to longest to maximize consolidation
- **Integration Points**: Enhanced `generate_domain_rules()` with consolidation pre-processing
- **UI Enhancement**: Updated `update_rule_count_preview()` with consolidation statistics and smart preview
- **Comment Generation**: Automatic summary comment generation showing consolidation details

### User Impact
- **Massive Rule Savings**: Reduces AWS Network Firewall capacity consumption for domain-heavy rule sets
- **Improved Performance**: Fewer rules mean faster rule evaluation
- **Simplified Management**: Fewer rules to maintain while providing identical security coverage
- **Zero Learning Curve**: Works automatically with existing workflows - no new concepts to learn
- **Transparency**: Clear preview and comments show exactly what consolidation occurred

---

## Version 1.15.7 - November 11, 2025

### Security Enhancement: Input Validation Integration
- **Security Validator Integration**: Integrated comprehensive security validation for all user text inputs with Suricata-appropriate security patterns
  - **Critical Security Fix**: The security_validator.py module was previously defined but never actually used in the application, leaving user inputs unvalidated
  - **Suricata-Aware Validation**: Security patterns carefully designed to allow legitimate Suricata syntax while blocking actual threats
    - **Allowed Suricata Syntax**: Semicolons (`;`), parentheses `()`, dollar signs (`$`), pipes (`|`), and other characters required for valid Suricata rules
    - **Blocked Patterns**: Only blocks clearly malicious patterns unlikely in legitimate rules:
      - **Script Tags**: `<script>`, `<?php>`, `<%...%>` tags
      - **Control Characters**: Null bytes and non-printable characters (allows tabs, newlines, carriage returns)
    - **AWS-Compliant Length Limits**: Updated to match AWS Network Firewall quotas (8,000 chars for messages/content/comments, allowing headroom within AWS's 8,192 character rule limit)
    - **False Positive Prevention**: Validation patterns tested to ensure legitimate Suricata rule content is never blocked
  - **Four Validation Points**: Security checks applied at all critical input locations:
    - Rule editing via bottom editor panel (`save_rule_changes()`)
    - New rule insertion from editor (`insert_new_rule_from_editor()`)
    - Comment insertion dialog (`insert_comment()`)
    - Rule edit dialog OK button (`show_edit_rule_dialog()`)
  - **User-Friendly Errors**: Clear "Security Validation Error" messages if dangerous input detected
  - **Legitimate Input Preserved**: Suricata-specific syntax (keywords, operators, special chars) not blocked
  - **Zero Functionality Impact**: All existing features work exactly as before with added security layer

### Technical Implementation
- **Import Integration**: Added security_validator import to main application with `validate_rule_input()` convenience function
- **Pre-Save Validation**: All validation occurs before data is saved or state is modified
- **Error Flow**: Validation failures return early with clear error messages, preventing malicious data from entering the system
- **Comprehensive Coverage**: Protects against OWASP Top 10 injection vulnerabilities

### User Impact
- **Maintained Usability**: Security checks are transparent to users entering legitimate Suricata rule content
- **Professional Quality**: Security validation matches enterprise security application standards

---

## Version 1.15.6 - November 11, 2025

### Bug Fix: Search Results Visual Highlighting
- **Search Highlighting Restoration**: Fixed issue where search results were not displaying yellow background highlighting
  - **Root Cause**: Tree selection highlight was overriding the yellow background color applied to matched search results
  - **Impact**: Users could not see visual indication of which rule matched their search term, making search navigation confusing
  - **Solution**: Modified `highlight_search_result()` method to clear tree selection before applying yellow highlight, using focus instead of selection for visibility
  - **User Experience**: Search results now properly display with yellow (#FFFF00) background highlighting as specified in release documentation
  - **Navigation**: Users can navigate search results with F3 (next match) and Escape (close search) while seeing clear yellow highlighting on current match

### Technical Implementation
- Updated `search_manager.py` to remove `selection_set()` call that was causing selection highlight to override yellow background
- Implemented `selection_remove()` before applying search_highlight tag to ensure yellow background is visible
- Maintained keyboard navigation functionality using `focus()` and `see()` without requiring selection

### User Impact
- **Visual Clarity**: Search matches now clearly visible with yellow highlighting
- **Enhanced Usability**: Improved search experience with proper visual feedback for current match location

---

## Version 1.15.5 - November 10, 2025

### Domain Import Feature Enhancement
- **Strict Domain List for Single Domain Rules**: Extended "Strict domain list" checkbox functionality to the "Insert Domain Allow Rule" button for consistent domain matching control
  - **Feature Parity**: Single domain insertion now supports same strict matching option as bulk domain import
  - **Side-by-Side Layout**: "Strict domain list" checkbox positioned next to "Alert on pass" for compact, organized interface
  - **Default Behavior**: Checkbox defaults to unchecked (subdomain matching) maintaining consistency with bulk import
  - **Tooltip Documentation**: Hover tooltip explains: "Matches only exact domain (no subdomains) using startswith/endswith keywords"
  - **Dynamic Info Text**: Real-time preview updates showing:
    - Rule count (2 or 4 based on "Alert on pass" setting)
    - Domain matching behavior: "(allows *.example.com)" or "(exact match only: example.com)"
  - **Accurate Success Messages**: Completion dialog now shows correct number of rules created (2 or 4)

### Technical Implementation
- Enhanced `insert_domain_rule()` dialog in `domain_importer.py` with strict domain checkbox and logic
- Integrated `strict_domain` parameter into single domain rule generation path
