# Release Notes

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
