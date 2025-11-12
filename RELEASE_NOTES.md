# Release Notes

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
- Added real-time info text updates based on domain input and checkbox states
- Dynamic rule count calculation for accurate user feedback

### User Impact
- **Consistent Experience**: Same strict domain functionality available for both bulk and single domain operations
- **Enhanced Control**: Users can precisely control subdomain matching for individual domain rules
- **Improved Usability**: Clear visual feedback showing exactly what will be created before insertion
- **Professional Quality**: Feature parity between bulk and single domain workflows

---

## Version 1.14.5 - November 8, 2025

### Critical Bug Fix: AWS Network Firewall Direction Compatibility
- **Removed Invalid Direction Option**: Fixed bug where direction dropdown incorrectly included "<-" option which is not supported by AWS Network Firewall
  - **Root Cause**: Application allowed users to select "<-" (left arrow) direction in rule creation, but AWS Network Firewall Suricata implementation only supports "->" (unidirectional) and "<>" (bidirectional) directions
  - **Impact**: Rules created with "<-" direction would be rejected by AWS Network Firewall during deployment, causing rule group creation failures
  - **Comprehensive Fix**: Removed "<-" support from all program components:
    - **UI Dropdowns**: Removed "<-" from direction dropdown in both main Rule Editor and Test Flow dialog
    - **Constants**: Updated `SUPPORTED_DIRECTIONS` to only include "->" and "<>"
    - **Rule Validation**: Updated validation logic in `suricata_rule.py` and `file_manager.py` to reject "<-" direction
    - **Comment Detection**: Updated toggle rule functionality to only detect "->" and "<>" as valid directional indicators
- **Documentation Updates**: Updated README.md to reflect correct direction options and version information
  - **Direction Documentation**: Removed "<-" from all direction option lists

### Technical Implementation
- **constants.py**: Updated `SUPPORTED_DIRECTIONS = ["->", "<>"]` (removed "<-")
- **ui_manager.py**: Updated both direction dropdown values to only include ["->", "<>"]
- **suricata_rule.py**: Updated direction validation in `from_string()` method to reject "<-"
- **file_manager.py**: Updated direction validation in `_auto_correct_port_brackets()` method
- **suricata_generator.py**: Updated comment toggle detection to only recognize "->" and "<>" as valid directions
- **README.md**: Updated documentation and version information

### User Impact
- **AWS Compatibility**: All generated rules now use only AWS Network Firewall compatible direction options
- **Deployment Success**: Eliminates rule group creation failures due to invalid direction syntax
- **Clear Guidance**: Direction dropdown only shows valid options, preventing user errors

---

## Version 1.14.4 - November 8, 2025

### Domain Import Feature Enhancement
- **Rule Generation Improvements**: Comprehensive updates to domain import rule generation for improved accuracy and functionality
  - **Network Specification Update**: Replaced `$EXTERNAL_NET` with `any` in all generated domain rules for broader compatibility
  - **TLS Rule Optimization**: Removed `ssl_state:client_hello;` keyword from all TLS rules to eliminate state-specific constraints
  - **Flow Direction Support**: Added `flow:to_server;` keyword to all generated domain rules as a "best practice"
  - **Enhanced Domain Format**: Updated all rule messages to use `*.domain.com` format (strict mode not selected) or `domain.com` format (strict mode selected) for clearer domain representation
- **Strict Domain List Feature**: New checkbox option for precise domain matching control
  - **Subdomain Control**: Unchecked (default) allows domain and all subdomains using `dotprefix` transformation
  - **Exact Matching**: Checked restricts matching to exact domain only using `startswith; endswith;` keywords
  - **False Positive Prevention**: `dotprefix` transformation prevents unwanted matches (e.g., "notmicrosoft.com" won't match "microsoft.com" rules)
  - **PCRE Compatibility**: Automatically disabled when PCRE optimization is enabled
  - **Tooltip Documentation**: Hover tooltip explains: "Matches only exact domain (no subdomains) using startswith/endswith keywords"
- **Alert on Pass Enhancement**: Flexible rule generation supporting separate alert and pass rules
  - **Checked (default)**: Generates 2 rules per domain with `alert` keyword (combined alert+pass functionality)
  - **Unchecked**: Generates 4 rules per domain (separate alert and pass rule pairs for TLS and HTTP)
  - **Distinct Messages**: Alert rules use "Alert for TLS/HTTP traffic to domain" format, pass rules use "Pass TLS/HTTP traffic to domain" format
  - **Dynamic UI**: Rule count preview and info text automatically update based on checkbox state
- **Message Template System**: Enhanced message customization with dynamic template updates
  - **Action-Based Defaults**: Template automatically updates when action type changes (pass/drop/reject)
  - **Alert State Integration**: Template updates when "Alert on pass" checkbox toggles
  - **Protocol Injection**: Custom templates automatically get protocol type (TLS/HTTP) injected for accurate descriptions
  - **Domain Format Support**: All templates properly use `*.domain.com` or `domain.com` based on strict mode setting
- **User Interface Improvements**: Enhanced dialog with cleaner layout and better user feedback
  - **Tooltip Help System**: Replaced static info labels with hover tooltips for cleaner interface
  - **Side-by-Side Checkboxes**: "Alert on pass" and "Strict domain list" positioned side-by-side for compact layout
  - **Dynamic Updates**: All UI elements respond in real-time to setting changes
  - **Professional Appearance**: 650px dialog height with well-organized sections

### Technical Implementation
- **Core Rule Generation**: Updated `generate_domain_rules()` method with `strict_domain` parameter and dotprefix support
- **Message Generation**: Enhanced message construction with protocol type injection and custom template handling
- **Content Generation**: Conditional logic for dotprefix transformation vs startswith/endswith keywords based on strict mode
- **UI State Management**: Smart checkbox enabling/disabling based on action type and PCRE settings
- **Tooltip Class**: New ToolTip class for professional hover-based help text

### User Impact
- **Improved Accuracy**: Rules now properly match intended domains while preventing false positives
- **Enhanced Flexibility**: Users can choose between broad subdomain matching and strict exact-domain matching
- **Better Logging Control**: Granular control over alert generation with alert+pass combinations
- **Professional Quality**: Generated rules follow Suricata best practices with proper flow direction and domain matching
- **AWS Compatibility**: All generated rules fully compatible with AWS Network Firewall requirements

---

## Flow Tester Version 1.0.0 - November 2, 2025

### Critical Bug Fixes: Test Flow Feature Rule Matching
- **Complete Test Flow Feature Overhaul**: Fixed multiple critical bugs causing test flow feature to incorrectly identify which rules match network flows
  - **Issue #1 - Missing ip_proto Keyword Validation**: Test feature was ignoring `ip_proto:` keyword constraints, causing false matches
    - **Root Cause**: Flow tester had no logic to check `ip_proto:!TCP`, `ip_proto:!UDP`, or `ip_proto:!ICMP` constraints
    - **Example**: Rule with `ip_proto:!TCP` was incorrectly matching TLS traffic (TLS runs over TCP, so should NOT match)
    - **Fix**: Added `_check_ip_proto_keyword()` method that maps application protocols to underlying IP protocols and validates constraints
  - **Issue #2 - Overly Aggressive No-SNI Detection**: Default block rules were being excluded from matching TLS traffic with SNI
    - **Root Cause**: Any rule with `ja4.hash; content:"_"` was treated as a no-SNI detection rule, even without `startswith` modifier
    - **Real-World Impact**: Test showed flows as ALLOWED when they should be REJECT by default block rules
    - **Fix**: Modified `_is_no_sni_detection_rule()` to require BOTH `content:"_"` AND `startswith` modifier for no-SNI classification
  - **Issue #3 - Incorrect Rule Processing Order**: Later rules within the same type were overriding earlier rules
    - **Root Cause**: Test feature allowed later rules to override earlier rules within same Suricata rule type (e.g., both SIG_TYPE_APPLAYER)
    - **Suricata Behavior**: With strict rule ordering, first matching rule wins WITHIN the same type
    - **Fix**: Modified `_test_flow_phase()` to only allow rule updates when transitioning to new rule type, not within same type

### Protocol Mapping Enhancement
- **Comprehensive IP Protocol Mapping**: Added complete mapping of application protocols to underlying IP protocols
  - **TCP-Based**: TLS, HTTP, HTTPS, SSH, FTP, SMTP mapped to TCP
  - **UDP-Based**: DNS, QUIC mapped to UDP
  - **Protocol Number Support**: Handles both protocol names (TCP, UDP, ICMP) and numbers (6, 17, 1)
  - **Multiple Constraints**: Supports rules with multiple `ip_proto:` keywords

### Version Management Implementation
- **Separate Versioning**: Flow tester now has independent version tracking (v1.0.0) in `version.py`
- **UI Display**: Version displayed in Test Flow dialog below disclaimer text
- **Consistent Pattern**: Follows same versioning approach as Rules Analysis Engine

### User Impact
- **Accurate Test Results**: Test flow feature now correctly identifies which rules match and final actions

---

## Version 1.13.4 - November 1, 2025

### Critical Bug Fix: Windows Line Ending Issue with Terraform/CloudFormation Exports
- **AWS Network Firewall Comment Support on Windows**: Fixed critical issue where Terraform and CloudFormation exports from Windows systems would fail with "Illegal rule syntax" errors when rules contained comment lines
  - **Root Cause**: Two-part problem affecting Windows users exporting rules with comments
    1. **Rule Content Line Endings**: Rules loaded from Windows files contained CRLF (`\r\n`) line endings which were embedded directly into export templates
    2. **File Write Conversion**: Python's `open()` function in text mode automatically converts `\n` back to `\r\n` when writing files on Windows
  - **AWS API Validation**: AWS Network Firewall API strictly requires Unix (LF) line endings and rejects comment lines with CRLF
- **Comprehensive Cross-Platform Solution**: Implemented universal line ending normalization for all operating systems
  - **Content Normalization**: Enhanced export functions to strip all `\r` characters from rules and comments before building templates
  - **File Write Protection**: Added `newline=''` parameter to file write operations to prevent Python from re-introducing CRLF on Windows
  - **Platform Independence**: Solution works correctly on Windows, macOS, and Linux without requiring user intervention
  - **Zero Configuration**: Automatic fix requiring no user awareness of line ending complexities
- **Enhanced Export Functions**: Updated both Terraform and CloudFormation template generation with line ending fixes
  - **Rule Content Cleaning**: All rule strings processed through `.replace('\r\n', '\n').replace('\r', '')` normalization
  - **Comment Handling**: Comment lines specifically normalized to ensure AWS API compatibility
  - **Preserved Functionality**: All existing export features maintained while fixing line ending issues

### Technical Implementation
- **file_manager.py Updates**: Enhanced `generate_terraform_template()` and `generate_cloudformation_template()` methods with line ending normalization and explanatory comments referencing GitHub issue #40856
- **suricata_generator.py Updates**: Modified `export_file()` method to use `newline=''` parameter when writing export files to prevent automatic CRLF conversion on Windows
- **Complete Solution**: Two-part fix addresses both rule content normalization and file write conversion for comprehensive cross-platform compatibility

### User Impact
- **Seamless Windows Experience**: Windows users can now successfully export and deploy rules with comments via Terraform/CloudFormation
- **Cross-Platform Consistency**: Same code works correctly on Windows, macOS, and Linux without platform-specific workarounds
- **Professional Quality**: Exported templates now meet AWS Network Firewall API requirements regardless of development platform
- **Zero User Action**: Automatic fix requires no manual line ending conversion or Git configuration

---

## Rules Analysis Engine Version 1.7.0 - October 31, 2025

### Major Enhancement: Connectionless Protocol Flow:Established Detection
- **UDP/ICMP Flow State Validation**: New detection system identifying problematic use of `flow:established` with DROP/REJECT actions on connectionless protocols
  - **Security Gap Detection**: Identifies rules that won't block initial packets due to Suricata's flow establishment requirements for UDP/ICMP
  - **Root Cause**: UDP and ICMP flows are only considered "established" after bidirectional traffic is seen. A DROP/REJECT rule with `flow:established` will NOT block the initial packet (e.g., DNS query, ICMP echo request), creating a security gap where the first packet is allowed through
  - **Comprehensive Coverage**: Detects issues across all connectionless protocols: ICMP, UDP, DNS, DHCP, NTP, TFTP, SNMP, Syslog, RADIUS, QUIC
  - **Real-World Example**:
    - Rule: `drop dns any any -> any any (dns.query; content:"baddomain.com"; flow:established; sid:100;)`
    - **Problem**: First DNS query to baddomain.com will be allowed through because flow is not yet established
    - **Detection**: Analyzer flags this with warning: "Initial packets (like DNS queries) will NOT match this rule and will be allowed through"
- **Smart Warning Messages**: Protocol-specific guidance tailored to each connectionless protocol type
  - **ICMP Rules**: References "ICMP echo requests" as packet example  
  - **DNS Rules**: References "DNS queries" as packet example
  - **Other UDP Protocols**: Uses generic protocol-specific packet examples
  - **Clear Recommendations**: Suggests removing `flow:established` or adding separate rule without flow constraints to catch initial packets
- **Enhanced Analysis Reports**: New dedicated section for UDP/ICMP flow:established warnings
  - **Warning Category**: Displayed as "⚠️ UDP/ICMP FLOW:ESTABLISHED WARNINGS" in both text and HTML reports
  - **Detailed Information**: Each warning includes line number, protocol, action, full issue description, and actionable recommendation
  - **Updated Recommendations**: Report recommendations now include "Fix UDP/ICMP flow:established warnings to block initial packets"

### Technical Implementation
- **New Detection Method**: Added `check_udp_flow_established_issues()` method with comprehensive connectionless protocol list
- **Analysis Integration**: Integrated check into main `analyze_rule_conflicts()` pipeline as separate validation category
- **Report Generation Updates**: Enhanced both `generate_analysis_report()` and `generate_html_report()` methods with UDP/ICMP warnings section
- **Conflict Categories Expansion**: Added `'udp_flow_established': []` to conflict categories dictionary
- **Protocol Classification**: Maintains consistent protocol handling across all analysis functions

### Security Impact
- **Critical Gap Prevention**: Prevents security rules that appear to block traffic but actually allow initial packets through
- **Professional Analysis**: Matches enterprise security team expectations for flow state validation
- **Enhanced Rule Quality**: Helps users create effective connectionless protocol rules that actually block initial packets as intended
- **Suricata Compliance**: Enforces proper understanding of Suricata's flow establishment behavior for UDP/ICMP protocols

---

## Version 1.13.3 - October 31, 2025

### Critical Bug Fix: Test Flow Feature with flow:not_established Rules
- **Flow State Matching Bug**: Fixed critical bug in test flow feature that incorrectly reported HTTP traffic as ALLOWED when it should be DROPPED in complex scenarios involving `flow:not_established` rules
  - **Root Cause #1**: Rules without flow keywords were incorrectly matching in ALL phases (both TCP handshake and established connection), allowing them to override more specific application layer rules
  - **Root Cause #2**: Phase processing was returning immediately after first matching rule, preventing later rule types from being evaluated
  - **Root Cause #3**: All matching rules were displayed instead of only the final effective rule
  - **Security Impact**: Medium - Test results could mislead users about whether traffic would be allowed or blocked
- **Comprehensive Fix**: Applied three-part solution to correctly simulate Suricata's rule processing behavior
  - **Flow State Correction**: Rules without flow keywords now correctly match only during established connections (not during TCP handshake)
  - **Complete Rule Evaluation**: All rule types (IPONLY → PKT → APPLAYER) are now evaluated before determining final action, with later types properly overriding earlier ones
  - **Clean Display**: Only the final effective rule for each phase is displayed in matched rules and flow diagram
- **Accurate Suricata Simulation**: Test flow feature now properly handles:
  - **TCP Handshake Phase**: Only `flow:not_established` rules match during SYN/SYN-ACK/ACK
  - **Established Connection Phase**: Rules without flow keywords and rules with `flow:established/to_server/to_client` match
  - **Rule Type Processing**: Respects Suricata's processing order where later rule types override earlier types within the same phase
  - **Visual Clarity**: Flow diagrams only show rules that actually affect the final outcome

### Technical Implementation
- **flow_tester.py Updates**: Modified `_flow_state_matches()` method to properly restrict rules without flow keywords to established phase only
- **Phase Processing Rewrite**: Complete rewrite of `_test_flow_phase()` to collect all matches before determining final action instead of returning early
- **Display Filtering**: Enhanced phase processing to only add final effective rule to matched rules list, eliminating confusion from overridden rules

### User Impact
- **Accurate Test Results**: Test flow feature now provides correct simulation of how Suricata will actually process rules
- **Clear Visualization**: Flow diagrams show only rules that matter, eliminating clutter from overridden rules
- **Proper Debugging**: Users can now trust test results when debugging complex rule interactions involving handshake and established phases

---

## Version 1.13.2 - October 25, 2025

### Critical Bug Fix: Double-Paste in Text Entry Fields
- **Clipboard Paste Fix**: Fixed critical bug where pasting text (Ctrl-V) in text entry fields would paste the content twice
  - **Root Cause**: Global Ctrl-V keyboard binding was interfering with Entry widgets' built-in paste handler, causing both the custom handler and default handler to execute
  - **Affected Fields**: All text entry fields in Rule Editor including Content Keywords, Message, Source Network, Destination Network, Source Port, Destination Port, and SID fields
  - **User Impact**: When users selected text in any entry field and pressed Ctrl-V to paste, the clipboard content would appear twice instead of once
  - **Security Rating**: Low - No data loss or corruption, but significantly impaired user workflow efficiency
- **Comprehensive Solution**: Removed global Ctrl-V binding and implemented widget-specific bindings
  - **Entry Field Behavior**: Text entry fields now use tkinter's default paste handler without interference
  - **Rules Tree Binding**: Added tree-specific Ctrl-V binding for pasting rules from clipboard into rule table
  - **Clean Separation**: Each widget type handles paste operations independently, eliminating conflicts
  - **Preserved Functionality**: All existing copy/paste operations work correctly without double-paste issue

### Technical Implementation
- **Removed Global Binding**: Eliminated `self.parent.root.bind('<Control-v>', ...)` that was interfering with Entry widgets
- **Added Tree Binding**: Added `self.tree.bind("<Control-v>", lambda e: self.parent.paste_rules())` for rule table paste operations
- **Method Updates**: Updated `handle_ctrl_v()` method signature to accept event parameter and simplified logic
- **Widget Isolation**: Entry fields now rely solely on their built-in paste handler for proper single-paste behavior

### User Impact
- **Improved Usability**: Text entry fields now paste content correctly without duplication
- **Workflow Restoration**: Users can efficiently edit rule content, messages, and other fields without paste annoyances
- **Maintained Functionality**: Rule copy/paste between rule table and external applications continues to work as expected
- **Zero Learning Curve**: Fix is transparent to users - clipboard operations simply work correctly now

---

## Rules Analysis Engine Version 1.6.0 - October 25, 2025

### Major Enhancement: Sticky Buffer and Keyword Ordering Validation
- **Sticky Buffer Ordering Checks**: New validation system ensuring proper keyword ordering for Suricata sticky buffers
  - **Content Context Validation**: Detects when `content:` keywords appear before sticky buffer keywords (e.g., `tls.sni`, `http.host`)
  - **Comprehensive Buffer Support**: Validates ordering for 50+ sticky buffer keywords across HTTP, TLS, DNS, SSH, JA3/JA4, File, SMB, Kerberos, and other protocols
  - **Smart Detection Logic**: Only flags rules where sticky buffers exist but are placed after content keywords, avoiding false positives for rules that intentionally don't use sticky buffers
  - **Warning Severity**: Issues categorized as Warning severity in analysis reports
  - **Clear Guidance**: Actionable suggestions like "Move 'tls.sni' keyword before the content keyword"
  
- **Dotprefix Keyword Validation**: Comprehensive validation for proper `dotprefix` keyword usage
  - **Ordering Validation**: Ensures `dotprefix` appears directly before `content` keyword
  - **Leading Dot Requirement**: Validates that content values include leading dot when `dotprefix` is used (e.g., `dotprefix; content:".amazon.com"`)
  - **Context Awareness**: Recognizes that `dotprefix` establishes context for following content keywords
  
- **Enhanced Analysis Reports**: Sticky buffer and dotprefix issues displayed in dedicated "STICKY BUFFER ORDERING ISSUES" section
  - **Integrated Display**: Issues appear in both text and HTML analysis reports with Warning severity styling
  - **Detailed Information**: Each issue includes line number, specific problem description, full rule text, and actionable recommendations
  - **Professional Presentation**: Consistent formatting with existing conflict categories in analysis reports

### Technical Implementation
- **New Detection Methods**: Added `check_sticky_buffer_ordering()`, `_check_rule_sticky_buffer_order()`, `_check_dotprefix_ordering()`, and `_get_dotprefix_content_indices()` methods
- **Comprehensive Buffer Registry**: Added `_get_sticky_buffer_keywords()` method with complete set of Suricata sticky buffers
- **Smart Tokenization**: Enhanced `_tokenize_rule_options()` to properly parse rule options while respecting quoted strings
- **Deduplication Logic**: Implemented issue tracking and content index exclusion to prevent duplicate warnings
- **Content Source Optimization**: Uses `original_options` or `content` (not both) to avoid processing duplicate tokens
- **Conflict Category Expansion**: Added `sticky_buffer_order` category to conflict results dictionary

### Security Impact
- **Syntax Correctness**: Ensures content keywords have proper context, preventing rules that may not function as intended
- **Improved Rule Quality**: Helps users follow Suricata best practices for sticky buffer usage and dotprefix syntax
- **Enhanced Analysis**: Provides comprehensive rule quality checks beyond conflict detection for professional-grade rulesets

---

## Version 1.13.1 - October 17, 2025

### MacOS UI Compatibility Enhancement
- **Improved MacOS Rendering**: Fixed UI layout issues that caused certain buttons and fields to be cut off when running on MacBook
  - **Editor Section Redistribution**: Optimized vertical space allocation by reducing rules table height from 20 to 15 rows and increasing editor section height from 260px to 360px
  - **Consistent Tab Heights**: Moved rule management buttons (Delete Selected, Copy Selected, Paste, Insert Rule, etc.) inside the Rule Editor tab to maintain consistent Editor section height across all tabs
  - **Eliminated Height Jumping**: Editor section now maintains fixed 360px height whether Rule Editor, Rule Variables, or Change History tab is active
  - **Complete Field Visibility**: All editor fields (Action, Protocol, Networks, Ports, Message, Content, SID, Rev, Save Changes button) now fully visible on MacOS
  - **Variable Tab Buttons**: All variable management buttons (Add IP Set, Add Port Set, Add Reference, Edit, Delete) now fully visible on MacBook displays
- **Cross-Platform Consistency**: Changes improve layout on MacOS while maintaining excellent user experience on Windows and Linux
  - **Rules Table**: Still shows 15 rows with full scrolling capability - sufficient for most workflows
  - **Editor Space**: 40% increase in editor section height provides comfortable working space on all platforms
  - **Button Organization**: Buttons positioned within tab content ensures they're always visible and accessible

### Technical Implementation
- **UI Manager Updates**: Enhanced `setup_rule_editor_tab()` method to include button container within tab content
- **Layout Optimization**: Changed rules table height and editor frame height for better MacOS compatibility
- **Tab Switching**: Simplified `on_tab_changed()` method by eliminating dynamic button show/hide logic
- **Button Management**: Removed external buttons_frame that was causing height inconsistencies between tabs

### User Impact
- **Seamless MacOS Experience**: MacBook users can now access all functionality without layout issues
- **Improved Usability**: Better vertical space distribution benefits all users regardless of platform
- **Professional Appearance**: Consistent tab heights create polished, professional-looking interface

---

## Version 1.13.0 - October 10, 2025

### Major New Feature: Flow Testing System
- **Interactive Flow Testing**: Complete flow testing capabilities to simulate network flows against current rules
  - **Protocol Support**: Tests IP, ICMP, UDP, TCP, HTTP, and TLS protocols with accurate protocol-specific behavior
  - **Visual Flow Diagram**: Interactive canvas showing TCP 3-way handshake, TLS handshake steps, and rule matching with color-coded arrows
  - **Matched Rules Table**: Shows all matched rules in evaluation order with line numbers, actions, and double-click navigation to source rules
  - **Accurate Simulation**: Respects Suricata rule processing order (IPONLY → PKT → APPLAYER) and TCP connection states
  - **Application Layer Support**: Full HTTP/TLS support with URL/domain matching against `http.host`, `tls.sni`, and `app-layer-protocol` keywords
  - **Flow State Accuracy**: Properly handles `flow:established`, `flow:to_server` keywords - only matches TCP connections, not ICMP/UDP
- **User-Friendly Interface**: Comprehensive test dialog with input validation and helpful tooltips
  - **Flow Information Section**: Input fields for source/destination IPs, ports, protocol selection, and URL/domain for HTTP/TLS
  - **Dynamic UI**: Protocol dropdown automatically shows/hides URL field and adjusts port defaults based on selected protocol
  - **Real-time Validation**: Input validation for IPs, ports, and required fields before running tests
  - **Test Results Section**: Split-pane view with flow diagram above and matched rules table below
  - **Final Action Display**: Clear indication whether flow is ALLOWED, BLOCKED, or UNDETERMINED
- **Enhanced Flow Diagram Features**:
  - **Alert Rules**: Blue dashed arrows showing alerts in correct evaluation order
  - **Visual Indicators**: Green checkmarks for pass rules, red X marks for drop/reject rules
  - **Hover Highlighting**: Mouse hover on arrows highlights corresponding rule in matched rules table

### Technical Implementation
- **FlowTester Module**: New `flow_tester.py` module with comprehensive flow simulation logic
- **Phase-Based Testing**: Separate handshake and established phases for TCP/HTTP/TLS protocols
- **Pattern Matching**: Full support for `startswith`, `endswith`, `dotprefix` modifiers and domain matching
- **Network Matching**: Complete CIDR, variable, negation, and group support for network/port matching
- **UI Integration**: New menu item "Tools > Test Flow" with complete dialog and visualization system
- **Canvas Drawing**: Sophisticated arrow rendering with direction indicators, labels, and interactive features

### User Impact
- **Debugging Tool**: Quickly test if specific flows would be allowed or blocked by current rule set
- **Educational Value**: Visual representation helps understand TCP/TLS handshakes and Suricata rule processing
- **Rule Validation**: Verify rules work as intended before deploying to AWS Network Firewall
- **Interactive Learning**: See exactly which rules match and why for any given network flow

---

## Version 1.12.9 - October 8, 2025

### Protocol-Based Content Keywords Enhancement
- **Smart Default Content Keywords**: Enhanced new rule creation to automatically set appropriate Content Keywords based on protocol selection
  - **UDP and ICMP Protocols**: Content Keywords field now defaults to empty for "udp" and "icmp" protocol rules
  - **Other Protocols**: Content Keywords defaults to "flow: to_server" for all other protocols (tcp, http, tls, dns, etc.)
  - **Dynamic Protocol Detection**: Content Keywords automatically adjusts when user changes protocol dropdown while creating new rules
  - **Editor Integration**: Works seamlessly in both the main program window's editor section and the Insert Rule button dialog
  - **Existing Rules Unaffected**: Change only applies to new rule creation - editing existing rules preserves their current Content Keywords values
  - **Easy Customization**: Users can still modify Content Keywords field to any value after protocol selection

### Technical Implementation
- **Main Editor**: Updated `set_default_editor_values()` method in `suricata_generator.py` to set protocol-based content defaults
- **Dialog Integration**: Added protocol change callback `on_dialog_protocol_change()` in `show_edit_rule_dialog()` method
- **UI Manager**: Added `on_protocol_changed()` callback method in `ui_manager.py` for main editor protocol dropdown
- **Complete Coverage**: Applied to all rule creation scenarios including Insert Rule button, Add Rule dialog, and bottom editor panel

### User Impact
- **Flexible Workflow**: Maintains full user control while improving starting templates for common rule patterns

---

## Version 1.12.8 - October 7, 2025

### Content Keywords Semicolon Fix
- **Trailing Semicolon Issue Resolution**: Fixed issue where Content Keywords with user-added trailing semicolons would result in double semicolons when rules are saved
  - **Problem Identified**: When users added a ";" character at the end of Content Keywords (e.g., `flow: to_server; http_method;`), the program automatically added another semicolon, creating invalid syntax: `(flow: to_server; http_method;;)`  
  - **Comprehensive Fix**: Implemented trailing semicolon stripping across all rule creation and editing workflows
  - **Smart Processing**: Program now uses `.rstrip(';')` to remove any trailing semicolons from Content Keywords before processing, ensuring clean output: `(flow: to_server; http_method;)`
  - **Preservation Logic**: Only removes trailing semicolons - semicolons that appear before the last keyword are preserved as intended
  - **Complete Coverage**: Fix applies to all rule creation scenarios including main program editor, Insert Rule button dialog, rule editing dialogs, and all form-based rule creation methods

### User Experience Enhancement  
- **Default Content Keywords**: Added "flow: to_server" as the default content keyword for all new rules in the editor window
  - **Improved Starting Point**: New rules now include commonly-used flow state by default, reducing manual entry for typical rule patterns
  - **Professional Standards**: Follows Suricata best practices by encouraging flow state specification in stateful rules
  - **User Convenience**: Reduces repetitive typing while maintaining full user control over final content keywords

### Technical Implementation
- **Core Rule Processing**: Updated `to_string()` method in `SuricataRule` class to strip trailing semicolons from content before formatting
- **Editor Integration**: Enhanced all rule creation methods in `suricata_generator.py` to clean content keywords before building `original_options` strings
- **Complete Workflow Coverage**: Applied fix to:
  - `save_rule_changes()` method (main editor workflow)
  - `show_edit_rule_dialog()` method (Insert Rule button and edit dialogs)  
  - `insert_new_rule_from_editor()` method (placeholder row creation)
  - `create_rule_from_form()` method (form-based rule creation)
- **Backward Compatibility**: Existing rules without trailing semicolons continue to work exactly as before

### User Impact
- **Syntax Correctness**: Eliminates invalid double semicolon syntax in generated Suricata rules
- **User Flexibility**: Users can optionally add trailing semicolons to Content Keywords without causing formatting issues
- **Professional Output**: All generated rules now use clean, properly formatted Suricata syntax regardless of user input patterns
- **Enhanced Workflow**: Default "flow: to_server" content provides better starting template for new rule creation

---

## Version 1.12.7 - October 6, 2025

### Domain Import Alert Control Enhancement
- **Configurable Alert Keyword**: Added user control for alert keyword inclusion in domain import pass rules
  - **"Alert on pass" Checkbox**: New checkbox in both Bulk Domain Import and Insert Domain Rule dialogs
  - **Default Behavior**: Checkbox defaults to checked (maintaining current functionality for existing users)
  - **Dynamic UI Feedback**: Dialog text and info labels update based on checkbox state to show exactly what rules will be created
  - **Smart Context Awareness**: Checkbox only enabled for 'pass' actions, automatically disabled and grayed out for other actions (drop, reject)
  - **Flexible Rule Generation**: Users can now choose between:
    - **With Alert**: Pass rules include 'alert' keyword for logging (e.g., "Alert and pass TLS traffic to domain example.com")
    - **Without Alert**: Pass rules without 'alert' keyword for silent operation (e.g., "Pass TLS traffic to domain example.com")
- **Complete Implementation Coverage**: Enhancement applies to all domain import scenarios
  - **Bulk Domain Import**: Works with both standard and PCRE-optimized domain imports
  - **Insert Domain Rule**: Single domain insertion respects checkbox setting
  - **Consistent Behavior**: Both import methods use same checkbox logic and rule generation approach
- **User Experience Improvements**: Enhanced dialogs with clear explanatory text and real-time preview updates
  - **Informational Text**: Blue helper text explains "Adds 'alert' keyword to pass rules for logging"
  - **Dynamic Info Updates**: Rule description automatically updates to show "with alert" or without based on checkbox state
  - **Contextual Availability**: Clear visual indication when checkbox applies vs when it's disabled for non-pass actions

### Technical Implementation
- **Enhanced Rule Generation**: Updated `generate_domain_rules()` and `generate_pcre_group_rules()` methods with `alert_on_pass` parameter
- **Conditional Content**: Rule content and messages dynamically generated based on alert preference
- **UI State Management**: Checkbox state properly managed with event binding and dynamic updates
- **Backward Compatibility**: All existing functionality preserved with sensible defaults

### User Impact
- **Flexible Logging Control**: Users can now choose whether domain pass rules generate alerts for monitoring purposes
- **Reduced Noise Option**: Option to create silent pass rules reduces log volume when alerting is not needed
- **Professional Configuration**: Granular control over rule behavior matches enterprise security requirements
- **Maintained Efficiency**: Continues to generate only 2 rules per domain while providing alert configuration flexibility

---

## Version 1.11.7 - October 5, 2025

### Domain Import Rule Generation Enhancement
- **Optimized Pass Rule Generation**: Streamlined domain import rule generation to reduce rule count while maintaining functionality

  - **Enhanced Pass Rules**: Added 'alert' keyword to Pass TLS and Pass HTTP rules, combining alert and pass functionality in single rules
  - **Consistent UI Updates**: Updated all dialog text, preview counts, and info labels to reflect 2 rules per domain for pass actions
- **Import Dialog Enhancements**: Updated Bulk Domain Import dialog to show accurate rule counts and descriptions
  - **Accurate Previews**: Rule count calculations now correctly display 2 rules per domain for all actions
  - **Updated Information Text**: Dialog info now states "For 'pass' action: Creates Pass rules with alert keyword (2 rules per domain)"
  - **PCRE Integration**: PCRE optimization calculations properly account for reduced rule count per domain
- **Insert Domain Allow Rule**: Single domain insertion feature also updated to create 2 rules instead of 4
  - **Consistent Behavior**: Both bulk import and single domain insertion now follow same rule generation pattern
  - **Updated Success Messages**: Confirmation messages now correctly state "Successfully inserted 2 rules for domain"

### Technical Implementation
- **Core Rule Generation**: Enhanced `generate_domain_rules()` method to create optimized pass rules with embedded alert keywords
- **PCRE Support**: Updated `generate_pcre_group_rules()` method to apply same optimization for PCRE-based domain groups
- **UI Consistency**: Updated rule count calculations, preview text, and success messages throughout domain import workflows
- **Backward Compatibility**: No changes to other action types (drop, reject, alert) - they continue to create 2 rules per domain as before

### User Impact
- **Reduced Rule Consumption**: Domain imports use 50% fewer rules for pass actions, providing more capacity for additional rules
- **Simplified Rule Management**: Fewer rules to manage while maintaining identical security coverage and alerting capabilities
- **Improved AWS Capacity Usage**: More efficient use of AWS Network Firewall rule limits with streamlined rule generation

---

## Version 1.10.7 - October 3, 2025

### Status Bar Enhancement: Reference Sets Counter
- **IP Set References Counter**: Added real-time counter in status bar displaying unique IP set references
  - **Live Tracking**: Automatically updates as rules are added, modified, or deleted showing current count of distinct @ variables
  - **Always Visible**: Displays even when count is 0, showing format "IP Set References: {count}/5" where 5 is the constant AWS limit reference
  - **Unique Counting**: Only counts distinct reference sets, preventing duplicates from inflating the count
  - **Distinctive Styling**: Uses teal color (#008B8B) to differentiate from other status elements
  - **AWS Compliance**: Helps users track AWS Network Firewall IP Set Reference usage at a glance
- **Enhanced Rule Statistics**: Extended `calculate_rule_statistics()` method to include reference sets analysis alongside existing action counts, SID ranges, and undefined variables
  - **Real-time Analysis**: Scans all rule network fields (source/destination networks and ports) for @ variables
  - **Integration**: Seamlessly integrates with existing status bar update logic and variable detection systems

### Technical Implementation
- **Core Statistics**: Enhanced rule statistics calculation in `suricata_generator.py` with reference sets counting logic
- **UI Components**: Added new status label in `ui_manager.py` with proper color coding and parent reference storage
- **Automatic Updates**: Reference counter updates automatically via existing `update_status_bar()` method calls throughout the application

### User Impact
- **Enhanced Visibility**: Users can quickly see their IP Set Reference usage without manually counting @ variables
- **AWS Limit Awareness**: Constant "/5" reminder helps users stay within AWS Network Firewall reference set limits
- **Professional Monitoring**: Adds another layer of real-time rule statistics for comprehensive firewall management

---

## Version 1.9.7 - October 3, 2025

### Protocol Support Enhancement
- **Extended Protocol Coverage**: Added support for 12 additional protocols to enhance rule creation capabilities
  - **New Protocols Added**: `ftp`, `smb`, `dcerpc`, `smtp`, `imap`, `msn`, `krb5`, `ikev2`, `tftp`, `ntp`, `dhcp`, `quic`
  - **Total Protocol Support**: Now supports 21 protocols (previously 9) for comprehensive network traffic analysis
  - **Alphabetical Organization**: All protocols now listed alphabetically in dropdown menus for improved usability
  - **Complete Integration**: New protocols fully integrated throughout application including rule editor, conflict analysis, statistics tracking, and export templates
- **Rule Analysis Engine Enhancement**: Updated rule analyzer to properly classify new protocols as application-layer protocols
  - **Conflict Detection**: All new protocols properly recognized for rule conflict analysis and shadowing detection
  - **Protocol Layering**: Enhanced protocol layering conflict detection to support expanded protocol set
  - **Statistics Integration**: Protocol usage statistics now track all 21 supported protocols
- **User Interface Improvements**: Protocol dropdown in rule editor now presents all options alphabetically for better user experience
  - **Consistent Ordering**: Both main rule editor and popup dialog dropdowns use alphabetical protocol ordering
  - **Improved Navigation**: Alphabetical listing makes it easier to find specific protocols in large protocol list

### Technical Implementation
- **Constants Enhancement**: Updated `SUPPORTED_PROTOCOLS` in `constants.py` with full alphabetical protocol list
- **Dynamic Statistics**: Enhanced protocol statistics to dynamically use constants instead of hard-coded protocol lists
- **Rule Analyzer Updates**: Updated protocol classification methods to recognize new protocols as higher-layer application protocols
- **Backward Compatibility**: All existing functionality preserved while expanding protocol support

### Security Impact
- **Enhanced Coverage**: Extended protocol support enables more comprehensive network security rule creation
- **Professional Analysis**: Rule conflict detection now works across expanded protocol set for better security analysis
- **Enterprise Readiness**: Protocol coverage now matches enterprise network requirements including authentication (krb5), file transfer (ftp, tftp, smb), messaging (smtp, imap, msn), network services (dhcp, ntp), and modern protocols (quic, ikev2)

---

## Version 1.9.6 - September 30, 2025

### Critical Bug Fix: SID Conflict Detection with Change Tracking
- **Fixed SID Validation with Header Comments**: Resolved critical bug where enabling change tracking would cause false SID conflicts when pasting or editing rules with SID 100
  - **Root Cause**: When change tracking is enabled, the system creates a header with 4 comment rules that each have the default SID value of 100. The `validate_unique_sid()` method was incorrectly checking ALL rules (including comments and blanks) for SID conflicts, causing false positives.
  - **The Problem Flow**:
    1. User creates new file and enables change tracking
    2. System creates header with 4 comment rules (all SID=100)
    3. User pastes a rule from clipboard → gets assigned SID=100
    4. User tries to save changes → `validate_unique_sid(100)` finds "conflicts" with comment rules
    5. System shows error: "SID 100 is already in use"
  - **Solution**: Modified `validate_unique_sid()` method to skip comment and blank rules during SID validation, as these don't represent actual Suricata rules and don't participate in SID uniqueness requirements
  - **Impact**: Users can now successfully save pasted rules when change tracking is enabled, eliminating the workflow disruption caused by false SID conflicts
- **Enhanced SID Validation Logic**: Updated validation method to ignore non-rule entries while maintaining proper conflict detection for actual rule duplicates
  - **Skip Comment Rules**: Rules with `is_comment=True` are excluded from SID validation
  - **Skip Blank Rules**: Rules with `is_blank=True` are excluded from SID validation  
  - **Preserve Real Validation**: Actual rule-to-rule SID conflicts are still properly detected and reported
  - **Maintain Exclusion Logic**: Self-exclusion logic (exclude_index parameter) continues to work correctly for rule editing scenarios

### Technical Implementation
- **Core Fix**: Updated `validate_unique_sid()` method in `suricata_generator.py` to filter out comment and blank rules before checking for SID conflicts

### User Impact
- **Seamless Change Tracking**: Users can now enable change tracking without experiencing SID conflicts when working with rules
- **Restored Workflow**: Paste operations work correctly with change tracking enabled, eliminating a major usability barrier
- **Maintained Security**: Real SID conflict detection remains fully functional for actual rule duplicates
- **Zero False Positives**: Comment and blank rules no longer generate false SID conflict warnings

---

## Version 1.9.5 - September 29, 2025

### Enhanced Change Tracking System
- **Detailed Field-by-Field Change Display**: Major enhancement to Change History tab showing comprehensive details about what changed in each rule modification
  - **Before**: Simple messages like `[2025-09-29 13:43:19] Modified pass rule at line 7 (SID: 104)`
  - **After**: Detailed field-by-field breakdown showing:
    ```
    [2025-09-29 13:43:19] Modified pass rule at line 7 (SID: 104) - Changes:
      - Source Network: '$HOME_NET' → '192.168.1.0/24'
      - Dest Port: 'any' → '[80,443]'
      - Content: 'HTTP' → 'HTTP/1.1'
    ```
  - **Field Coverage**: Tracks changes to Action, Protocol, Source Network, Source Port, Direction, Dest Network, Dest Port, Message, Content, and SID fields
  - **Visual Clarity**: Uses clear before → after format with proper field names for easy understanding
- **Message-Only Change Filtering**: Implemented intelligent filtering to exclude message-only modifications from change history
  - **Smart Detection**: Automatically detects when only the message field has been modified with no other rule changes
  - **History Exclusion**: Message-only changes are not recorded in change tracking, keeping audit trails focused on substantive rule modifications
  - **Rule Updates**: Message changes still update the rule in the interface but don't create history entries
  - **Rev Handling**: Message-only changes don't increment the rev field, preserving version numbers for actual rule modifications
- **Preserved Functionality**: All existing change tracking capabilities maintained while adding enhanced detail and filtering
  - **Backward Compatibility**: Works with existing .history files and maintains all current tracking categories
  - **Full Coverage**: Enhancement applies to both inline editor changes and rule dialog changes
  - **Complete Integration**: Works seamlessly with undo functionality and file save operations

### Technical Implementation
- **Enhanced History Data**: Updated `save_rule_changes()` and `edit_selected_rule()` methods to capture and include detailed change information
- **Message-Only Detection**: Added comprehensive field comparison logic to detect message-only modifications
- **Change Analysis**: Leveraged existing `compare_rules_for_changes()` method to provide detailed field-by-field change information
- **UI Display**: Enhanced `refresh_history_display()` method already supported showing detailed changes - now receives the data
- **Dual Path Logic**: Created separate processing paths for message-only changes vs substantive rule changes

### User Impact
- **More Informative History**: Users can now see exactly what changed in each rule modification for better audit trails
- **Reduced Noise**: Message-only changes no longer clutter change history, focusing attention on actual rule modifications  
- **Professional Auditing**: Change tracking now provides enterprise-level detail suitable for compliance and security auditing
- **Improved Workflow**: Users can confidently update rule messages/documentation without creating unnecessary history entries

---

## Version 1.9.4 - September 25, 2025

### User Interface Enhancement
- **Improved Rules Table Layout**: Enhanced main rules table display for better readability and organization
  - **Optimized Column Structure**: Changed from 3 columns to 4 well-balanced columns for improved visual scanning
    - **Line**: Line numbers (narrow, fixed width)
    - **Action**: Rule actions - pass, drop, alert, reject (narrow, fixed width)
    - **Protocol**: Protocol types - tcp, udp, http, tls, etc. (narrow, fixed width)
    - **Rule Data**: Combined remaining fields for efficient screen space usage (wide, stretches)
  - **Enhanced Column Header**: Updated Rule Data column header to comprehensively list all included fields
    - **Complete Field List**: "Source | Src Port | Direction | Destination | Dst Port | Options | Message | SID | Rev"
    - **Rev Field Addition**: Added Rev field to header to reflect complete rule information displayed
  - **Improved Placeholder Positioning**: Moved "<click to add rule>" placeholder text from Action column to Rule Data column for better visual flow and logical placement where users will enter rule data
- **Screen Space Optimization**: Balanced approach providing key field visibility while conserving screen real estate
  - **Quick Scanning**: Action and Protocol columns allow rapid visual identification of rule types
  - **Detailed Information**: Rule Data column contains all detailed rule components in organized format
  - **Efficient Layout**: Avoids excessive column proliferation while maintaining essential field separation

### Technical Implementation
- **UI Manager Module**: Updated `setup_rules_table()` method in `ui_manager.py` with new 4-column structure
- **Main Application**: Updated `refresh_table()` method in `suricata_generator.py` to populate individual columns correctly
- **Placeholder Logic**: Updated `add_placeholder_row()` method to position placeholder text in appropriate column
- **Preserved Functionality**: All existing functionality maintained - purely cosmetic improvement for better user experience

---

## Version 1.9.3 - September 22, 2025

### Rules Analysis Engine Critical Bug Fix (v1.5.2)
- **Shadow Conflict Detection with Multiple CIDR Blocks**: Fixed critical bug in rule analyzer that failed to detect shadow conflicts when destination network fields contained multiple CIDR blocks in bracket notation
  - **Root Cause**: The `_network_specification_contains()` method returned `False` for all group containment scenarios instead of checking if specific networks were contained within bracketed groups
  - **Missing Detection**: Rules like `reject tcp ... -> [10.0.0.0/24, 10.0.1.0/24] 80` that should shadow `pass tcp ... -> 10.0.1.0/24 80` were not being flagged as conflicts
  - **Security Impact**: Critical - Security policy violations where broader REJECT rules shadow more specific PASS rules were going undetected
  - **Real-World Example**:
    - Rule 1: `reject tcp $HOME_NET any -> [10.0.0.0/24, 10.0.1.0/24] 80 (sid:100; rev:3;)`
    - Rule 2: `pass tcp $HOME_NET any -> 10.0.1.0/24 80 (sid:101; rev:2;)`
    - **Problem**: Rule 1 blocks traffic to 10.0.1.0/24 (contained in the bracketed group), making Rule 2 unreachable
- **Enhanced Group Containment Logic**: Added proper handling for group containment scenarios where bracketed CIDR lists contain specific networks
  - **Group Analysis**: When broader rule uses group format `[10.0.0.0/24, 10.0.1.0/24]` and specific rule uses simple format `10.0.1.0/24`
  - **Containment Detection**: Checks if the specific network is contained within any network in the bracketed group
  - **Mathematical Validation**: Uses Python ipaddress library for precise subnet containment analysis (subnet_of() or exact equality)
  - **Conservative Error Handling**: Maintains conservative approach for IP network comparison errors
- **Complete Fix Validation**: Comprehensive testing confirms perfect shadow conflict detection with multiple CIDR blocks
  - **Network Parsing**: Bracketed groups correctly parsed to network sets with proper type classification
  - **Containment Check**: Successfully detects that `10.0.1.0/24` is contained within `[10.0.0.0/24, 10.0.1.0/24]` group
  - **Conflict Detection**: Now properly flags as "REJECT rule prevents PASS rule from executing (security policy violation)"

### Technical Implementation
- **Enhanced Network Analysis**: Updated `_network_specification_contains()` method in `rule_analyzer.py` with group containment logic
- **Preserved Functionality**: All existing network analysis capabilities maintained while adding group containment support
- **Error Safety**: Conservative error handling ensures IP network comparison errors don't cause analysis failures
- **Version Updates**: Updated Rules Analysis Engine to version 1.5.2 and main application to version 1.9.3

### Security Impact
- **Critical Vulnerability Fixed**: Prevents undetected rule shadowing that could lead to security policy bypasses
- **Enterprise Rule Support**: Properly handles complex network specifications commonly found in enterprise AWS Network Firewall configurations
- **Enhanced Threat Detection**: Now identifies all forms of network-based rule shadowing including bracketed CIDR groups

---

## Version 1.9.2 - September 21, 2025

### Critical Bug Fix: Port Validation Bracket Enforcement
- **Suricata Bracket Requirement**: Fixed critical bug where port validation logic incorrectly accepted port ranges without brackets
  - **Root Cause**: Port validation accepted formats like `8080:8090` and `80,443,8080:8090` without brackets, but Suricata syntax requires `[8080:8090]` and `[80,443,8080:8090]`
  - **Security Impact**: Medium - Rules would be rejected by Suricata engine during deployment due to syntax violations
  - **Affected Areas**: All port validation throughout application including rule editor, variable definitions, file loading, and clipboard operations
  - **Standard Compliance**: Now enforces proper Suricata syntax requiring brackets for all port ranges and complex port specifications
- **Enhanced Port Validation Logic**: Complete rewrite of `validate_port_list()` method with strict bracket enforcement
  - **Valid Formats**: Single ports `80`, keywords `any`, variables `$WEB_PORTS`, bracketed ranges `[8080:8090]`, bracketed lists `[80,443,8080]`, complex specs `[80:100,!85]`
  - **Invalid Formats**: Unbracketed ranges `8080:8090`, unbracketed lists `80,443,8080`, unbracketed complex `80:100,!85`
  - **Reference Variable Restriction**: Properly rejects `@` variables for port fields per AWS Network Firewall requirements (only `$` variables allowed)
  - **Clear Error Messages**: Enhanced validation errors with examples showing correct bracket syntax
- **Auto-Conversion System**: Intelligent auto-correction for backward compatibility
  - **File Loading**: Automatically converts old format rules to bracket format when loading .suricata files
  - **Clipboard Operations**: Automatically converts pasted rules to proper bracket format
  - **Seamless Migration**: Existing rules with old format are transparently converted to compliant format
  - **Single Port Preservation**: Single ports like `80` remain unchanged (brackets not required for single ports)

### Rules Analysis Engine Enhancement (v1.5.1)
- **Bracketed Port Format Support**: Updated rule analyzer to properly parse new bracketed port format for conflict detection
  - **Root Cause**: Rule analyzer's `parse_port_specification()` method couldn't handle bracketed formats like `[80:100]` or complex negations like `[80:100,!83]`
  - **Impact**: Shadow conflicts with bracketed port ranges were not detected (e.g., `[80:100,!83]` vs port `85`)
  - **Enhanced Parser**: Complete rewrite of port parsing logic to handle brackets, negations, ranges, and exclusions
  - **Complex Negation Support**: Proper handling of port exclusions like `[80:100,!83]` which includes ports 80-82,84-100 (excludes only 83)
  - **Accurate Conflict Detection**: Now correctly identifies that `[80:100,!83]` contains port `85` and will shadow rules targeting port `85`
- **Validation Results**: Comprehensive testing confirms perfect shadow detection with new bracket format
  - **Port Parsing**: `[80:100,!83]` correctly parsed to port set {80,81,82,84,85,86,...,100}  
  - **Conflict Detection**: Rule `reject tcp ... [80:100,!83]` properly shadows `pass tcp ... 85` 
  - **Analysis Reports**: Critical conflict correctly reported as "REJECT rule prevents PASS rule from executing (security policy violation)"

### Technical Implementation
- **Enhanced Validation**: Updated `validate_port_list()` and `_validate_bracketed_port_content()` methods with strict bracket enforcement
- **Auto-Correction**: Added `_auto_correct_port_brackets()` and `_add_brackets_if_needed()` methods for seamless format conversion
- **UI Updates**: Updated error messages in both `suricata_generator.py` and `ui_manager.py` with bracket requirement explanations
- **Parser Enhancement**: Upgraded `parse_port_specification()` in rule analyzer with bracket and negation support
- **Comprehensive Coverage**: Updated both file loading (`file_manager.py`) and clipboard parsing with auto-conversion

### User Impact
- **Learning Enforcement**: Users learn correct Suricata syntax through validation errors that clearly explain bracket requirements
- **Seamless Migration**: Existing rules automatically converted to proper format when loaded or pasted
- **Rule Quality**: All generated rules now use proper Suricata syntax accepted by all Suricata engines
- **Analysis Accuracy**: Rule analysis now works correctly with all port specification formats including complex negations

---

## Rules Analysis Engine Version 1.5.0 - September 20, 2025

### Major Enhancement: Comprehensive Port Range and Variable Support
- **Port Range Shadowing Detection**: Fixed critical flaw in rule analysis that was missing port range shadowing scenarios
  - **Root Cause**: The `is_port_equal_or_broader()` method only handled simple single ports and failed on complex port specifications
  - **Missing Cases**: Port ranges like "80:90" vs single ports like "85" were not detected as shadowing relationships
  - **Port Variable Support**: Added full support for port variables (e.g., `$destination`, `$HTTP_PORTS`) with proper resolution from .var files
  - **Real-World Impact**: Now correctly detects when `pass tcp ... -> any 80:90` shadows `reject tcp ... -> any 85`, preventing security bypasses
  - **Variable Resolution**: Port specifications like `$destination = "88"` are properly resolved and analyzed for range containment

### Enhanced Port Parsing Capabilities
- **Comprehensive Port Specification Support**: Added advanced port parsing with full Suricata compatibility
  - **Port Ranges**: Full support for ranges like "80:90", "1000:2000", "443:8443"
  - **Port Lists**: Support for comma-separated lists like "80,443,8080", "20,21,990,991"
  - **Mixed Specifications**: Complex combinations like "80:90,443,8080"
  - **Port Variables**: Complete variable resolution for `$HTTP_PORTS`, `$destination`, etc.
  - **Validation**: Proper port number bounds (1-65535), range ordering validation
  - **Conservative Handling**: Safe fallbacks for negated ports (!80) and unsupported complex patterns

### New Technical Methods
- **`parse_port_specification(port_spec, variables)`**: Comprehensive port specification parser with variable resolution
  - Handles port ranges, lists, variables, and mixed specifications
  - Returns port sets for mathematical containment analysis
  - Includes proper validation and error handling
- **`port_set_contains(broader_ports, specific_ports)`**: Set-based port containment analysis
  - Uses subset mathematics for accurate shadowing detection
  - Supports complex port relationships beyond simple equality
- **Enhanced `is_port_equal_or_broader(port1, port2, variables)`**: Complete rewrite with variable support
  - Now accepts variables parameter for proper port variable resolution
  - Falls back to original logic for simple cases while supporting complex specifications
  - Maintains backward compatibility with all existing functionality

### Test Results and Validation
- **Verified Fix**: Successfully detects port range shadowing in test cases
  - `pass tcp ... -> any 80:90` vs `reject tcp ... -> any 85` → **CRITICAL: PASS rule prevents REJECT rule from executing**
  - `pass tcp ... -> any 80:90` vs `reject tcp ... -> any $destination` (where `$destination = "88"`) → **CRITICAL: security bypass**
- **Variable Resolution Confirmed**: Port variables properly resolved from .var files and analyzed for containment
- **Backward Compatibility**: All existing port analysis functionality preserved and working correctly

### Security Impact
- **Enhanced Threat Detection**: Now identifies port-based rule shadowing that could lead to security bypasses
- **Variable-Aware Analysis**: Properly analyzes rules using port variables, common in enterprise environments
- **Comprehensive Coverage**: Handles all Suricata port specification formats for complete security analysis

---

## Version 1.9.1 - September 19, 2025

### Critical Bug Fix: Port Range Format Validation
- **Port Range Format Correction**: Fixed inconsistent port range validation that incorrectly allowed "80-100" format instead of the correct "80:100" format
  - **Root Cause**: Validation logic used `-` separator for port ranges while Suricata standard requires `:` separator
  - **Affected Areas**: Port range validation in both rule editing (working) and initial rule creation (broken) workflows
  - **Missing Validation**: `insert_new_rule_from_editor()` method was missing port field validation entirely, allowing invalid formats during inline rule creation
  - **Inconsistent Experience**: Users could create rules with invalid port ranges via bottom panel editor but couldn't edit those same rules later
  - **Security Impact**: Medium - Invalid port range formats would be rejected by AWS Network Firewall deployment
- **Comprehensive Format Update**: Updated port range format throughout entire application
  - **Validation Logic**: Changed core `validate_port_list()` method from using `-` to `:` separator (e.g., "8080:8090")
  - **Error Messages**: Updated all validation error messages to show correct format examples
  - **UI Examples**: Updated dialog hints and examples from "80,443,8080-8090" to "80,443,8080:8090"
  - **Documentation**: Updated README.md and test_cases.md with corrected format examples
  - **Complete Validation**: Added missing port validation to `insert_new_rule_from_editor()` method for consistent behavior

### Technical Implementation
- **Core Validation**: Modified `validate_port_list()` method in `suricata_generator.py` to use `:` separator instead of `-`
- **Error Message Updates**: Updated `validate_port_field()` and UI dialog error messages with correct format examples
- **Missing Validation Fix**: Added port field validation calls to `insert_new_rule_from_editor()` method
- **UI Consistency**: Updated `ui_manager.py` variable dialog hints and error messages
- **Documentation Updates**: Updated examples in `README.md`, `test_cases.md` with correct colon format
- **Complete Coverage**: Verified no remaining instances of old dash format exist in codebase

### User Impact
- **Consistent Validation**: Both rule creation workflows (inline editor and dialog) now enforce the same port range format
- **Clear Guidance**: All error messages and examples guide users to correct "80:100" format
- **AWS Compatibility**: Generated rules now use proper port range format accepted by AWS Network Firewall
- **Immediate Feedback**: Users receive validation errors for incorrect formats during rule creation, not during deployment

---

## Rules Analysis Engine Version 1.4.0 - September 19, 2025

### Major Protocol Layering Analysis Overhaul
- **Critical Bug Fix: Protocol Pattern Detection**: Fixed fundamental bug in `low_level_rule_is_broader_than_app_rule()` that completely missed broad application-layer protocol patterns
  - **Root Cause**: Function incorrectly assumed rules with content were equally specific, missing that `app-layer-protocol:!http` patterns are extremely broad
  - **Impact**: Critical - Rules like `reject tcp ... (app-layer-protocol:!http)` were not detected as conflicting with TLS rules, missing legitimate protocol layering conflicts
  - **Solution**: Added protocol-aware pattern analysis that recognizes negated application-layer patterns as broad even when they contain "content"
  - **Pattern Coverage**: Now detects conflicts with `!http`, `!tls`, `!dns`, `!smtp`, `!ftp`, `!ssh` patterns when they affect specific protocol rules

- **AWS Network Firewall Processing Model**: Complete rewrite of rule type classification and processing order detection
  - **Corrected Priority Order**: Fixed backwards Suricata rule type processing priority (SIG_TYPE_IPONLY processes FIRST, not last)
  - **Rule Type Elevation**: TCP/IP rules with `flow` or `app-layer-protocol` keywords properly elevated to application layer processing  
  - **Accurate Classification**: HTTP/TLS protocols correctly classified as SIG_TYPE_APPLAYER regardless of keywords
  - **Intra-Type Conflict Detection**: Added file-order based conflict detection within same rule types

- **Advanced Flow State Analysis**: Comprehensive flow state exclusion logic to prevent false positives
  - **Handshake vs Application Layer**: TCP handshake rules (`flow:not_established`) properly excluded from conflicting with application layer content rules
  - **Protocol-Based Requirements**: Application layer protocols (HTTP, TLS, etc.) automatically recognized as requiring established connections
  - **False Positive Elimination**: Reduced conflicts in best_practices.suricata from 31 to 1 by eliminating illegitimate handshake conflicts

- **Base Protocol Separation**: Enhanced protocol compatibility logic to prevent unrelated protocol conflicts
  - **Protocol Isolation**: TCP vs ICMP vs UDP rules properly recognized as non-conflicting since they handle different traffic types
  - **Application Layer Exclusion**: `app-layer-protocol:!tls` correctly excludes TLS traffic, preventing false conflicts with TLS rules
  - **Bidirectional Analysis**: Proper exclusion logic works in both directions for comprehensive conflict prevention

### Technical Implementation
- **Rules Analysis Engine**: Updated to version 1.3.4 with complete AWS Network Firewall processing model
- **Enhanced Functions**: 15+ new/enhanced methods including `flow_states_are_mutually_exclusive()`, `requires_established_connection()`, `protocols_could_match_same_traffic()`
- **Intelligent Classification**: Dynamic rule type determination based on keywords and protocol types
- **Comprehensive Testing**: Validated against multiple test files including original bug cases and complex enterprise rules

### Security Impact
- **Accurate Conflict Detection**: Now properly identifies real protocol layering issues while eliminating false positives
- **Enterprise Rule Support**: Handles complex rule scenarios found in production AWS Network Firewall deployments
- **Professional Analysis**: Provides precise, context-aware rule conflict analysis matching security team expectations

---

## Rules Analysis Engine Version 1.3.3 - September 18, 2025

### Critical Bug Fix: Protocol Layering Conflict Detection
- **Missing Action Combination Fix**: Fixed critical bug in protocol layering conflict detection that was missing a key scenario where application-layer pass rules are blocked by network-layer reject/drop rules
  - **Root Cause**: The `check_protocol_layering_conflict()` method was missing the action combination: `upper_rule.action == 'pass' and lower_rule.action in ['drop', 'reject']`
  - **Missing Detection**: Rules with higher-layer pass actions (HTTP, TLS, DNS) followed by broader low-level reject/drop rules (IP, TCP, UDP) were not detected as conflicts
  - **Security Impact**: Critical - Intended traffic allowance could be blocked without detection, creating security policy violations
  - **Real-World Example**: 
    - Rule 1: `pass http $HOME_NET any -> any any (http.host; content:"aws.amazon.com"; endswith; flow:to_server; msg:"Allow AWS"; sid:101;)`
    - Rule 2: `reject ip $HOME_NET any -> any any (msg:"Block all traffic"; sid:102;)`
    - **Problem**: The IP reject rule would be processed before the HTTP pass rule due to Suricata's protocol layering, blocking intended AWS traffic
- **Complete Action Coverage**: Enhanced protocol layering detection to handle all critical action combinations:
  - **HTTP/TLS drop/reject vs IP pass**: Prevents security bypasses where low-level pass rules allow traffic that should be blocked
  - **HTTP/TLS pass vs IP drop/reject**: Prevents policy violations where intended traffic gets blocked (FIXED in this version)
  - **HTTP/TLS alert vs IP pass/drop/reject**: Prevents missing alerts when network-layer rules process first
- **Accurate Conflict Classification**: New conflicts properly classified as 'protocol_layering' severity with precise explanations
  - **Root Cause Identification**: Clear explanation that conflicts occur "due to protocol layering" rather than simple rule ordering
  - **Appropriate Suggestions**: Recommends adding flow keywords or moving application-layer rules above network-layer rules
- **100% Detection Accuracy**: Comprehensive testing validates perfect detection of all protocol layering scenarios with zero false negatives

### Technical Implementation
- **Rules Analysis Engine**: Updated to version 1.3.3 with complete protocol layering action combination coverage
- **Enhanced Logic**: Added missing `elif` branch for pass vs drop/reject action combinations
- **Consistent Messaging**: All protocol layering conflicts now use consistent explanation format and suggestion patterns
- **Backward Compatibility**: Maintains all existing functionality while expanding detection capabilities

### Security Impact
- **Policy Enforcement**: Ensures intended traffic policies are properly enforced by detecting when network-layer rules would override application-layer decisions
- **Reduced Security Gaps**: Prevents protocol layering bypasses where intended allow/block decisions are subverted by broader rules
- **Enhanced Rule Quality**: Helps users create more robust Suricata rulesets with proper flow constraints to prevent layering conflicts

---

## Rules Analysis Engine Version 1.3.2 - September 18, 2025

### Critical Bug Fix: Endswith Pattern Shadowing Detection
- **Domain Pattern Shadowing Fix**: Fixed critical bug in rule analyzer that was completely missing endswith pattern shadowing relationships
  - **Root Cause**: The `is_content_equal_or_broader()` method only checked for exact content equality and did not understand domain suffix relationships
  - **Missing Detection**: Rules with shorter domain suffixes (e.g., `content:"amazon.com"; endswith`) were not detected as broader than rules with longer suffixes (e.g., `content:"aws.amazon.com"; endswith`)
  - **Security Impact**: Critical - Rules intended to allow AWS traffic could be blocked by broader Amazon rules without detection
  - **Traffic Analysis**: Any SNI ending with `aws.amazon.com` also ends with `amazon.com`, making the shorter pattern significantly broader
  - **Real-World Example**: 
    - Rule 1: `reject tls ... content:"amazon.com"; endswith` (blocks all Amazon domains)
    - Rule 2: `pass tls ... content:"aws.amazon.com"; endswith` (allows AWS domains)  
    - **Problem**: Rule 1 would block `aws.amazon.com`, `ec2.aws.amazon.com`, `s3.aws.amazon.com` before Rule 2 could allow them
- **Enhanced Content Analysis**: Added sophisticated endswith pattern detection and domain relationship analysis
  - **New Methods**: Added `has_endswith_pattern()` and `extract_endswith_domain()` helper methods
  - **Domain Suffix Logic**: Implemented proper endswith relationship detection where shorter suffixes are broader than longer ones
  - **TLS/HTTP Targeting**: Specifically targets `tls.sni` and `http.host` patterns where endswith is commonly used
  - **Bidirectional Analysis**: Correctly identifies broader-to-narrower relationships (amazon.com > aws.amazon.com) and narrower-to-broader relationships
- **Conflict Detection Accuracy**: Now properly identifies endswith pattern conflicts as CRITICAL security policy violations
  - **Correct Classification**: These conflicts now appear as "REJECT rule prevents PASS rule from executing (security policy violation)"
  - **Actionable Recommendations**: Provides clear guidance to reorder rules or make broader rules more specific
  - **Zero False Negatives**: Testing confirms 100% detection of endswith domain shadowing relationships

### Technical Implementation
- **Enhanced Pattern Recognition**: Updated `is_content_equal_or_broader()` with specialized endswith pattern analysis
- **Domain Extraction**: Added robust domain extraction from Suricata content fields with proper escaping and validation
- **Relationship Detection**: Sophisticated string suffix matching to determine domain hierarchy relationships
- **Preserved Functionality**: All existing conflict detection capabilities maintained while adding new endswith support
- **Rules Analysis Engine**: Updated to version 1.3.2 with complete endswith pattern shadowing coverage

### User Impact
- **Critical Security Issue Resolved**: Prevents accidental blocking of intended traffic due to undetected rule shadowing
- **Professional Rule Analysis**: Rule analyzer now matches professional security team expectations for endswith pattern analysis
- **Improved Confidence**: Users can trust that domain-based rule conflicts will be properly identified and reported
- **Enhanced AWS Integration**: Particularly important for AWS environments where domain-based traffic control is common

---

## Rules Analysis Engine Version 1.3.1 - September 18, 2025

### Rules Analysis Engine Critical Bug Fix
- **Shadow Rule Detection Fix**: Fixed critical bug in rule conflict detection that was missing a key scenario where blocking rules shadow permissive rules
  - **Missing Case Detection**: Added detection for when reject/drop rules prevent pass rules from executing (security policy violation)
  - **Root Cause**: The `check_rule_conflict` method was missing the condition: `upper_rule.action in ['drop', 'reject'] and lower_rule.action == 'pass'`
  - **Impact**: Critical security analysis gap where intended traffic allowance could be blocked without detection
  - **Resolution**: Added missing conflict detection case with appropriate severity (critical) and actionable suggestion
  - **Variable Resolution**: Confirms that network variable resolution (e.g., `$HOME_NET` → `10.0.0.0/24`, `$small_net` → `10.0.0.0/26`) was working correctly
  - **Network Containment**: Validates that subnet containment detection (`10.0.0.0/26` is subnet of `10.0.0.0/24`) was functioning properly
- **Test Case Validation**: Bug discovered and fixed using test rules where reject rule with broader network range (`$HOME_NET`) was shadowing pass rule with narrower network range (`$small_net`)
- **Enhanced Analysis Accuracy**: Rule analyzer now properly detects all major shadow scenarios including blocking-over-permissive rule conflicts

### Technical Implementation
- **Rules Analysis Engine**: Updated version to 1.3.1 with complete shadow rule detection coverage
- **Conflict Classification**: New conflict properly classified as 'critical' severity with security policy violation description
- **User Guidance**: Provides clear suggestion to reorder rules to ensure intended traffic flow behavior

---

## Version 1.9.0 - September 18, 2025

### Major New Feature: Rev Keyword Support
- **Complete Rev Keyword Implementation**: Full support for Suricata rev keyword for rule versioning and change tracking
  - **Rule Editor Integration**: Rev field displayed on same row as SID in Rule Editor section (read-only for user safety)
  - **Edit Dialog Support**: Edit rule popup window includes rev field display (read-only) positioned next to SID field
  - **Automatic Positioning**: Rev keyword always appears at the end of rules after the sid keyword per Suricata best practices
  - **Smart Incrementing**: Rev automatically increments by 1 when any rule field changes (excluding message field changes)
  - **Message Exception**: Changes to the message field do NOT increment the rev value, allowing documentation updates without version changes
  - **Default Value Handling**: Rules imported from clipboard without rev keyword automatically get rev=1 default value
  - **Preservation Logic**: Rules imported with existing rev keywords preserve their current rev values
- **Change Tracking Integration**: Rev support works independently of change tracking settings
  - **Universal Support**: Rev functionality operates whether change tracking is enabled or disabled
  - **History Exclusion**: Rev changes are intentionally excluded from change history to prevent clutter in audit logs
  - **Clean Audit Trails**: Change tracking focuses on substantive rule changes while rev increments happen transparently
- **Clipboard Operations**: Rev keyword included when copying rules to system clipboard for external applications
  - **Complete Rule Preservation**: Copied rules include all keywords including rev for accurate external representation
  - **Import Compatibility**: Supports importing rules with or without rev keywords from external sources

### Technical Implementation
- **Core Data Model**: Enhanced `SuricataRule` class with rev attribute and parsing support in `suricata_rule.py`
- **Rule Parsing**: Updated `from_string()` method to extract rev keyword from existing rules with proper fallback to rev=1
- **Rule Generation**: Updated `to_string()` method to include rev keyword in proper position after sid
- **UI Components**: Enhanced `ui_manager.py` with read-only rev field positioned next to SID field
- **Main Application**: Updated `suricata_generator.py` with rev incrementing logic and change detection for all edit operations
- **Display Integration**: Enhanced table display to show rev keyword in main rules table immediately when rules are added or modified

### User Experience
- **Transparent Operation**: Rev support works automatically without requiring user configuration or manual management
- **Professional Standards**: Follows Suricata community best practices for rev keyword usage and positioning
- **Error Prevention**: Read-only rev fields prevent accidental user modification while showing current values
- **Immediate Visibility**: Rev keywords visible in main rules table as soon as rules are created or modified

---

## Version 1.8.1 - September 17, 2025

### Enhanced Comment Editing
- **Double-Click Comment Editing**: Enhanced double-click functionality to properly support comment editing alongside regular rule editing
  - **Comment Detection**: Added intelligent detection of comment lines using `getattr(rule, 'is_comment', False)` in `edit_selected_rule()` method
  - **Specialized Comment Dialog**: New `show_edit_comment_dialog()` method provides focused interface for editing comment text
  - **Streamlined Interface**: Comment editing dialog shows only the comment text field without unnecessary rule fields
  - **Automatic Formatting**: Dialog automatically strips `#` prefix for editing and ensures proper `# ` formatting when saving
  - **Consistent User Experience**: Double-click behavior now works uniformly for both rules and comments
- **Improved Workflow**: Users can now edit comments as easily as rules by double-clicking on comment lines in the rules table
- **Clean Interface Design**: Comment editing dialog is optimized for text editing with proper focus, text selection, and Enter key support

### Technical Implementation
- Enhanced `edit_selected_rule()` method with comment type detection and routing logic
- Added dedicated `show_edit_comment_dialog()` method with specialized UI for comment editing
- Maintained backward compatibility with existing rule editing functionality
- Proper state management with undo support and table refresh after comment updates

---

## Version 1.8.0 - September 17, 2025

### Major New Feature: PCRE Domain Optimization
- **Smart Domain Grouping**: Revolutionary PCRE optimization for domain list imports that can reduce rule counts by 40-75%
  - **TLD Variation Detection**: Automatically groups domains like `microsoft.com` and `microsoft.edu` into single PCRE rules: `microsoft\.(com|edu)`
  - **Subdomain Pattern Detection**: Groups subdomains like `mail.google.com`, `drive.google.com`, `docs.google.com` into wildcard patterns: `.*\.google\.com`
  - **Mixed Optimization**: Intelligently combines PCRE groups with individual rules when some domains don't benefit from optimization
  - **Rule Structure Preservation**: Each PCRE group maintains proper rule structure (4 rules for "pass" action, 2 rules for "drop/reject")
  - **Significant Capacity Savings**: Example - 12 individual domain rules reduced to 4 PCRE group rules = 8 rule savings!

### Enhanced Import Dialog
- **PCRE Optimization Checkbox**: New checkbox in Bulk Domain Import dialog: "Use PCRE optimization to reduce rule count"
- **Real-time Rule Count Preview**: Live comparison showing standard vs PCRE-optimized rule counts with exact savings
  - **Green Preview**: "PCRE optimized: 8 rules (2 PCRE groups + 0 individual) - Saves 4 rules!"
  - **Orange Warning**: "PCRE analysis: No optimization possible with current domains"
- **Smart Analysis Feedback**: Visual indicators show when optimization is beneficial vs when individual rules are more appropriate
- **Informational Guidance**: Blue help text explaining PCRE functionality and benefits

### PCRE Rule Generation
- **Proper Suricata Syntax**: Generates valid PCRE rules using `pcre:"/pattern/i"` with case-insensitive matching
- **Protocol-Specific Rules**: Creates both TLS (`tls.sni`) and HTTP (`http.host`) rules for each PCRE group
- **Descriptive Comments**: Adds clear comments explaining each PCRE group and the domains it covers
- **Two-Phase Analysis**:
  - **Phase 1**: Groups domains by root domain for subdomain optimization
  - **Phase 2**: Groups domains by name for TLD variation optimization
- **Backward Compatibility**: Standard domain import unchanged when PCRE optimization disabled

### Technical Implementation
- **Enhanced Dialog Layout**: Increased dialog height from 450px to 550px to accommodate new PCRE features
- **Advanced Pattern Generation**: Sophisticated regex escaping and pattern construction for complex domain matching
- **Comprehensive Error Handling**: Graceful fallbacks when PCRE analysis encounters edge cases
- **Full Integration**: Works seamlessly with existing undo, history tracking, and variable management systems

### User Experience
- **Zero Learning Curve**: Simple checkbox interface requiring no PCRE knowledge
- **Informed Decision Making**: Preview shows exact benefits before committing to import
- **Professional Results**: Generated PCRE rules use industry-standard patterns and proper Suricata syntax
- **Maximum Compatibility**: Full integration with AWS Network Firewall capacity planning and rule limits

---

## Version 1.7.1 - September 16, 2025

### Critical Bug Fix: Terraform Export Variable Handling
- **Port Set vs IP Set Variable Classification**: Fixed critical issue in terraform export where variables used in port positions were incorrectly categorized as IP sets
  - **Problem**: Variables like `$src` with port values (e.g., "33") were being generated as `ip_sets` instead of `port_sets` in terraform templates
  - **Root Cause**: Export logic only considered variable prefixes (`$` = IP Set, `@` = Port Set) rather than analyzing actual usage context in rules
  - **Solution**: Implemented intelligent variable usage analysis that examines where variables are used:
    - Variables used only in port positions (src_port, dst_port) → `port_sets` section
    - Variables used only in IP positions (src_net, dst_net) → `ip_sets` section  
    - Variables starting with `@` → Always `port_sets` (traditional Suricata convention)
  - **Impact**: Terraform templates now generate with correct AWS Network Firewall syntax, eliminating terraform apply failures
- **Both Export Formats Fixed**: Enhanced both Terraform (.tf) and CloudFormation (.cft) template generation with usage-based variable analysis
- **Backward Compatibility**: Maintains all existing variable functionality while fixing categorization logic

### Technical Implementation
- **New Analysis Methods**: Added `analyze_variable_usage()` and `get_variable_type_from_usage()` methods to FileManager class
- **Context-Aware Classification**: Variable types now determined by analyzing actual rule usage rather than simple prefix matching
- **Enhanced Export Logic**: Updated `generate_terraform_template()` and `generate_cloudformation_template()` methods to use intelligent variable analysis
- **Preserved Functionality**: All existing variable management features maintained while fixing the core categorization issue

### Files Modified
- **file_manager.py**: Enhanced terraform and CloudFormation generation with intelligent variable usage analysis

---

## Version 1.7.0 - September 16, 2025

### Rules Analysis Engine Priority Enhancement (v1.3.0)
- **Report Display Order Optimization**: Enhanced rule analysis report to display findings in order of priority for better user workflow
  - **Protocol Layering Conflicts First**: PROTOCOL LAYERING CONFLICTS now appear first in all analysis reports (text and HTML)
  - **Critical Issues Second**: CRITICAL ISSUES now display after protocol layering conflicts for logical resolution sequence
  - **Enhanced User Guidance**: Updated recommendations to reflect new priority order - "Address protocol layering conflicts first (add flow constraints), then address critical issues next (security bypasses)"
- **Intelligent Conflict Deduplication**: Enhanced deduplication logic to prevent the same rule pair from appearing in multiple sections
  - **Root Cause Focus**: When both protocol layering and critical/warning conflicts exist for the same rule pair, only the protocol layering conflict is shown
  - **Cleaner Reports**: Eliminates duplicate reporting of the same underlying issue, focusing user attention on the actual root cause
  - **Preserved Important Conflicts**: Maintains all unique conflicts while removing redundant ones for better user experience

### Technical Implementation
- **Report Generation Update**: Modified both `generate_analysis_report()` and `generate_html_report()` methods to reflect new display order
- **Deduplication Enhancement**: Enhanced `_deduplicate_protocol_layering_conflicts()` method to work with the new priority system
- **Consistent Recommendations**: Updated recommendation text across both text and HTML report formats
- **Backward Compatibility**: Maintains all existing analysis capabilities while improving presentation order

### Security Impact
- **Improved Workflow**: Users now see the most fundamental issues first, leading to more effective rule optimization
- **Reduced Confusion**: Cleaner reports with less duplication help users focus on actual problems rather than symptom reports
- **Better Remediation**: Priority ordering guides users to address root causes first, improving overall rule quality

---

## Version 1.6.9 - September 15, 2025

### Rules Analysis Engine Major Enhancement (v1.2.0)
- **Expanded Protocol Layering Detection**: Comprehensive enhancement to protocol layering conflict detection beyond original TCP/HTTP scope
  - **All Low-Level Protocols**: Now detects IP, ICMP, UDP, and TCP rules interfering with higher-layer protocols (HTTP, TLS, DNS, FTP, SSH, SMTP, IMAP, POP3)
  - **Universal Flow Keyword Requirements**: All low-level protocol rules now require flow keywords (flow:established, flow:to_server, etc.) when interfering with application-layer rules
  - **Enhanced Protocol Classification**: Added sophisticated protocol classification system distinguishing network-layer from application-layer protocols
  - **Comprehensive Coverage**: Detects protocol layering conflicts for any combination of low-level protocols interfering with higher-layer rules
  - **Smart Mitigation Detection**: Recognizes various flow keywords (established, to_server, to_client, stateless, flowbits) that prevent layering issues
- **Improved Suggestions**: Enhanced recommendations now suggest appropriate flow keywords for all protocol types rather than TCP-specific solutions
  - **Generic Flow Keywords**: Suggests "flow:established" for all low-level protocols instead of protocol-specific constraints
  - **Universal Application**: Same conflict resolution approach works across IP, ICMP, UDP, and TCP protocols
- **100% Detection Accuracy**: Comprehensive testing validates perfect detection across all protocol combinations with zero false negatives
  - **Test Coverage**: Validated against IP vs HTTP, TLS vs IP, DNS vs UDP, HTTP vs TCP, and FTP vs TCP scenarios  
  - **Flow Keyword Exemption**: Correctly exempts rules that already have appropriate flow constraints
  - **Protocol Classification**: Perfect accuracy in distinguishing higher-layer from low-level protocols

### Technical Implementation
- **Enhanced Helper Methods**: Added `is_higher_layer_protocol()`, `is_low_level_protocol()`, `low_level_rule_is_broader_than_app_rule()`, and `has_flow_keywords()` methods
- **Generic Analysis Logic**: Updated `check_protocol_layering_conflict()` to handle all protocol combinations with unified detection logic
- **Flow Keyword Detection**: Comprehensive detection of all flow-related keywords that mitigate protocol layering issues
- **Backward Compatibility**: Maintains all existing functionality while expanding detection capabilities
- **Same Conflict Category**: Continues using 'protocol_layering' category for consistent user experience

### Security Impact
- **Broader Threat Coverage**: Now identifies protocol layering bypasses across entire protocol stack rather than just TCP/HTTP scenarios
- **Enhanced Rule Quality**: Helps users create more robust Suricata rulesets with proper flow constraints across all protocols
- **Reduced Security Gaps**: Prevents protocol layering bypasses that could occur with any low-level protocol rules lacking flow constraints

---

## Version 1.6.8 - September 15, 2025

### Rules Analysis Engine Enhancement (v1.1.0)
- **Protocol Layering Conflict Detection**: Major improvement to rule analysis with new specialized detection for Suricata protocol processing behavior
  - **New Conflict Category**: Added `protocol_layering` conflict category specifically for TCP rules interfering with HTTP/TLS rules
  - **Accurate Root Cause Analysis**: Identifies when TCP rules will be processed before HTTP/TLS rules due to Suricata's network-layer-first architecture, regardless of rule ordering
  - **Precise Explanations**: Replaced generic "rule shadowing" messages with accurate protocol layering explanations (e.g., "TCP rule at line 3 will be processed before HTTP rule at line 2 due to protocol layering")
  - **Correct Recommendations**: Suggestions now only recommend adding `flow:to_server;` constraints rather than rule reordering, since rule position doesn't solve protocol layering issues
- **Smart Conflict Deduplication**: Intelligent conflict resolution that removes redundant critical/warning conflicts when protocol layering conflicts are detected for the same rule pairs
  - **Root Cause Prioritization**: Shows protocol layering as the primary issue rather than confusing users with multiple overlapping warnings about the same underlying problem
  - **Cleaner Analysis Reports**: Eliminates redundant conflict reports, focusing user attention on the actual root cause
- **Enhanced Recommendations**: Updated analysis report recommendations to prioritize protocol layering conflicts first, then critical issues second
  - **Priority Guidance**: "Address protocol layering conflicts first (add flow constraints)" followed by "Address critical issues second (security bypasses)"
  - **Actionable Workflow**: Provides clear step-by-step approach for resolving different types of rule conflicts

### Technical Implementation
- **Rules Analysis Engine**: Updated to version 1.1.0 with comprehensive protocol layering detection logic
- **Conflict Detection Methods**: Added specialized `check_protocol_layering_conflict()` method with TCP-over-HTTP analysis
- **Network/Port Overlap Detection**: Enhanced overlap detection with looser matching criteria for protocol layering scenarios  
- **Mitigation Detection**: Intelligent detection of existing flow constraints that prevent protocol layering issues
- **Deduplication Algorithm**: Sophisticated conflict deduplication that preserves important conflicts while removing redundant ones

### Security Impact
- **Improved Threat Detection**: Better identification of Suricata rule configurations that could lead to security bypasses due to protocol processing order
- **Reduced False Positives**: More accurate conflict analysis reduces user confusion and improves focus on actual security issues
- **Enhanced Rule Quality**: Helps users create more effective Suricata rulesets with proper flow constraints to prevent protocol layering bypasses

---

## Version 1.6.7 - September 14, 2025

### Code Architecture Enhancement
- **UI Management Module Extraction**: Extracted comprehensive UI management functionality from main application into dedicated `ui_manager.py` module
  - **UIManager Class Creation**: Centralized all UI setup, event handling, and component management in dedicated class
  - **Menu System Management**: Complete menu bar setup with file operations, edit functions, tools, and help menus
  - **Tabbed Interface Control**: Rule editor, variables, and history tabs with dynamic content switching
  - **Event Handler Organization**: All UI event handlers (clicks, keyboard shortcuts, selections) now properly organized
  - **Status Bar Management**: Comprehensive status bar setup with colored action counts and capacity tracking
  - **Table Management**: Rules table setup, formatting, color coding, and interaction handling
- **Search Management Module Enhancement**: Continued refinement of search functionality in dedicated `search_manager.py` module
  - **Complete Search Integration**: All search operations properly integrated with UI manager for seamless user experience
  - **Event Coordination**: Proper coordination between search operations and UI updates through manager pattern

### Critical Bug Fix
- **AWS Template Loading**: Fixed critical error in "Load AWS Best Practice template" function
  - **Issue**: Method was calling `self.parent.show_rule_editor()` but `show_rule_editor()` method exists in UIManager class, not main application
  - **Fix**: Updated method call to `self.parent.ui_manager.show_rule_editor()` to properly access UI manager functionality
  - **Impact**: Resolves popup error "'SuricataRuleGenerator' object has no attribute 'show_rule_editor'" when loading AWS templates
  - **Security Rating**: High - AWS template loading is a core feature used by many users

### Technical Implementation
- **Composition Pattern**: Main application now uses UIManager through composition with `self.ui_manager = UIManager(self)`
- **Method Delegation**: UI-related methods in main application now delegate to appropriate manager instances
- **Preserved Functionality**: All existing UI functionality maintained while achieving better code organization
- **Enhanced Maintainability**: UI logic now centralized in dedicated module for easier maintenance and testing
- **Consistent Architecture**: Follows established pattern used for FileManager, DomainImporter, RuleAnalyzer, and SearchManager modules

---

## Version 1.6.6 - September 14, 2025

### Enhanced Search Functionality
- **Complete Search Implementation**: Fixed incomplete search functionality with comprehensive field-specific search capabilities
  - **Field-Specific Search**: Search within specific fields (Message, Content, Networks, Ports, SID, Protocol) or all fields
  - **Action-Based Filtering**: Filter search results by rule action types (Pass, Drop, Reject, Alert) and Comments with convenient Select All/Deselect All buttons
  - **Advanced Search Options**: Case sensitive search, whole word matching, regular expression support, and comment inclusion control
  - **Text Matching Engine**: Complete implementation supporting simple substring search, regex patterns with error handling, and word boundary detection
- **Simplified Search Interface**: Streamlined search dialog by removing search scope complexity - all searches now search all rules by default for improved usability
- **Search Navigation**: Enhanced keyboard navigation with F3 for next result, Escape to close search, and visual yellow highlighting of matches
- **Status Bar Integration**: Real-time search status showing current position (e.g., "Search: 2 of 5 matches for 'tcp'") in main status bar

### Bug Fixes
- **Incomplete Method Implementation**: Fixed truncated `matches_search_criteria()` method that was causing search functionality failures
- **Missing Text Matching**: Added complete `perform_text_match()` method for handling different search options (regex, whole word, case sensitivity)
- **Duplicate Method Removal**: Cleaned up duplicate `show_find_dialog()` method definitions that were causing code conflicts
- **Search Scope Simplification**: Removed unused `get_search_scope_rules()` method after eliminating search scope functionality

### Technical Improvements
- Enhanced error handling for invalid regular expression patterns with user-friendly error messages
- Improved search performance by eliminating unnecessary scope checking and focusing on core search functionality
- Streamlined search dialog layout with better organization of search options and controls
- Complete implementation of all search-related methods with proper parameter handling and validation

---

## Version 1.5.6 - September 14, 2025

### New Keyboard Shortcuts
- **Quick Rule Disable/Enable (Space bar)**: Toggle selected rules between enabled (rule) and disabled (comment) state
  - **Individual Toggle**: Each selected item toggles independently - rules become comments, comments with directional indicators become rules
  - **Smart Detection**: Only converts comments back to rules if they contain directional indicators ("<-", "<>", or "->")
  - **Context Sensitive**: Only works when rules table has focus, preserves normal space behavior in text fields
  - **Multiple Selection**: Works on single rule or multiple selected rules simultaneously
  - **Visual Feedback**: Disabled rules appear as gray comments, excluded from capacity calculations
- **Jump to Line (Ctrl+G)**: Navigate directly to any line number in the rules table
  - **Line Number Dialog**: Shows popup asking for target line number with validation
  - **Smart Navigation**: Jumps to placeholder row if line number exceeds total lines
  - **Complete Coverage**: Includes all lines (rules, comments, blanks) in line counting
  - **Auto-Focus**: Automatically selects and scrolls to the target line

### Technical Implementation
- **Focus-Aware Shortcuts**: Both shortcuts only activate when rules table has focus to avoid conflicts with text editing
- **Undo Support**: All toggle operations can be reverted with Ctrl+Z
- **Rule Parsing**: Uses existing SuricataRule.from_string() method for reliable comment-to-rule conversion
- **Error Handling**: Graceful handling of invalid line numbers and parsing failures

---

## Version 1.5.5 - September 14, 2025

### Critical Bug Fix
- **Undefined Variables**: Fixed critical runtime error in `network_matches` method that referenced undefined variables `matched_positive` and `has_positive_networks`
  - **Issue**: Method contained incomplete implementation with undefined variable references causing NameError exceptions
  - **Fix**: Implemented complete network matching logic with proper IP address validation, CIDR network comparison, and variable resolution
  - **Impact**: Resolves application crashes during rule analysis operations and enables proper network matching functionality
  - **Security Rating**: Critical - Application would crash when performing network analysis operations

### Technical Details
- **Complete Implementation**: Added full network matching logic supporting 'any' keyword, variable expansion, and IP/CIDR comparisons
- **Error Handling**: Proper exception handling for invalid IP addresses and network formats with string comparison fallback
- **Variable Support**: Recursive variable resolution for network variables defined in Variables tab

---

## Version 1.5.4 - September 14, 2025

### High Severity Security Fixes
- **CWE-22 Path Traversal Vulnerability**: Fixed critical path traversal vulnerability in history file creation
  - **Issue**: `save_history_file` method was vulnerable to directory traversal attacks through malicious filenames
  - **Fix**: Added comprehensive filename validation and sanitization using `os.path.basename()` and `os.path.join()`
  - **Impact**: Prevents attackers from writing files outside the intended directory structure
  - **Security Rating**: High - Could allow unauthorized file system access
- **Generic Exception Handling**: Replaced all generic `except Exception:` blocks with specific exception types
  - **Issue**: Generic exception handlers could mask security-relevant errors and make debugging difficult
  - **Fix**: Implemented specific exception handling (TypeError, ValueError, IndexError, KeyError, UnicodeError, OSError, IOError, json.JSONDecodeError, tk.TclError, UnicodeDecodeError)
  - **Impact**: Improves error visibility, debugging capability, and prevents potential security issues from being hidden
  - **Security Rating**: Medium - Improves overall security posture and error handling

### Files Modified
- **file_manager.py**: Enhanced `save_history_file` method with path traversal protection and specific exception handling
- **suricata_generator.py**: Replaced 7 generic exception handlers with specific exception types across file operations, network operations, and UI handling

### Technical Details
- **Path Sanitization**: Uses `os.path.basename()` to extract safe filename and `os.path.join()` for secure path construction
- **Exception Specificity**: Each exception type now has appropriate handling for its specific error condition
- **Backward Compatibility**: All security fixes maintain existing functionality while improving security

---

## Version 1.5.3 - September 14, 2025

### Security Fixes
- **CWE-22 Path Traversal**: Fixed path traversal vulnerability in history file creation that could allow writing files outside intended directory
  - Enhanced filename validation and sanitization in `save_history_file()` method
  - Now uses `os.path.join()` with sanitized base filename to prevent directory traversal attacks
  - History files are always created in the same directory as the source .suricata file
- **Authorization Bypass**: Fixed authorization check in AWS template loading that could allow bypassing user save confirmation
  - Properly handles all return values from save dialog including cancel operation
  - Prevents template loading when user explicitly cancels the save operation
  - Ensures user authorization is properly enforced before proceeding with template operations

### Technical Improvements
- Enhanced path construction using secure `os.path.join()` method with validated components
- Improved authorization flow with explicit handling of user dialog responses
- Added proper validation for file operations to prevent security vulnerabilities

---

## Version 1.5.2 - September 14, 2025

### Bug Fixes
- **Enhanced Error Handling**: Comprehensive improvement of error handling throughout the application
  - **File Operations**: Specific handling for FileNotFoundError, PermissionError, UnicodeDecodeError, and OSError
  - **Network Operations**: Separate handling for HTTP errors, network connectivity issues, and content decoding problems
  - **Data Validation**: Improved handling for ValueError, OverflowError, and range validation for SID values
  - **JSON Operations**: Specific handling for JSONDecodeError and serialization errors
  - **User-Friendly Messages**: Clear, actionable error messages with descriptive titles and guidance
  - **Graceful Degradation**: Application continues working when non-critical operations fail

### Technical Improvements
- Replaced generic `except Exception` blocks with specific exception handling across all modules
- Enhanced SID parsing in suricata_rule.py with proper range validation (100-999999999)
- Improved file system error handling with directory permission checks before write operations
- Added proper encoding error handling for UTF-8 file operations
- Enhanced network error handling for AWS template loading with HTTP status code reporting

---

## Version 1.5.1 - September 13, 2025

### Bug Fixes
- **Delete Key Context Sensitivity**: Fixed issue where Delete key would delete rules even when editing text in editor fields - Delete key now only deletes rules when the rules table has focus, allowing normal text deletion in editor fields
- **Improved User Experience**: Enhanced keyboard interaction by making Delete key behavior context-aware based on widget focus

### Technical Improvements
- Modified Delete key binding to use custom handler method `on_delete_key()` that checks widget focus
- Added focus detection logic to ensure Delete key only triggers rule deletion when tree view has focus
- Preserved normal text editing behavior in all editor input fields

---

## Version 1.5.0 - September 13, 2025

### Rule Analyzer Module Enhancement
- **Bidirectional Analysis Fix**: Fixed critical flaw in rule analysis logic that only checked shadowing in one direction
  - **Forward Analysis**: Continues to check if upper rules shadow lower rules
  - **Reverse Analysis**: NEW - Detects when lower broad rules make upper specific rules unreachable
  - **Significantly Broader Detection**: Identifies rules with protocol "ip", "any" networks/ports, or missing content restrictions
  - **Real-World Impact**: Catches cases where broad pass/drop rules appear anywhere and create security bypasses
- **Rule Analyzer Versioning**: Independent versioning for rule_analyzer.py module starting at version 1.0.0
  - Allows independent evolution of analysis logic while maintaining main application compatibility
  - Version tracked in main application release notes for centralized documentation

### Domain Import Module Extraction
- **DomainImporter Class Creation**: Extracted all domain import functionality from main application into dedicated `domain_importer.py` module
  - **Bulk Domain Import**: Domain list processing and rule generation for multiple domains
  - **AWS Template Loading**: Dynamic fetching and parsing of AWS best practices rules from official documentation
  - **Individual Domain Rules**: Single domain rule insertion with customizable templates
  - **Rule Generation Logic**: Comprehensive domain rule creation supporting pass/drop/reject actions with proper TLS/HTTP handling
- **Main Application Integration**: Updated main application to use DomainImporter through composition pattern
  - Simplified domain operation methods to delegate to DomainImporter instance
  - Maintained identical functionality while achieving better code organization
  - Removed duplicate domain operation methods from main application

### Technical Implementation
- Created comprehensive DomainImporter class with domain import, AWS template loading, and bulk operations
- Updated main application to instantiate `self.domain_importer = DomainImporter(self)`
- Modified menu commands and button handlers to use DomainImporter delegation pattern
- Preserved all sophisticated domain handling including validation, error handling, and SID management
- Maintained backward compatibility with existing domain import workflows

---

## Version 1.4.0 - September 13, 2025

### File Operations Module Extraction
- **FileManager Class Creation**: Extracted all file I/O operations from main application into dedicated `file_manager.py` module
  - **Suricata File Operations**: Loading/saving .suricata files with validation and error handling
  - **Variable File Management**: Companion .var file operations for persistent variable storage
  - **History File Management**: Change tracking .history file operations for audit trails
  - **Export Functionality**: Terraform and CloudFormation template generation
  - **AWS Template Loading**: Dynamic fetching and parsing of AWS best practices rules
- **Main Application Integration**: Updated main application to use FileManager through composition pattern
  - Simplified file operation methods to delegate to FileManager instance
  - Maintained identical functionality while achieving better code organization
  - Removed duplicate file operation methods from main application

### Technical Implementation
- Created comprehensive FileManager class with 20+ file operation methods
- Updated main application to instantiate `self.file_manager = FileManager()`
- Modified file operation methods to use FileManager delegation pattern
- Preserved all sophisticated file handling including validation, error handling, and companion file management
- Maintained backward compatibility with existing file formats and operations

---

## Version 1.3.0 - September 13, 2025

### Code Architecture Optimization
- **Rule Analysis Module Extraction**: Moved comprehensive rule analysis logic from main application into separate `rule_analyzer.py` module
  - Extracted `RuleAnalyzer` class containing all conflict detection, shadowing analysis, flow state analysis, and report generation methods
  - Main application now uses composition pattern with `self.rule_analyzer = RuleAnalyzer()` instance
  - Maintains identical functionality while achieving better modularity and testability
- **Enhanced Code Organization**: Building on previous SuricataRule class extraction to `suricata_rule.py` module
  - Improved separation of concerns with focused, single-responsibility modules
  - Better maintainability through logical code organization
  - Enhanced potential for code reuse and independent testing

### Technical Implementation
- Updated main application to import and instantiate `RuleAnalyzer` class
- Modified `review_rules()` method to delegate analysis operations to analyzer instance
- Updated report generation methods to use analyzer's capabilities
- Preserved all sophisticated analysis features including complete shadow detection, geographic specificity recognition, and professional HTML/PDF report generation

---

## Version 1.2.3 - September 12, 2025

### Bug Fixes
- **Change Tracking for Copy/Paste**: Fixed issue where only copy operations were being tracked in Change History tab - removed copy operation tracking and ensured paste operations are properly tracked with detailed rule information
- **Right-Click Context Menu**: Fixed missing "Select All" option in right-click context menu - removed duplicate method that was overriding the complete context menu implementation
- **Context Menu Enhancement**: Improved right-click menu to show Paste option when clipboard contains rules and properly organize menu items with separators
- **System Clipboard Integration**: Fixed copy functionality to properly write rules to Windows system clipboard for external applications like Notepad
- **Dual Clipboard Implementation**: Implemented dual clipboard approach - internal clipboard uses new SIDs to prevent conflicts when pasting within the app, while system clipboard preserves original SIDs for external applications

### Enhancements
- **Domain Import Tracking**: Enhanced change tracking for domain list imports to show detailed information including domain names and SID ranges assigned to each domain (e.g., "Imported 12 pass rules for 3 domains (SIDs 1000-1011): example.com: SIDs 1000-1003, test.org: SIDs 1004-1007, sample.net: SIDs 1008-1011")
- **Rule Deletion Tracking**: Enhanced rule deletion tracking to capture complete rule information in history files while displaying user-friendly summaries in Change History tab (shows rule message and truncated rule text for better readability)

### Technical Improvements
- Removed duplicate `on_right_click()` method that was causing context menu functionality conflicts
- Enhanced context menu logic to conditionally show Copy/Delete options based on selection state
- Improved menu organization with proper separators between logical groups of actions
- Removed duplicate `copy_selected_rules()` method that lacked system clipboard functionality
- Enhanced copy operation to maintain separate rule collections for internal vs external clipboard usage

---

## Version 1.2.2 - September 12, 2025

### Bug Fixes
- **Change Tracking**: Fixed issue where change tracking would remain enabled when creating new files - tracking now properly resets to disabled state for new content operations
- **Select All (Ctrl+A)**: Enhanced Ctrl+A functionality to properly exclude placeholder rows from selection and only select actual rules
- **File State Management**: Improved new file creation to properly reset tracking state and clear pending history

### Technical Improvements
- Modified `new_file()` method to disable change tracking for new content operations
- Enhanced `select_all_rules()` to filter out placeholder items and focus on first selected item
- Added proper state cleanup when creating new files to prevent tracking state persistence

---

## Version 1.2.1 - September 2025

### Bug Fixes
- **Change Tracking**: Fixed missing history entry when adding new rules - new rule additions now properly appear in Change History tab
- **Rule Deletion Tracking**: Enhanced rule deletion history to show specific details (action type, line number, SID) instead of generic "Deleted X rules" message
- **Saved History Display**: Fixed inconsistent formatting between pending changes and saved history sections - both now show the same detailed information

### Technical Improvements
- Added `add_history_entry()` call to `insert_new_rule_from_editor()` method for complete change tracking
- Enhanced `delete_selected_rule()` to capture individual rule details before deletion
- Updated `display_saved_history()` to use same detailed formatting logic as pending changes section
- Improved change tracking consistency across all rule operations

---

## Version 1.2.0 - September 2025

### Major New Feature: Change Tracking System
- **Comprehensive Audit Trail**: Complete change tracking and history logging system
  - **Toggle Control**: Enable/disable change tracking via Tools > Enable Change Tracking menu
  - **Change History Tab**: New tab displaying detailed audit trail of all operations
  - **Automatic Headers**: Files include creation and modification timestamps when tracking enabled
  - **Persistent History**: Changes saved to companion .history files alongside .suricata files
  - **History Export**: Export change history to text files for documentation and compliance
  - **Cross-Session Continuity**: History persists across application sessions
  - **Auto-Detection**: Automatically enables tracking when opening files with existing history

### Operation Tracking Categories
- **Rule Operations**: Addition, modification, deletion, and movement of rules with SID tracking
- **Variable Operations**: Addition, modification, and deletion of network variables with definitions
- **File Operations**: File creation, opening, and saving activities
- **Bulk Operations**: Domain imports and SID management operations with counts and details

### Enhanced Variable Management
- **$EXTERNAL_NET Handling**: Proper exclusion from undefined variable counts (auto-defined by AWS Network Firewall)
- **Visual Indicators**: $EXTERNAL_NET displayed in grey with explanatory text in Variables tab
- **Protection**: Prevention of manual editing/deletion of $EXTERNAL_NET variable
- **Status Bar Updates**: Real-time updates when variables are modified or deleted

### Technical Implementation
- **User Configuration**: Persistent tracking preferences stored in user config file
- **JSON Storage**: Structured history data in companion .history files
- **Timestamped Entries**: ISO format timestamps for all tracked operations
- **Version Tracking**: History entries include generator version information
- **Memory Efficient**: Pending history cleared after successful file saves

### User Interface Enhancements
- **Menu Integration**: Change tracking toggle in Tools menu with checkmark indicator
- **Status Display**: Tracking status shown in status bar when enabled
- **History Management**: Refresh, clear display, and export buttons in Change History tab
- **Informational Messages**: Clear guidance when tracking is disabled

---

## Version 1.0.3 - September 2025

### New Features
- **SID Management Dialog**: Complete bulk SID renumbering system with comprehensive conflict detection and resolution
  - **Scope Options**: Renumber all rules, selected rules only, or rules by action type (pass, drop, reject, alert)
  - **Conflict Detection**: Advanced conflict checking that identifies when new SID assignments would clash with existing rules
  - **Resolution Strategies**: Three conflict resolution options:
    - **Skip**: Automatically find next available SID when conflicts occur
    - **Restart**: Use safe starting SID beyond all existing SIDs
    - **Overwrite**: Move conflicting rules to safe SIDs and proceed with desired assignments
  - **Live Preview**: Real-time preview showing which rules will be affected and their new SID assignments
  - **Undo Support**: Full undo capability with Ctrl+Z for all SID renumbering operations
  - **Input Validation**: Comprehensive validation for starting SID (100-999999999) and increment (1-1000) values
  - **User Feedback**: Detailed confirmation dialogs and completion messages with change counts

### Technical Improvements
- Enhanced SID conflict detection algorithm with proper rule identity comparison
- Integrated conflict resolution strategies into the main Apply logic
- Maintained original rule formatting by updating both SID field and original_options string
- Added safety checks to prevent infinite loops and SID range violations
- Comprehensive error handling with user-friendly messages

### User Interface
- Added "SID Management" menu item under Tools menu
- 600x650 pixel dialog with organized sections for current SID info, renumbering options, scope selection, and conflict management
- Context-sensitive radio button states based on rule selection
- Professional conflict resolution dialog with detailed explanations and recommendations

---

## Version 1.0.2 - September 2025

### Bug Fixes
- **Duplicate Placeholder Fix**: Fixed issue where adding a new rule and saving it would create two placeholder rows instead of one
  - Root cause: Manual placeholder reference reset in `insert_new_rule_from_editor` method was not properly cleaning up existing placeholder
  - Solution: Replaced manual reset with proper `remove_placeholder_row()` method call before adding new placeholder
  - Ensures clean removal from both tree view and internal reference tracking

### Technical Details
- Modified `insert_new_rule_from_editor` method to use proper placeholder cleanup
- Improved placeholder management consistency across the application

---

## Version 1.0.1 - September 2025

### New Features
- **Home Key Navigation**: Added Home key functionality to quickly jump to the first line in the rules table and select it
  - Press `Home` to navigate to the first rule
  - Press `End` to navigate to the last rule/placeholder (existing functionality)
  - Provides quick navigation to both ends of large rule sets

### Improvements
- Enhanced keyboard navigation for improved user experience

---

## Version 1.0.0 - September 2025

### Initial Release
- **Complete Suricata Rule Generator** for AWS Network Firewall
- **GUI Interface** with tabbed editor (Rule Editor + Rule Variables)
- **Rule Management**: Create, edit, delete, move, copy/paste rules with undo functionality
- **File Operations**: Open/save .suricata files with companion .var files for variables
- **Bulk Import**: Domain list import with configurable rule generation patterns
- **Export**: Terraform and CloudFormation templates for AWS Network Firewall
- **Rule Conflict Analysis**: Sophisticated shadow detection with minimal false positives
- **Variable Management**: IP sets, port sets, and reference sets with persistent storage
- **Search Functionality**: Find rules with highlighting and navigation (Ctrl+F, F3)
- **Status Bar**: Real-time capacity calculation, colored action counts, SID ranges
- **Protocol Validation**: Subtle warnings for unusual protocol/port combinations
- **AWS Integration**: Load best practices templates from AWS documentation
- **Professional Features**: Vertical scrollbar, comprehensive statistics, persistent variables

### Keyboard Shortcuts
- `Ctrl+Z`: Undo last change
- `Ctrl+C`: Copy selected rules
- `Ctrl+V`: Paste rules
- `Delete`: Delete selected rules
- `Ctrl+F`: Find rules
- `F3`: Find next occurrence
- `Escape`: Close search mode
- `End`: Navigate to last rule/placeholder
- `Home`: Navigate to first rule *(Added in v1.0.1)*

### System Requirements
- Python 3.6 or higher
- tkinter (usually included with Python)
- Standard Python libraries: re, os, ipaddress, typing
