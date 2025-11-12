# Suricata Rule Generator for AWS Network Firewall

A GUI application for creating, editing, and managing Suricata rules specifically designed for AWS Network Firewall deployments.

## Overview

This application provides an intuitive graphical interface for generating Suricata rules with features tailored for AWS Network Firewall use cases. It supports individual rule creation, bulk domain rule generation, and comprehensive rule management with inline editing capabilities.

## Screenshot

![Suricata Rule Generator Interface](screenshot.png)

*The main interface showing the color-coded rules table, tabbed editor with Rule Editor and Rule Variables tabs, and comprehensive rule management controls.*

## Features

- **Visual Rule Management**: Color-coded table display with line numbers
- **Tabbed Interface**: Rule Editor and Rule Variables tabs for organized workflow
- **Inline Editing**: Bottom panel editor for modifying rules
- **Variable Management**: Auto-detection and management of network variables ($HOME_NET, @PORT_SETS)
- **Infrastructure Export**: Generate Terraform (.tf) and CloudFormation (.cft) templates
- **Copy/Paste Functionality**: Copy rules with Ctrl+C/V and right-click context menus
- **Toggle Selection**: Click selected rules again to deselect for improved workflow
- **Bulk Domain Import**: Generate multiple rules from domain lists with optional PCRE optimization
- **Rule Validation**: Network field validation and SID uniqueness checking
- **File Operations**: Open, save, and manage .suricata rule files
- **Comment Support**: Add and edit comment lines with proper formatting
- **Undo Functionality**: Revert changes with Ctrl+Z
- **Rule Movement**: Reorder rules with up/down controls
- **AWS Template Loading**: Dynamic fetching of latest AWS best practices rules
- **Click-to-Insert**: Click below last rule to add new entries
- **Keyboard Navigation**: Down arrow and End key navigation to placeholder row
- **Rule Conflict Analysis**: Comprehensive shadow detection and conflict reporting
- **Enhanced Search Functionality**: Comprehensive field-specific search with advanced filtering options
- **Enhanced Analysis Reports**: Professional HTML/PDF export with timestamps and version info
- **Rule Statistics**: Real-time action counts (Pass/Drop/Reject/Alert) in colored status bar
- **Protocol/Port Validation**: Subtle warnings for unusual protocol/port combinations
- **Persistent Variables**: Automatic save/load of variable definitions via companion .var files
- **Status Bar Enhancements**: SID ranges, undefined variables warnings, and search status
- **SID Management**: Bulk SID renumbering with conflict detection and resolution strategies
- **Change Tracking**: Comprehensive audit trail with history logging and export capabilities

## Requirements

- Python 3.6 or higher
- tkinter (usually included with Python)
- Standard Python libraries: re, os, ipaddress, typing

## Installation

### Prerequisites

Before installing the Suricata Rule Generator, ensure your system meets the following requirements:

### Step 1: Install Python 3.6 or Higher

The application requires Python 3.6 or higher. Follow the instructions for your operating system:

#### Windows
1. **Check if Python is already installed:**
   - Open Command Prompt (cmd) or PowerShell
   - Type: `python --version` or `python3 --version`
   - If Python 3.6+ is installed, you'll see the version number (e.g., "Python 3.9.7")

2. **If Python is not installed or version is too old:**
   - Visit [python.org/downloads](https://www.python.org/downloads/)
   - Download the latest Python 3.x version (3.6 or higher)
   - Run the installer and **check "Add Python to PATH"** during installation
   - Restart Command Prompt and verify with `python --version`

#### macOS
1. **Check current Python version:**
   ```bash
   python3 --version
   ```

2. **Install Python 3.6+ if needed:**
   - **Option A - Using Homebrew (recommended):**
     ```bash
     brew install python3
     ```
   - **Option B - Download from python.org:**
     - Visit [python.org/downloads](https://www.python.org/downloads/)
     - Download and install the macOS installer

#### Linux (Ubuntu/Debian)
1. **Check current Python version:**
   ```bash
   python3 --version
   ```

2. **Install Python 3.6+ if needed:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```

#### Linux (CentOS/RHEL/Fedora)
1. **Check current Python version:**
   ```bash
   python3 --version
   ```

2. **Install Python 3.6+ if needed:**
   ```bash
   # CentOS/RHEL
   sudo yum install python3 python3-pip
   
   # Fedora
   sudo dnf install python3 python3-pip
   ```

### Step 2: Install and Verify tkinter

The application uses tkinter for its graphical user interface. **Important:** tkinter is NOT installed by default on macOS and some Linux distributions require separate installation.

#### Verify tkinter is installed:
```bash
python3 -c "import tkinter; print('tkinter is available')"
```

If this command runs without error and prints "tkinter is available", you're ready to proceed. Otherwise, follow the platform-specific instructions below.

#### Install tkinter if missing:

**macOS - IMPORTANT:**

If tkinter is NOT included on macOS, choose one of these installation methods:

**Method 1: Reinstall Python from python.org (Recommended for beginners)**
1. Download the official macOS installer from [python.org/downloads](https://www.python.org/downloads/)
2. Run the installer (the python.org version includes tkinter)
3. Verify installation: `python3 -c "import tkinter; print('tkinter is available')"`

**Method 2: Using Homebrew (Recommended for advanced users)**
1. Install Homebrew if not already installed: [brew.sh](https://brew.sh)
2. Install Python with tkinter support:
   ```bash
   brew install python-tk@3.12
   # Or for your specific Python version:
   brew install python-tk@3.11
   brew install python-tk@3.10
   ```
3. Verify installation: `python3 -c "import tkinter; print('tkinter is available')"`

**Method 3: Install tkinter for existing Python (via Homebrew)**
```bash
# Find your Python version
python3 --version

# Install matching tkinter (replace 3.12 with your version)
brew install tcl-tk
brew install python-tk@3.12

# You may need to reinstall Python to link with tcl-tk
brew reinstall python@3.12
```

**Method 4: Using ActiveTcl (Alternative)**
1. Download and install ActiveTcl from [ActiveState](https://www.activestate.com/products/tcl/)
2. Reinstall Python from python.org to link with the new Tcl/Tk installation

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3-tk
```

**CentOS/RHEL:**
```bash
sudo yum install tkinter
# or for newer versions
sudo yum install python3-tkinter
```

**Fedora:**
```bash
sudo dnf install python3-tkinter
```

**Windows:**
tkinter is included with Python installations from python.org. If missing, reinstall Python ensuring the "tcl/tk and IDLE" component is selected during installation.

### Step 3: Download the Application

1. **Clone the repository (if you have Git):**
   ```bash
   git clone <repository-url>
   cd suricata-generator
   ```

2. **Or download as ZIP:**
   - Download the ZIP file from the repository
   - Extract to a folder of your choice
   - Navigate to the extracted folder in your terminal/command prompt

### Step 4: Verify Dependencies

Run this command to verify all required Python modules are available:

```bash
python3 -c "
import tkinter
import re
import os
import ipaddress
import typing
import urllib.request
import urllib.error
print('All dependencies are available!')
"
```

If this command completes without errors, all required dependencies are installed.

### Step 5: Run the Application

Navigate to the application directory and run:

```bash
python3 suricata_generator.py
```

**Windows users may need to use:**
```cmd
python suricata_generator.py
```

### Troubleshooting

#### Common Issues:

1. **"python: command not found"**
   - Try `python3` instead of `python`
   - On Windows, ensure Python was added to PATH during installation
   - Restart your terminal/command prompt after Python installation

2. **"No module named 'tkinter'"**
   - Install tkinter using the platform-specific commands above
   - On some systems, try `python3-tk` instead of `python3-tkinter`

3. **Permission errors on Linux/macOS:**
   - Use `python3` instead of `python`
   - Don't use `sudo` to run the application
   - Ensure the script file has execute permissions: `chmod +x suricata_generator.py`

4. **Application doesn't start:**
   - Verify you're in the correct directory containing `suricata_generator.py`
   - Check Python version: `python3 --version` (must be 3.6+)
   - Verify all files are present in the directory

#### Getting Help:

- Ensure you're using Python 3.6 or higher
- Verify tkinter is properly installed
- Check that all application files are in the same directory
- Try running from the command line to see any error messages

## Creating a Standalone Executable (Optional)

If you want to create a standalone executable that can run without requiring Python to be installed, you can use PyInstaller. This is particularly useful for distributing the application to users who don't have Python installed.

### For macOS:

#### Step 1: Install PyInstaller

```bash
pip3 install pyinstaller
```

#### Step 2: Navigate to Application Directory

```bash
cd /path/to/suricata-generator-cline
```

#### Step 3: Create the Executable

**Option A: Single File Executable (Recommended)**
```bash
pyinstaller --onefile --windowed --name "Suricata Rule Generator" \
  --add-data "screenshot.png:." \
  --add-data "README.md:." \
  --add-data "RELEASE_NOTES.md:." \
  suricata_generator.py
```

**Option B: Directory-Based Bundle (Faster startup)**
```bash
pyinstaller --windowed --name "Suricata Rule Generator" \
  --add-data "screenshot.png:." \
  --add-data "README.md:." \
  --add-data "RELEASE_NOTES.md:." \
  suricata_generator.py
```

#### Step 4: Locate the Executable

The executable will be created in the `dist` directory:
- **Single file**: `dist/Suricata Rule Generator`
- **Directory bundle**: `dist/Suricata Rule Generator/Suricata Rule Generator`

#### Step 5: Test the Executable

```bash
# For single file
./dist/Suricata\ Rule\ Generator

# For directory bundle
./dist/Suricata\ Rule\ Generator/Suricata\ Rule\ Generator
```

### For Windows:

#### Step 1: Install PyInstaller

```cmd
pip install pyinstaller
```

#### Step 2: Create the Executable

```cmd
pyinstaller --onefile --windowed --name "Suricata Rule Generator" ^
  --add-data "screenshot.png;." ^
  --add-data "README.md;." ^
  --add-data "RELEASE_NOTES.md;." ^
  suricata_generator.py
```

The executable will be created at `dist\Suricata Rule Generator.exe`

### PyInstaller Options Explained:

- `--onefile`: Packages everything into a single executable file
- `--windowed`: Prevents console window from appearing (GUI only)
- `--name`: Sets the name of the executable
- `--add-data`: Includes additional files (screenshot, README, release notes)
- Note: The colon `:` is used on macOS/Linux, semicolon `;` on Windows

### Important Notes:

1. **Platform-Specific**: Executables must be built on the target platform:
   - Build on macOS to create macOS executable
   - Build on Windows to create Windows executable
   - Build on Linux to create Linux executable

2. **File Size**: Single-file executables are larger (40-60MB) because they bundle Python and all dependencies

3. **First Run**: Single-file executables extract to a temporary directory on first run, causing a slight startup delay

4. **Code Signing**: On macOS, unsigned applications may show security warnings. Users need to right-click and select "Open" the first time

5. **Dependencies**: All Python module dependencies are automatically detected and bundled by PyInstaller

### Troubleshooting PyInstaller:

**"ModuleNotFoundError" when running executable:**
- Use `--hidden-import` flag to explicitly include missing modules:
  ```bash
  pyinstaller --onefile --windowed --hidden-import=tkinter suricata_generator.py
  ```

**macOS Gatekeeper blocks the app:**
- Right-click the app and select "Open"
- Or disable Gatekeeper temporarily: `xattr -cr "Suricata Rule Generator.app"`

**Executable is too large:**
- Use directory-based bundle instead of `--onefile`
- Exclude unnecessary modules with `--exclude-module`

**"Failed to execute script" error:**
- Run without `--windowed` flag to see error messages
- Check that all required files are included with `--add-data`

### Alternative: py2app (macOS only)

For a more native macOS experience with .app bundle:

```bash
pip3 install py2app
py2applet --make-setup suricata_generator.py
python3 setup.py py2app
```

The .app bundle will be created in the `dist` directory and can be dragged to Applications folder.

## Usage

### Starting the Application

Launch the program to see a blank canvas with the tabbed editor at the bottom. The interface consists of:

- **Menu Bar**: File, Edit, Tools, and Help menus
- **Rules Table**: Displays all rules with color coding by action type
- **Tabbed Editor**: Bottom panel with Rule Editor and Rule Variables tabs
- **Control Buttons**: Rule management operations (context-sensitive display)

### Creating Rules

#### Individual Rules
1. Click in the empty area below existing rules to create a placeholder
2. Fill in the rule editor fields:
   - **Action**: pass, drop, reject, alert
   - **Protocol**: dcerpc, dhcp, dns, ftp, http, http2, icmp, ikev2, imap, ip, krb5, msn, ntp, quic, smb, smtp, ssh, tcp, tftp, tls, udp (21 protocols supported)
   - **Direction**: ->, <>
   - **Networks**: Source and destination (supports CIDR, "any", or variables like $HOME_NET)
   - **Ports**: Source and destination ports
   - **Message**: Descriptive text for the rule
   - **Content Keywords**: Suricata detection keywords
   - **SID**: Unique identifier (100-999999999)
3. Click "Save Changes" to add the rule

#### Rev Keyword Support *(New in v1.9.0)*

The application automatically manages Suricata rev keywords for rule versioning:

- **Automatic Display**: Rev field appears next to SID field in Rule Editor (read-only)
- **Smart Incrementing**: Rev automatically increments by 1 when rule fields change (except message)
- **Message Exception**: Changes to message field do NOT increment rev (allows documentation updates)
- **Default Values**: New rules start with rev=1; imported rules without rev get rev=1
- **Preservation**: Rules imported with existing rev values preserve their rev numbers
- **Universal Support**: Works with or without change tracking enabled
- **Clean Integration**: Rev changes excluded from change history to avoid clutter
- **Proper Positioning**: Rev keyword appears after sid keyword per Suricata standards
- **Edit Dialog Support**: Rev field shown in edit rule popup (read-only for safety)
- **Clipboard Integration**: Rev keywords included when copying/pasting rules

**Example rule with rev keyword:**
```
pass tls $HOME_NET any -> any any (tls.sni; content:".example.com"; endswith; msg:"Allow example.com"; sid:100; rev:2;)
```

### Bulk Domain Import
1. Go to **File > Import Domain List**
2. Select a .txt file containing one domain per line
3. Configure the import settings:
   - **Action**: pass, drop, or reject
   - **Starting SID**: First SID to use
   - **Message Template**: Use {domain} as placeholder
   - **PCRE Optimization**: *(New in v1.8.0)* Check to enable PCRE optimization for rule count reduction
   - **Alert on pass**: *(New in v1.12.7)* Control whether pass rules include alert keyword for logging
   - **Strict domain list**: *(New in v1.14.4)* Create a strict domain list (domain name must exactly match what is in the list.)
4. Click "Import" to generate rules

**Rule Generation Logic:**
- **All actions**: Creates 2 rules per domain (TLS + HTTP)
- **Pass action with "Alert on pass" enabled** *(default)*: Pass rules include embedded alert keyword for logging
- **Pass action with "Alert on pass" disabled**: Alert rule created for each Pass rule (each domain creates 4 rules for pass action)

**PCRE Optimization *(New in v1.8.0)*:**
- **Smart Domain Grouping**: Automatically groups related domains to reduce rule count by 40-75%
- **TLD Variations**: Groups `microsoft.com` and `microsoft.edu` → `microsoft\.(com|edu)` (8 rules → 4 rules)
- **Subdomain Patterns**: Groups `mail.google.com`, `drive.google.com` → `.*\.google\.com` (12 rules → 4 rules)
- **Real-time Preview**: Shows exact rule count savings before import
- **Mixed Approach**: Combines PCRE groups with individual rules for maximum efficiency
- **Professional PCRE Rules**: Uses proper Suricata `pcre:"/pattern/i"` syntax with case-insensitive matching

### Editing Rules

#### Inline Editing
1. Select a rule from the table
2. Modify fields in the bottom editor panel
3. Click "Save Changes" to apply modifications

#### Double-Click Editing *(Enhanced in v1.8.1)*
- **Rule Editing**: Double-click any rule to open a comprehensive edit dialog
- **Comment Editing**: Double-click comment lines to edit comment text directly
  - **Streamlined Interface**: Comment editing shows only the comment field without unnecessary rule fields
  - **Automatic Formatting**: Dialog strips `#` prefix for editing and ensures proper formatting when saving
  - **Consistent Experience**: Double-click works uniformly for both rules and comments

#### Rule Management
- **Delete**: Select rules and press Delete key or use "Delete Selected" button
- **Move**: Use "Move Up"/"Move Down" buttons to reorder rules
- **Insert**: Use "Insert Rule" to add rules at specific positions
- **Comments**: Use "Insert Comment" to add documentation or double-click existing comments to edit

### File Operations

- **New**: Start with a blank rule set
- **Open**: Load existing .suricata files
- **Save**: Save current rules to file
- **Save As**: Save with a new filename
- **Export**: Generate Terraform or CloudFormation templates for AWS Network Firewall
- **Load AWS Best Practices Template**: Fetch latest rules from AWS documentation

### Color Coding

Rules are color-coded in the table by action type:
- **Green**: pass actions
- **Blue**: alert actions  
- **Red**: drop actions
- **Purple**: reject actions
- **Grey**: comments
- **Yellow**: search result highlights (when searching)

### Keyboard Shortcuts

- **Ctrl+Z**: Undo last change
- **Ctrl+C**: Copy selected rules to clipboard
- **Ctrl+V**: Paste rules from clipboard
- **Delete**: Delete selected rules (context-sensitive - only when rules table has focus)
- **Space**: Toggle selected rules between enabled/disabled state (context-sensitive)
- **Down Arrow**: Navigate to placeholder row when at last rule
- **End**: Jump to placeholder row for new rule insertion
- **Home**: Jump to first rule and select it
- **Ctrl+G**: Jump to specific line number dialog
- **Enter**: Confirm dialogs
- **Ctrl+F**: Open Find dialog for searching rules
- **F3**: Find next occurrence in search results
- **Escape**: Close search mode and clear highlights

#### New Keyboard Features *(Added in v1.5.6)*
- **Space Bar Toggle**: Press Space to toggle selected rules between enabled (rule) and disabled (comment) state
  - **Smart Detection**: Only converts comments back to rules if they contain directional indicators
  - **Context Sensitive**: Only works when rules table has focus, preserves normal space behavior in text fields
  - **Multiple Selection**: Works on single rule or multiple selected rules simultaneously
- **Jump to Line (Ctrl+G)**: Navigate directly to any line number in the rules table
  - **Line Number Dialog**: Shows popup asking for target line number with validation
  - **Smart Navigation**: Jumps to placeholder row if line number exceeds total lines

### SID Management *(Added in v1.0.3)*
- **Tools > SID Management**: Open bulk SID renumbering dialog
- **Scope Options**: All rules, selected rules, or rules by action type
- **Conflict Detection**: Check for SID conflicts before applying changes
- **Resolution Strategies**: Skip conflicts, restart with safe SIDs, or overwrite existing rules
- **Undo Support**: All SID changes can be reverted with Ctrl+Z

### Enhanced Search Functionality *(Added in v1.6.6)*
- **Edit > Find (Ctrl+F)**: Open comprehensive search dialog with advanced filtering options
- **Field-Specific Search**: Search within specific fields or all fields
  - **Message**: Search rule message text
  - **Content**: Search content keywords and options
  - **Networks**: Search source and destination network fields
  - **Ports**: Search source and destination port fields
  - **SID**: Search specific rule IDs
  - **Protocol**: Search protocol types (tcp, udp, http, tls, etc.)
  - **All Fields**: Search across all rule components (default)
- **Action-Based Filtering**: Filter search results by rule action types
  - **Pass/Drop/Reject/Alert**: Individual action type filtering
  - **Comments**: Include or exclude comment lines from search
  - **Select All/Deselect All**: Convenient bulk selection controls
- **Advanced Search Options**: Flexible search behavior controls
  - **Case Sensitive**: Toggle case-sensitive matching
  - **Whole Word**: Match complete words only (word boundary detection)
  - **Regular Expression**: Use regex patterns for complex searches
  - **Include Comments**: Control whether comments are included in results
- **Search Navigation**: Efficient result browsing
  - **F3**: Find next occurrence in search results
  - **Escape**: Close search mode and clear highlights
  - **Visual Highlighting**: Yellow background highlighting of matches
- **Status Bar Integration**: Real-time search feedback
  - **Position Display**: Shows current position (e.g., "Search: 2 of 5 matches for 'tcp'")
  - **Match Count**: Total number of matches found
  - **Search Term**: Currently active search term

### Change Tracking *(Added in v1.2.0)*
- **Tools > Enable Change Tracking**: Toggle comprehensive change tracking on/off
- **Change History Tab**: View detailed audit trail of all operations
- **Automatic Headers**: Files include creation and modification timestamps when tracking enabled
- **Persistent History**: Changes saved to companion .history files
- **History Export**: Export change history to text files for documentation
- **Operation Tracking**: Logs rule additions, modifications, deletions, moves, and bulk operations
- **Variable Tracking**: Tracks variable definitions, modifications, and deletions
- **File Operations**: Records file creation, opening, and saving activities
- **Auto-Detection**: Automatically enables tracking when opening files with existing history

## Rule Format

The application generates standard Suricata rule format:
```
action protocol src_net src_port direction dst_net dst_port (options)
```

Example:
```
pass tls $HOME_NET any -> any any (tls.sni; content:".example.com"; endswith; nocase; msg:"Domain allow rule for example.com"; sid:100;)
```

## Network Field Validation

Source and destination network fields accept:
- **"any"**: Matches all networks
- **CIDR notation**: e.g., 192.168.1.0/24, 10.0.0.1/32
- **Variables**: Starting with $ or @ (e.g., $HOME_NET, @WEB_PORTS)

## Variable Management

The Rule Variables tab provides comprehensive variable management:

### Variable Types
- **IP Sets ($)**: Network variables like $HOME_NET with CIDR definitions
- **Port Sets ($)**: Port variables like $WEB_PORTS with port/range definitions  
- **Reference Sets (@)**: AWS VPC IP Set Reference ARNs for dynamic updates

### Variable Features
- **Auto-Detection**: Automatically discovers variables used in rules
- **Persistent Storage**: Variables automatically saved/loaded via companion .var files
- **Default Values**: HOME_NET defaults to RFC1918 private address space
- **Validation**: CIDR and port format validation with negation support
- **Export Integration**: Variables are included in Terraform/CloudFormation exports

### Variable Formats
- **CIDR Lists**: `192.168.1.0/24,10.0.0.0/8,!172.16.0.0/12`
- **Port Lists**: `80,443,[8080:8090],!22`
- **Reference ARNs**: `arn:aws:ec2:region:account:managed-prefix-list/pl-id`

## SID Management

- SIDs must be unique within the rule group
- Valid range: 100-999999999
- Application auto-generates next available SID for new rules
- Duplicate SID validation prevents conflicts

## File Format

Rules are saved in standard Suricata format (.suricata extension) with:
- Proper line endings
- Comment preservation
- Blank line support
- Original syntax preservation

## Rule Conflict Analysis

The application includes comprehensive rule analysis to detect shadowing and conflicts:

### Analysis Menu
- **Review Rules**: Analyze current ruleset for conflicts and shadowing issues
- **Variable Definition**: Define CIDR ranges for network variables during analysis
- **Detailed Reporting**: Categorized findings with severity levels and recommendations

### Conflict Detection
- **Complete Shadow Detection**: Only flags cases where upper rule ALWAYS prevents lower rule execution
- **Enhanced Protocol Layering Detection**: Universal detection across all protocol combinations (IP, ICMP, UDP, TCP vs HTTP, TLS, DNS, FTP, SSH, SMTP, etc.)
- **Flow State Analysis**: Understands Suricata flow keywords (established vs not_established)
- **Protocol Layer Separation**: Distinguishes between application and network layer rules with comprehensive protocol classification
- **Smart Mitigation Detection**: Recognizes flow keywords (established, to_server, to_client, stateless, flowbits) that prevent layering issues
- **Geographic Specificity**: Recognizes intentional geographic rule layering
- **Flowbits Dependencies**: Accounts for conditional rule execution
- **Action-Aware Analysis**: Different handling for alert vs pass vs drop/reject combinations

### Report Categories
- **Critical**: Security bypasses (pass rules shadowing drop/reject rules)
- **Warning**: Missing alerts (drop/reject rules shadowing alert rules) and unreachable rules
- **Informational**: Redundant rules with same actions

### Enhanced Report Features
- **Professional HTML Export**: Formatted reports with timestamps and version info
- **PDF Export**: Browser-based PDF generation for documentation
- **Right-click Copy**: Copy analysis results to clipboard
- **Disclaimer Boilerplate**: Professional analysis disclaimers with legal language
- **Actionable Recommendations**: Specific suggestions for rule reordering
- **Comprehensive Metadata**: Tool version, analysis timestamp, and file information

## Tips

1. **Start Simple**: Begin with basic pass/drop rules before adding complex content keywords
2. **Use Templates**: Leverage AWS best practices template and bulk domain import
3. **Organize Rules**: Use comments to document rule sections
4. **Manage Variables**: Use the Variables tab to define and organize network variables
5. **Export Early**: Generate infrastructure templates to validate deployment requirements
6. **Copy/Paste Workflow**: Use toggle selection to copy rules, deselect, then paste elsewhere
7. **Validate Networks**: Ensure network fields use proper CIDR notation or variables
8. **Analyze Conflicts**: Use Tools > Review Rules to check for shadowing issues
9. **Click-to-Insert**: Click below the last rule to quickly add new entries
10. **Backup Files**: Save frequently and use version control for rule files
11. **Search Efficiently**: Use Ctrl+F to find rules, F3 to navigate results
12. **Monitor Status**: Watch the status bar for rule counts, SID ranges, and warnings
13. **Protocol Validation**: Pay attention to orange warning icons for unusual port combinations
14. **Persistent Variables**: Variables are automatically saved with your .suricata files
15. **Change Tracking**: Enable tracking for comprehensive audit trails and history logging

## Troubleshooting

**Common Issues:**
- **SID Conflicts**: Ensure all SIDs are unique before saving (auto-resolved in copy/paste)
- **Network Validation**: Use proper CIDR format or predefined variables
- **Variable Definitions**: Define variables in Variables tab for export and analysis
- **File Permissions**: Ensure write access to save locations
- **Large Files**: Application handles files up to 200K characters efficiently
- **Network Connectivity**: AWS template loading and export require internet access
- **Analysis Variables**: Define network variables for accurate conflict detection
- **Export Capacity**: Ensure rule count plus buffer fits within AWS limits (30,000 capacity)
- **Search Not Working**: Ensure search term matches rule content (case-insensitive)
- **Variables Not Persisting**: Check for companion .var files in same directory as .suricata files
- **Protocol Warnings**: Orange warning icons indicate unusual protocol/port combinations (informational only)
- **Status Bar Issues**: Undefined variables warning indicates missing variable definitions

## Infrastructure as Code Export

Generate AWS Network Firewall resources for deployment:

### Export Formats
- **Terraform (.tf)**: Complete resource definition with variables and references
- **CloudFormation (.cft)**: JSON template with proper AWS resource structure

### Export Features
- **Dynamic Capacity**: Calculates actual rule count plus 100 buffer for growth
- **Variable Integration**: Includes IP sets, port sets, and reference sets from Variables tab
- **STRICT_ORDER**: Configures rule processing order for predictable behavior
- **Version Tracking**: Includes generator version in resource descriptions
- **Proper Escaping**: Handles special characters for infrastructure syntax

### Template Structure
```hcl
resource "aws_networkfirewall_rule_group" "suricata_rule_group" {
  capacity = 150  # Auto-calculated
  type     = "STATEFUL"
  
  rule_group {
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set { definition = ["10.0.0.0/8", "172.16.0.0/12"] }
      }
    }
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }
}
```

## Copy/Paste Workflow

Efficient rule management with clipboard operations:

### Copy Operations
- **Multi-Select**: Copy multiple rules simultaneously
- **SID Regeneration**: Automatically assigns new SIDs to prevent conflicts
- **Structure Preservation**: Maintains comments, blank lines, and formatting
- **Keyboard Shortcuts**: Ctrl+C or right-click context menu

### Paste Operations
- **Position Control**: Paste at selected location or end of list
- **Conflict Prevention**: Auto-generates unique SIDs for pasted rules
- **Undo Support**: Full undo capability for paste operations
- **Visual Feedback**: Confirmation messages with paste details

### Selection Management
- **Toggle Selection**: Click selected rules again to deselect
- **Clear Selection**: Click empty areas to clear all selections
- **Context Menus**: Right-click for copy/paste options
- **Multi-Rule Operations**: Select multiple rules for batch operations

## Advanced Features

### AWS Integration
- **Dynamic Template Loading**: Fetches latest best practices from AWS documentation
- **HTML Parsing**: Extracts Suricata rules from AWS security guides
- **Template Updates**: Stay current with AWS Network Firewall recommendations
- **Infrastructure Export**: Generate deployment-ready Terraform and CloudFormation

### User Interface Enhancements
- **Tabbed Interface**: Organized workflow with Rule Editor and Variables tabs
- **Context-Sensitive UI**: Buttons appear/hide based on active tab
- **Placeholder Row Management**: Visual indicator for new rule insertion points
- **Keyboard Navigation**: Efficient rule navigation without mouse interaction
- **Inline Comment Editing**: Edit comments directly in the bottom panel
- **Multiple Selection**: Select and delete multiple rules simultaneously
- **Toggle Selection**: Click to deselect for improved copy/paste workflow
- **Enhanced Status Bar**: Real-time statistics with colored action counts and warnings
- **Search Integration**: Traditional Windows-style search with highlighting
- **Protocol Validation**: Subtle tooltip warnings for unusual protocol/port combinations

### Rule Analysis Engine
- **Complete Shadow Detection**: Advanced algorithm to eliminate false positives
- **Multi-dimensional Analysis**: Protocol, network, port, and content overlap detection
- **Intentional Pattern Recognition**: Identifies legitimate layered security architectures
- **Variable Resolution**: Handles network variable definitions for accurate analysis
- **Flow State Analysis**: Understands Suricata flow keywords and dependencies
- **Professional Reporting**: HTML/PDF export with comprehensive metadata and disclaimers

### Data Persistence
- **Companion .var Files**: Automatic variable storage alongside .suricata files
- **JSON Format**: Human-readable variable definitions for version control
- **Automatic Loading**: Variables restored when opening associated .suricata files
- **Cross-Session Continuity**: Variable definitions persist between application sessions

### Change Tracking System
- **Comprehensive Audit Trail**: Complete logging of all rule and variable operations
- **Timestamped Headers**: Automatic file headers with creation and modification timestamps
- **Persistent History**: Companion .history files store detailed change logs
- **Operation Categories**: Rule operations, variable operations, file operations, and bulk operations
- **History Export**: Export change history for documentation and compliance
- **Auto-Detection**: Seamless integration with existing files that have history
- **User Control**: Toggle tracking on/off based on project requirements
- **Cross-Session Continuity**: History persists across application sessions

### Modular Architecture *(Enhanced in v1.6.7)*
- **Component Separation**: Well-organized codebase with dedicated modules for specific functionality
- **UIManager**: Centralized management of all user interface components, menus, event handling, and visual elements
- **SearchManager**: Comprehensive search functionality with field-specific search, filtering, and navigation
- **FileManager**: All file I/O operations including .suricata files, companion .var files, and export functionality  
- **DomainImporter**: Bulk domain import operations and AWS template loading capabilities
- **RuleAnalyzer**: Advanced rule conflict detection, shadowing analysis, and professional report generation
- **SuricataRule**: Core rule parsing, validation, and formatting functionality
- **Composition Pattern**: Main application uses manager instances through composition for better maintainability
- **Enhanced Maintainability**: Focused modules with single responsibilities for easier testing and code reuse

## Technical Architecture

The application follows a modular architecture pattern with specialized managers:

- **Main Application** (`suricata_generator.py`): Core application logic and manager coordination
- **UI Manager** (`ui_manager.py`): Complete user interface management and event handling
- **Search Manager** (`search_manager.py`): Advanced search capabilities with filtering and navigation
- **File Manager** (`file_manager.py`): All file operations, exports, and companion file management
- **Domain Importer** (`domain_importer.py`): Bulk domain processing and AWS template integration
- **Rule Analyzer** (`rule_analyzer.py`): Sophisticated conflict detection and analysis reporting
- **Flow Tester** (`flow_tester.py`): Interactive flow testing and network traffic simulation
- **Suricata Rule** (`suricata_rule.py`): Core rule parsing, validation, and string formatting
- **Security Validator** (`security_validator.py`): Comprehensive input validation and security protection
- **Constants** (`constants.py`): Application constants, limits, and validation patterns
- **Version** (`version.py`): Centralized version management for main application and components

### Security Features
The Security Validator module provides protection against:
- **Injection Attacks**: Filters dangerous patterns and script injection attempts
- **Path Traversal**: Validates filenames and prevents directory traversal
- **Input Validation**: Enforces length limits and character restrictions
- **File Operation Security**: Validates file sizes and access permissions
- **Domain Validation**: Ensures proper domain name format and safety

This architecture provides excellent separation of concerns, making the codebase more maintainable, testable, and extensible while maintaining robust security controls throughout the application.

## Version

Current version: 1.14.5

## Support

For issues or questions, refer to the application's Help > About dialog or review the source code comments for detailed implementation information.
