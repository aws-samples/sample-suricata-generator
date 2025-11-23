# Suricata Rule Generator for AWS Network Firewall

A GUI application for creating, editing, and managing Suricata rules specifically designed for AWS Network Firewall deployments.

## Overview

This application provides an intuitive graphical interface for generating Suricata rules with features tailored for AWS Network Firewall use cases. It supports individual rule creation, bulk domain rule generation, and comprehensive rule management with inline editing capabilities.  It also includes an advanced editor with IDE like capabilities for those that prefer more direct control *(New in v1.19.0)*.

## Screenshot

![Suricata Rule Generator Interface](screenshot.png)

*The main interface showing the color-coded rules table, tabbed editor with Rule Editor and Rule Variables tabs, and comprehensive rule management controls.*

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Requirements](#requirements)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Creating a Standalone Executable (Optional)](#creating-a-standalone-executable-optional)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Rule Format](#rule-format)
- [Network Field Validation](#network-field-validation)
- [Variable Management](#variable-management)
- [SID Management](#sid-management)
- [File Format](#file-format)
- [Rule Conflict Analysis](#rule-conflict-analysis)
- [Tips](#tips)
- [Troubleshooting](#troubleshooting)
- [Infrastructure as Code Export](#infrastructure-as-code-export)
- [Copy/Paste Workflow](#copypaste-workflow)
- [Advanced Features](#advanced-features)
- [Content Keywords JSON Structure](#content-keywords-json-structure)
- [Technical Architecture](#technical-architecture)
- [Version](#version)
- [Support](#support)

---

## Quick Start

> 💡 **New to the application?** Follow these steps to get started quickly!

### For Experienced Python Users

```bash
# 1. Verify Python 3.6+ is installed
python3 --version

# 2. Clone the repository
git clone https://github.com/aws-samples/sample-suricata-generator
cd sample-suricata-generator

# 3. Run the application
python3 suricata_generator.py
```

### First Time Setup

1. ✅ **Install Python 3.6+** - See [Prerequisites](#prerequisites) for detailed instructions
2. ✅ **Verify tkinter** - Run: `python3 -c "import tkinter; print('tkinter is available')"`
3. ✅ **Download** - Clone repository or download ZIP file
4. ✅ **Run** - Execute: `python3 suricata_generator.py`

### Your First Rule

1. 📝 Click in the empty area below the table to add a new rule
2. 🎯 Fill in the fields (Action, Protocol, Networks, Ports, Message, SID)
3. 💾 Click "Save Changes"
4. 🎉 Your rule appears in the table!

> ⚠️ **Need help?** Check the [Installation](#installation) section for detailed setup instructions or [Troubleshooting](#troubleshooting) if you encounter issues.

---

## Features

- **Visual Rule Management**: Color-coded table display with line numbers
- **Tabbed Interface**: Rule Editor and Rule Variables tabs for organized workflow
- **Inline Editing**: Bottom panel editor for modifying rules
- **Advanced Editor**: *(New in v1.19.0)* IDE-style text editor with auto-complete, syntax validation, and find/replace
- **Variable Management**: Auto-detection and management of network variables ($HOME_NET, @PORT_SETS)
- **Infrastructure Export**: Generate Terraform (.tf) and CloudFormation (.cft) templates
- **Copy/Paste Functionality**: Copy rules with Ctrl+C/V and right-click context menus
- **Toggle Selection**: Click selected rules again to deselect for improved workflow experience
- **Bulk Domain Import**: Generate multiple rules from domain lists with automatic domain consolidation
- **Rule Validation**: Network field validation and SID uniqueness checking
- **File Operations**: Open, save, and manage .suricata rule files
- **Comment Support**: Add and edit comment lines with proper formatting
- **Undo Functionality**: Revert changes with Ctrl+Z
- **Rule Movement**: Reorder rules with up/down controls
- **AWS Template Loading**: Dynamic fetching of latest AWS best practices rules template
- **Click-to-Insert**: Click below last rule to add new entries
- **Keyboard Navigation**: Down arrow and End key navigates to placeholder row
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

---

## Prerequisites

> ⚠️ **Before installing**, ensure your system meets these requirements.

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

The application uses tkinter for its graphical user interface. **Important:** tkinter may not installed by default on macOS and some Linux distributions require separate installation.

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

## Installation

> 💡 **Prerequisites installed?** See the [Prerequisites](#prerequisites) section above if you haven't set up Python and tkinter yet.

### Step 1: Download the Application

1. **Clone the repository (if you have Git):**
   ```bash
   git clone https://github.com/aws-samples/sample-suricata-generator
   cd sample-suricata-generator
   ```

2. **Or download as ZIP:**
   - Download the ZIP file from [GitHub repository](https://github.com/aws-samples/sample-suricata-generator)
   - Extract to a folder of your choice
   - Navigate to the extracted folder in your terminal/command prompt

### Step 2: Verify Dependencies

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

> ✅ **Success?** If this command completes without errors, you're ready to run the application!

### Step 3: Run the Application

Navigate to the application directory and run:

```bash
python3 suricata_generator.py
```

**Windows users may need to use:**
```cmd
python suricata_generator.py
```

> ⚠️ **Trouble starting?** Check the [Troubleshooting](#troubleshooting) section below for common solutions.

---

## Basic Usage

### 🚀 Starting the Application

Launch the program to see a blank canvas with the tabbed editor at the bottom. The interface consists of:

- **Menu Bar**: File, Edit, Tools, and Help menus
- **Rules Table**: Displays all rules with color coding by action type
- **Tabbed Editor**: Bottom panel with Rule Editor and Rule Variables tabs
- **Control Buttons**: Rule management operations (context-sensitive display)

### 📝 Creating Rules

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
   - **SID**: Unique identifier (1-999999999)
3. Click "Save Changes" to add the rule

> 💡 **Tip:** The application auto-generates the next available SID for new rules, but you can change it to any unique value between 1-999999999.

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

### ✏️ Editing Rules

#### Inline Editing
1. Select a rule from the table
2. Modify fields in the bottom editor panel
3. Click "Save Changes" to apply modifications

#### Double-Click Editing
- 🖱️ **Rule Editing**: Double-click any rule to open a comprehensive edit dialog
- 💬 **Comment Editing**: Double-click comment lines to edit comment text directly
  - **Streamlined Interface**: Comment editing shows only the comment field without unnecessary rule fields
  - **Automatic Formatting**: Dialog strips `#` prefix for editing and ensures proper formatting when saving

#### Rule Management
- 🗑️ **Delete**: Select rules and press Delete key or use "Delete Selected" button
- ⬆️⬇️ **Move**: Use "Move Up"/"Move Down" buttons to reorder rules
- ➕ **Insert**: Use "Insert Rule" to add rules at specific positions
- 💬 **Comments**: Use "Insert Comment" to add documentation

### 📁 File Operations

- **New**: Start with a blank rule set
- **Open**: Load existing .suricata files
- **Save**: Save current rules to file
- **Save As**: Save with a new filename

> 💡 **Tip:** The application supports persistent variables - your variable definitions are automatically saved alongside your .suricata files as companion .var files.

### 🎨 Color Coding

Rules are color-coded in the table by action type:
- 🟢 **Green**: pass actions
- 🔵 **Blue**: alert actions  
- 🔴 **Red**: drop actions
- 🟣 **Purple**: reject actions
- ⚫ **Grey**: comments
- 🟡 **Yellow**: search result highlights (when searching)

### ⌨️ Keyboard Shortcuts

> 💡 **Pro tip:** Learn these shortcuts to work more efficiently!

- **Ctrl+Z**: Undo last change
- **Ctrl+C**: Copy selected rules to clipboard
- **Ctrl+V**: Paste rules from clipboard
- **Delete**: Delete selected rules (context-sensitive)
- **Space**: Toggle selected rules between enabled/disabled
- **Down Arrow**: Navigate to placeholder row when at last rule
- **End**: Jump to placeholder row for new rule insertion
- **Home**: Jump to first rule and select it
- **Ctrl+G**: Jump to specific line number dialog
- **Ctrl+F**: Open Find dialog for searching rules
- **Ctrl+E**: Open advanced editor window
- **F3**: Find next occurrence in search results
- **Escape**: Close search mode and clear highlights

---

## Advanced Usage

### 📦 Bulk Domain Import
1. Go to **File > Import Domain List**
2. Select a .txt file containing one domain per line
3. Configure the import settings:
   - **Action**: pass, drop, or reject
   - **Starting SID**: First SID to use
   - **Message Template**: Use {domain} as placeholder
   - **Alert on pass**: Control whether pass rules include alert keyword for logging
   - **Strict domain list**: Create a strict domain list (domain name must exactly match what is in the list)
4. Click "Import" to generate rules

**Rule Generation Logic:**
- **All actions**: Creates 2 rules per domain (TLS + HTTP)
- **Pass action with "Alert on pass" enabled** *(default)*: Pass rules include embedded alert keyword for logging
- **Pass action with "Alert on pass" disabled**: Alert rule created for each Pass rule (each domain creates 4 rules for pass action)

> ⚡ **Automatic Domain Consolidation** Default behavior reduces rule count by finding the most specific common parent domains!

**Domain Consolidation Benefits:**
- 📊 **Smart Grouping**: Automatically finds most specific common parent for related domains
- 🎯 **Optimal Parents**: Groups `mail.server.com`, `web.server.com`, `server.com` → `*.server.com` (6 rules → 2 rules)
- 💡 **Intelligent Algorithm**: Filters subset groups to find maximal consolidation opportunities
- 👁️ **Real-time Preview**: Shows exact rule count savings before import
- 🔧 **Automatic**: Enabled by default when "Strict domain list" is unchecked

### 📥 Import Stateful Rule Group *(New in v1.18.7)*

Import existing AWS Network Firewall stateful rule groups directly from AWS for editing and enhancement:

#### Generating the JSON File

Use the AWS CLI to export your rule group to JSON format:

```bash
aws network-firewall describe-rule-group --rule-group-arn <RULE_GROUP_ARN> > stateful_rule_group.json
```

**Example:**
```bash
aws network-firewall describe-rule-group \
  --rule-group-arn arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/MyRuleGroup \
  > my_rule_group.json
```

**Alternative using Rule Group Name:**
```bash
aws network-firewall describe-rule-group \
  --rule-group-name MyRuleGroup \
  --type STATEFUL \
  > my_rule_group.json
```

For complete AWS CLI documentation, see: [AWS CLI describe-rule-group reference](https://docs.aws.amazon.com/cli/latest/reference/network-firewall/describe-rule-group.html)

#### Importing the Rule Group

1. Go to **File > Import Stateful Rule Group**
2. Select the JSON file generated from AWS CLI
3. Review the preview dialog showing:
   - Rule group name and description
   - Number of rules and variables to import
   - Preview of first 10 rules
   - Any SID conflicts within the JSON (if present)
4. Click "Import" to load the rule group

#### Import Features

- **Complete Data Import**: Imports rules, variables (IPSets and PortSets), and metadata
- **Metadata Preservation**: Adds comment header with original AWS attributes:
  ```
  # Original Rule Group attributes:
  #   RuleGroupArn: arn:aws:network-firewall:...
  #   RuleGroupName: MyRuleGroup
  #   RuleGroupId: abc123...
  #   Description: Production firewall rules
  ```
- **Format Conversion**: Automatically converts AWS 5-tuple format to Suricata format
- **Variable Mapping**: IPSets and PortSets imported with $ prefix (e.g., HOME_NET → $HOME_NET)
- **Type Validation**: Only imports STATEFUL rule groups (rejects STATELESS with clear error)
- **SID Management**: Detects and auto-renumbers any duplicate SIDs within the JSON
- **Force New File**: Clears current content for clean import (prompts to save changes first)

#### Use Cases

- **Edit AWS Rules**: Import existing AWS Network Firewall stateful rule groups for modification in the GUI
- **Round-Trip Workflow**: Export from AWS → Import to Generator → Edit → Export back to AWS
- **Rule Documentation**: Add comments and organize imported rules before re-deployment
- **Bulk Modifications**: Use SID Management and other tools on imported AWS rule groups
- **Begin using Suricata**: Importing standard stateful rule groups allows for quickly and easily switching to Suricata for managing existing rule groups

### 🔢 SID Management

> 💡 **Managing lots of rules?** Use SID Management to bulk renumber rules and avoid conflicts.

- **Tools > SID Management**: Open bulk SID renumbering dialog
- **Scope Options**: All rules, selected rules, or rules by action type
- **Conflict Detection**: Check for SID conflicts before applying changes
- **Resolution Strategies**: Skip conflicts, restart with safe SIDs, or overwrite existing rules
- ↩️ **Undo Support**: All SID changes can be reverted with Ctrl+Z

### 🔍 Enhanced Search Functionality

- **Edit > Find (Ctrl+F)**: Open comprehensive search dialog with advanced filtering options
- **Field-Specific Search**: Search within specific fields or all fields
  - 💬 **Message**: Search rule message text
  - 📄 **Content**: Search content keywords and options
  - 🌐 **Networks**: Search source and destination network fields
  - 🔌 **Ports**: Search source and destination port fields
  - 🔢 **SID**: Search specific rule IDs
  - 📡 **Protocol**: Search protocol types (tcp, udp, http, tls, etc.)
  - 🌍 **All Fields**: Search across all rule components (default)
- **Action-Based Filtering**: Filter search results by rule action types
  - Pass/Drop/Reject/Alert: Individual action type filtering
  - Comments: Include or exclude comment lines from search
  - Select All/Deselect All: Convenient bulk selection controls
- **Advanced Search Options**: Flexible search behavior controls
  - Case Sensitive, Whole Word, Regular Expression
  - Visual Highlighting: Yellow background for matches
- **Navigation**: F3 for next, Shift+F3 for previous, Escape to close

### 📊 Change Tracking

> 📝 **Need an audit trail?** Enable Change Tracking to log all operations with timestamps and detailed history.

- **Tools > Enable Change Tracking**: Toggle comprehensive change tracking on/off
- **Change History Tab**: View detailed audit trail of all operations
- **Automatic Headers**: Files include creation and modification timestamps when tracking enabled
- **Persistent History**: Changes saved to companion .history files
- **History Export**: Export change history to text files for documentation
- **Operation Tracking**: Logs rule additions, modifications, deletions, moves, and bulk operations
- **Auto-Detection**: Automatically enables tracking when opening files with existing history

### 💻 Advanced Editor *(New in v1.19.0)*

The Advanced Editor provides a powerful IDE-style text interface for users who prefer direct rule editing:

#### Accessing the Advanced Editor
- **Tools > Advanced Editor** (Ctrl+E)
- **Modal Window**: 1000x700 resizable with line numbers and status bar
- **Scope**: Edits all rules with variables displayed as-is (e.g., $HOME_NET)

#### Real-Time Syntax Validation
- **Two-Level System**: Red underlines for errors, orange for warnings
- **Error Detection**: Invalid actions, protocols, networks, ports, direction, malformed syntax
- **Warning Detection**: Unknown keywords, undefined variables, duplicate SIDs
- **Live Feedback**: Validates as you type (500ms delay) with error counts in status bar
- **Hover Tooltips**: Mouse over underlined text for detailed error information with suggestions
- **Auto-Comment**: Rules with errors automatically commented out with `# [SYNTAX ERROR]` when saving back to main program

#### Smart Auto-Complete
- **Context-Aware**: Intelligent suggestions based on cursor position
  - Actions: alert, pass, drop, reject, # (comment)
  - Protocols: All 26 supported protocols (tcp, udp, tls, http, dns, etc.)
  - Networks/Ports: "any", common CIDRs, port ranges, and defined variables
  - Content Keywords: 50+ Suricata keywords loaded from content_keywords.json
- **Trigger Methods**: Auto-appears while typing or manual with Ctrl+Space
- **Accept**: Tab or Enter, navigate with Up/Down arrows

#### Advanced Editing Features
- **Auto-Close Characters**: `(` `[` `"` automatically insert matching closing character
- **Smart Tab**: Tab jumps to next semicolon in rule options for rapid keyword entry
- **Smart Backspace**: Deleting opening bracket/quote also deletes matching closing character
- **Comment Toggle**: Ctrl+/ to comment/uncomment selected lines
- **Clipboard**: Standard Ctrl+X/C/V with system clipboard integration
- **Undo/Redo**: Full multi-level undo (Ctrl+Z) and redo (Ctrl+Y)
- **Go to Line**: Ctrl+G for quick navigation

#### Find and Replace
- **Unified Dialog**: Ctrl+F opens comprehensive Find and Replace dialog
- **Field-Specific**: Search in specific fields (message, content, networks, ports, SID, protocol, or all)
- **Action Filtering**: Include/exclude pass, drop, reject, alert rules and comments
- **Advanced Options**: Case-sensitive, whole word matching, regular expression support
- **Visual Highlighting**: Current match in yellow, other matches in gray
- **Navigation**: F3 for next, Shift+F3 for previous, Escape to close
- **Replace Operations**: Replace current match or Replace All with confirmation

#### User Interface
- **Line Numbers**: Always visible in left gutter
- **Status Bar**: Cursor position (Ln/Col), total lines, current rule number, modification status, validation status
- **Synchronized Scrolling**: Line numbers scroll with editor content
- **Right-Click Menu**: Cut/copy/paste, select all, find/replace, toggle comment, error details
- **Keyboard Shortcuts**: Built-in reference guide via "Shortcuts" button

#### Content Keywords Customization
- **External JSON**: `content_keywords.json` contains all Suricata keyword definitions
- **Hot Reload**: File loaded each time editor opens (edit JSON, reopen to see changes)
- **Easy Customization**: Add new keywords without modifying program code
- **Comprehensive Coverage**: Syntax, valid values, descriptions, and categories for each keyword
- **Graceful Degradation**: If file missing/corrupted, editor continues with basic auto-complete
- **Future-Proof**: Unknown keywords generate warnings (not errors) for new Suricata features

#### Save and Validation
- **Comprehensive Validation**: All rules validated and categorized when clicking OK
- **Error Rules**: Auto-commented with `# [SYNTAX ERROR]` prefix
- **Warning Rules**: Preserved as-is (unknown keywords, undefined variables allowed)
- **Confirmation Dialog**: Shows detailed summary of errors, warnings, and actions
- **Auto-Create Variables**: Undefined variables automatically created with empty definitions
- **Cancel Protection**: Unsaved changes prompt confirmation before discarding

**Use Cases:**
- **Power Users**: Text-based workflow for those comfortable with Suricata syntax
- **Bulk Editing**: Efficient for large-scale modifications and copy/paste operations
- **Professional IDE**: Auto-complete and validation match modern code editor expectations
- **Safety Net**: Real-time validation prevents invalid rules from breaking rule sets

### 📤 Infrastructure Export

> 🏗️ **Deploy to AWS** Export your rules as Terraform or CloudFormation templates for infrastructure as code deployment.

Generate AWS Network Firewall resources for deployment:

**Export Formats:**
- **Terraform (.tf)**: Complete resource definition with variables and references
- **CloudFormation (.cft)**: JSON template with proper AWS resource structure

**Export Features:**
- ⚙️ **Dynamic Capacity**: Calculates actual rule count plus 100 buffer for growth
- 🔗 **Variable Integration**: Includes IP sets, port sets, and reference sets from Variables tab
- 📋 **STRICT_ORDER**: Configures rule processing order for predictable behavior
- 📝 **Version Tracking**: Includes generator version in resource descriptions
- 🔒 **Proper Escaping**: Handles special characters for infrastructure syntax

**Template Structure Example:**
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

### 🌐 AWS Template Loading

- **File > Load AWS Best Practices Template**: Dynamically fetches latest rules from AWS documentation
- **HTML Parsing**: Extracts Suricata rules from AWS security guides
- **Template Updates**: Stay current with AWS Network Firewall recommendations

> ⚠️ **Note:** Requires internet connection to fetch templates from AWS documentation.

---

## Rule Format

The application generates standard Suricata rule format:
```
action protocol src_net src_port direction dst_net dst_port (options)
```

**Example:**
```
pass tls $HOME_NET any -> any any (tls.sni; content:".example.com"; endswith; nocase; msg:"Domain allow rule for example.com"; sid:100;)
```

---

## Network Field Validation

Source and destination network fields accept:
- 🌍 **"any"**: Matches all networks
- 📍 **CIDR notation**: e.g., 192.168.1.0/24, 10.0.0.1/32
- 🔤 **Variables**: Starting with $ or @ (e.g., $HOME_NET, @allow_list)

---

## Variable Management

> 💡 **Variables** simplify rule management by allowing reusable network and port definitions.

The Rule Variables tab provides comprehensive variable management:

### Variable Types
- **IP Sets ($)**: Network variables like $HOME_NET with CIDR definitions
- **Port Sets ($)**: Port variables like $WEB_PORTS with port/range definitions  
- **Reference Sets (@)**: AWS VPC IP Set Reference ARNs for dynamic updates

### Variable Features
- 🔍 **Auto-Detection**: Automatically discovers variables used in rules
- 💾 **Persistent Storage**: Variables automatically saved/loaded via companion .var files
- 🏠 **Default Values**: HOME_NET defaults to RFC1918 private address space
- ✅ **Validation**: CIDR and port format validation with negation support
- 📤 **Export Integration**: Variables are included in Terraform/CloudFormation exports

### Variable Formats
- **CIDR Lists**: `192.168.1.0/24,10.0.0.0/8,!172.16.0.0/12`
- **Port Lists**: `80,443,[8080:8090],!22`
- **Reference ARNs**: `arn:aws:ec2:region:account:managed-prefix-list/pl-id`

---

## SID Management

> 🔢 **SIDs** (Signature IDs) must be unique within your rule group.

- ✅ **Valid Range**: 1-999999999
- 🤖 **Auto-Generation**: Application auto-generates next available SID for new rules
- ⚠️ **Duplicate Prevention**: Built-in validation prevents conflicts

---

## File Format

Rules are saved in standard text format (.suricata extension) with:
- ✅ Proper line endings
- 💬 Comment preservation
- ⬜ Blank line support
- 🔒 Original syntax preservation

---

## Rule Conflict Analysis

> 🔍 **Analyze your rules** to detect shadowing and potential conflicts before deployment.

The rules analysis engine was designed to catch many of the common issues that customers make when working with Suricata. The application includes comprehensive rule analysis to detect rule shadowing and conflicts:

### Analysis Menu
- **Tools > Review Rules**: Analyze current ruleset for conflicts and shadowing issues
- **Variable Definition**: Define CIDR ranges for network variables during analysis
- **Detailed Reporting**: Categorized findings with severity levels and recommendations

### Conflict Detection Features
- ✅ **Complete Shadow Detection**: Only flags cases where upper rule ALWAYS prevents lower rule execution
- 🔄 **Protocol Layering Detection**: Universal detection across all protocol combinations
- 📊 **Flow State Analysis**: Understands Suricata flow keywords
- 🌐 **Geographic Specificity**: Recognizes intentional geographic rule layering
- 🎯 **Action-Aware Analysis**: Different handling for alert vs pass vs drop/reject combinations

### Report Categories
- 🔴 **Critical**: Security bypasses (pass rules shadowing drop/reject rules)
- 🟠 **Warning**: Missing alerts (drop/reject rules shadowing alert rules) and unreachable rules
- 🔵 **Informational**: Redundant rules with same actions

### Report Export
- 📄 **HTML Export**: Professional formatted reports with timestamps
- 📑 **PDF Export**: Browser-based PDF generation for documentation
- 📋 **Copy Support**: Right-click to copy analysis results

---

## Tips

> 💡 **Best Practices** for effective rule management

1. 🎯 **Start Simple**: Begin with basic pass/drop rules before adding complex content keywords
2. 📚 **Use Templates**: Leverage AWS best practices template and bulk domain import
3. 📝 **Organize Rules**: Use comments to document rule sections
4. 🔤 **Manage Variables**: Use the Variables tab to define and organize network variables
5. 🏗️ **Export Early**: Generate infrastructure templates to validate deployment requirements
6. 📋 **Copy/Paste Workflow**: Use toggle selection to copy rules, deselect, then paste elsewhere
7. ✅ **Validate Networks**: Ensure network fields use proper CIDR notation or variables
8. 🔍 **Analyze Conflicts**: Use Tools > Review Rules to check for shadowing issues
9. ➕ **Click-to-Insert**: Click below the last rule to quickly add new entries
10. 💾 **Backup Files**: Save frequently and use version control for rule files
11. 🔎 **Search Efficiently**: Use Ctrl+F to find rules, F3 to navigate results
12. 📊 **Monitor Status**: Watch the status bar for rule counts, SID ranges, and warnings
13. ⚠️ **Protocol Validation**: Pay attention to orange warning icons for unusual port combinations
14. 🔐 **Persistent Variables**: Variables are automatically saved with your .suricata files
15. 📈 **Change Tracking**: Enable tracking for comprehensive audit trails and history logging
16. 🚀 **Begin using Suricata**: Use the import feature to easily convert existing stateful standard rule groups over to Suricata

---

## Troubleshooting

> ⚠️ **Having issues?** Check these common problems and solutions.

### Common Issues

**🔴 SID Conflicts**
- Ensure all SIDs are unique before saving (auto-resolved in copy/paste)

**🌐 Network Validation**
- Use proper CIDR format or predefined variables

**🔤 Variable Definitions**
- Define variables in Variables tab for export and analysis

**📁 File Permissions**
- Ensure write access to save locations

**📊 Large Files**
- Application handles files up to 200K characters efficiently

**🌍 Network Connectivity**
- AWS template loading and export require internet access

**🔍 Analysis Variables**
- Define network variables for accurate conflict detection

**📦 Export Capacity**
- Ensure rule count plus buffer fits within AWS limits (30,000 capacity)

**🔎 Search Not Working**
- Ensure search term matches rule content (case-insensitive by default)

**💾 Variables Not Persisting**
- Check for companion .var files in same directory as .suricata files

**⚠️ Protocol Warnings**
- Orange warning icons indicate unusual protocol/port combinations (informational only)

---

## Infrastructure as Code Export

> 🏗️ **Deploy to AWS** with infrastructure as code templates.

*(See [Advanced Usage > Infrastructure Export](#-infrastructure-export) section for detailed information)*

---

## Copy/Paste Workflow

> 📋 **Efficient rule management** with clipboard operations.

### Intelligent Dual-Clipboard System

The application uses a sophisticated dual-clipboard system to handle different copy/paste scenarios:

#### Internal Clipboard (Pasting Within the Program)
When you copy rules with **Ctrl+C** and paste them with **Ctrl+V** within the same program instance:
- ✅ **Automatic SID Renumbering**: New SIDs are automatically generated to prevent conflicts
- ✅ **Conflict-Free**: Rules can be safely pasted multiple times without SID collisions
- ✅ **Seamless Workflow**: No manual SID adjustment needed when duplicating rules

**Example:**
```
1. Copy rule with SID:100
2. Paste within program → Automatically assigned SID:200 (or next available)
3. Paste again → Automatically assigned SID:201
```

#### System Clipboard (Pasting to External Programs)
When you copy rules to paste into external text editors, other files, or share with colleagues:
- 📋 **Original SIDs Preserved**: Rules maintain their original SID numbers
- 🔄 **Cross-File Sharing**: Enables moving rules between different .suricata files with SID integrity
- 🤝 **Collaboration**: Share rules with exact SID references for team coordination

**Example:**
```
1. Copy rule with SID:100
2. Paste to Notepad/TextEdit → Rule shows "sid:100;" (original SID preserved)
3. Paste to another .suricata file → Rule shows "sid:100;" (for manual management)
```

### How It Works

The application maintains **two clipboards simultaneously**:
1. **Internal clipboard**: Pre-calculated with new SIDs for conflict-free internal pasting
2. **System clipboard**: Contains rules with original SIDs for external use

**Smart Detection:**
- Internal paste: Uses internal clipboard when content matches last copy operation
- External paste: Detects external clipboard content and auto-assigns new SIDs to prevent conflicts
- Re-import protection: External rules pasted back get new SIDs automatically

### Copy Operations
- **Multi-Select**: Copy multiple rules simultaneously (Ctrl+C or right-click)
- **Dual Population**: Automatically populates both internal and system clipboards
- **Structure Preservation**: Maintains comments, blank lines, and formatting in both clipboards

### Paste Operations
- **Position Control**: Paste at selected location or end of list (Ctrl+V or right-click)
- **Intelligent Source**: Automatically detects whether to use internal or system clipboard
- **Conflict Prevention**: Always generates unique SIDs regardless of paste source
- ↩️ **Undo Support**: Full undo capability for all paste operations

### Use Cases

**Within Program (Internal Clipboard):**
- ✅ Duplicate rules for variations
- ✅ Copy templates to create similar rules
- ✅ Reorganize rules within the same file

**External Sharing (System Clipboard):**
- ✅ Share rules via email/chat with original SID references
- ✅ Copy rules to documentation with accurate SID numbers
- ✅ Move rules between different .suricata files for manual integration
- ✅ Copy to text editor for external editing and processing

---

## Advanced Features

> 🚀 **Power User Features** for advanced workflows.

*(This section provides a high-level overview. See [Advanced Usage](#advanced-usage) for detailed documentation of each feature.)*

### Key Capabilities
- 🌐 **AWS Integration**: Dynamic template loading and infrastructure export
- 🎨 **UI Enhancements**: Tabbed interface, context-sensitive controls, enhanced status bar
- 🔍 **Rule Analysis Engine**: Complete shadow detection and professional reporting
- 💾 **Data Persistence**: Companion files for variables and change history
- 📊 **Change Tracking System**: Comprehensive audit trail with history logging
- 🏗️ **Modular Architecture**: Well-organized codebase with dedicated manager modules

---

## Content Keywords JSON Structure

> 🔧 **Customize auto-complete** by editing the content_keywords.json file.

The `content_keywords.json` file allows users to customize and extend the auto-complete functionality in the Advanced Editor. This file defines all Suricata content keywords with their syntax, valid values, and descriptions.

### JSON File Format

```json
{
  "version": "1.0",
  "description": "AWS Network Firewall Suricata Content Keywords",
  "keywords": [
    {
      "name": "keyword_name",
      "syntax": "keyword_name:<value>",
      "values": ["optional", "list", "of", "valid", "values"],
      "description": "Human-readable description",
      "category": "general|flow|http|tls|dns|protocol"
    }
  ]
}
```

### Field Definitions

- **version**: Version number of the keyword definitions file (for tracking changes)
- **description**: Brief description of the keyword set
- **keywords**: Array of keyword objects, each containing:
  - **name** (required): The keyword name (e.g., "flow", "msg", "sid")
  - **syntax** (required): Template showing proper keyword syntax (e.g., "msg:\"<message>\"")
  - **values** (optional): Array of valid values for keywords with enumerated options
  - **description** (required): Human-readable explanation of the keyword's purpose
  - **category** (optional): Grouping category for organization

### Example Keywords

```json
{
  "version": "1.0",
  "description": "AWS Network Firewall Suricata Content Keywords",
  "keywords": [
    {
      "name": "flow",
      "syntax": "flow:<value>",
      "values": ["to_server", "to_client", "established", "not_established", "stateless"],
      "description": "Match on direction and state of the flow",
      "category": "flow"
    },
    {
      "name": "msg",
      "syntax": "msg:\"<message>\"",
      "description": "Rule message/description",
      "category": "general"
    },
    {
      "name": "sid",
      "syntax": "sid:<number>",
      "description": "Rule signature ID (1-999999999)",
      "category": "general"
    },
    {
      "name": "http.host",
      "syntax": "http.host; content:\"<domain>\"",
      "description": "Match HTTP host header",
      "category": "http"
    },
    {
      "name": "tls.sni",
      "syntax": "tls.sni; content:\"<domain>\"",
      "description": "Match TLS Server Name Indication",
      "category": "tls"
    }
  ]
}
```

### Adding New Keywords

To add a new keyword to the Advanced Editor's auto-complete:

1. 📝 **Open** `content_keywords.json` in a text editor
2. ➕ **Add** a new keyword object to the `keywords` array
3. 💾 **Save** the file
4. 🔄 **Reopen** the Advanced Editor (it reloads the JSON each time it opens)
5. ✅ **Test** the new keyword appears in auto-complete suggestions

### Hot Reload Feature

The Advanced Editor automatically reloads `content_keywords.json` each time it opens, allowing you to:
- Edit the JSON file while the main application is running
- Close the Advanced Editor
- Reopen the Advanced Editor to see your changes immediately
- No need to restart the main application

### Validation

> ⚠️ **Unknown keywords** generate warnings (not errors) for future compatibility.

The Advanced Editor validates unknown keywords as **warnings** (not errors), which means:
- Rules using undefined keywords are preserved (not commented out)
- Users can use new Suricata features before updating the JSON
- The JSON file can be gradually updated over time
- Forward compatibility is maintained

---

## Technical Architecture

The application follows a modular architecture pattern with specialized managers:

- **Main Application** (`suricata_generator.py`): Core application logic and manager coordination
- **UI Manager** (`ui_manager.py`): Complete user interface management and event handling
- **Advanced Editor** (`advanced_editor.py`): *(New in v1.19.0)* IDE-style text editor with auto-complete, validation, and find/replace
- **Search Manager** (`search_manager.py`): Advanced search capabilities with filtering and navigation
- **File Manager** (`file_manager.py`): All file operations, exports, and companion file management
- **Domain Importer** (`domain_importer.py`): Bulk domain processing and AWS template integration
- **Stateful Rule Importer** (`stateful_rule_importer.py`): Converts exported stateful rule groups to Suricata format
- **Rule Analyzer** (`rule_analyzer.py`): Sophisticated conflict detection and analysis reporting
- **Flow Tester** (`flow_tester.py`): Interactive flow testing and network traffic simulation
- **Suricata Rule** (`suricata_rule.py`): Core rule parsing, validation, and string formatting
- **Security Validator** (`security_validator.py`): Comprehensive input validation and security protection
- **Constants** (`constants.py`): Application constants, limits, and validation patterns
- **Version** (`version.py`): Centralized version management for main application and components

### Configuration Files
- **Content Keywords** (`content_keywords.json`): *(New in v1.19.0)* Extensible keyword definitions for Advanced Editor auto-complete

### Security Features
> 🔒 **Security First** - Built-in protection against common vulnerabilities.

The Security Validator module provides protection against:
- **Injection Attacks**: Filters dangerous patterns and script injection attempts
- **Path Traversal**: Validates filenames and prevents directory traversal
- **Input Validation**: Enforces length limits and character restrictions
- **File Operation Security**: Validates file sizes and access permissions
- **Domain Validation**: Ensures proper domain name format and safety

---

## Version

Current version: 1.19.1

## Support

For issues, questions, or to contribute to the project:

- 📚 **GitHub Repository**: [https://github.com/aws-samples/sample-suricata-generator](https://github.com/aws-samples/sample-suricata-generator)
- 💬 **Help Dialog**: Use Help > About in the application for version information
- 📖 **Documentation**: Review the source code comments for detailed implementation information
- 🐛 **Issues**: Report bugs or request features via GitHub Issues

---

**Repository**: [aws-samples/sample-suricata-generator](https://github.com/aws-samples/sample-suricata-generator)
