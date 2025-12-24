#!/usr/bin/env python3
"""
Advanced Editor for Suricata Rule Generator
Uses wxPython/Scintilla for professional code editing with native code folding

Launched as subprocess from main tkinter application.
Usage: python advanced_editor.py <input_json> <output_json>
"""

import sys
import os
import json
import re

# Try to import wxPython
try:
    import wx
    import wx.stc as stc
    HAS_WXPYTHON = True
except ImportError:
    HAS_WXPYTHON = False
    print("ERROR: wxPython not installed. Cannot launch advanced editor.")
    print("Install with: pip install wxPython")

# Import constants and rule analyzer (reuse from main app)
try:
    from constants import SuricataConstants
    from rule_analyzer import RuleAnalyzer
    from suricata_rule import SuricataRule
    HAS_RULE_ANALYZER = True
except ImportError:
    # Minimal fallback
    class SuricataConstants:
        SUPPORTED_ACTIONS = ['pass', 'alert', 'drop', 'reject']
        SUPPORTED_PROTOCOLS = ['tcp', 'udp', 'icmp', 'ip', 'http', 'tls', 'dns', 
                              'dhcp', 'ftp', 'smb', 'ssh', 'smtp']
        SID_MIN = 1
        SID_MAX = 999999999
    HAS_RULE_ANALYZER = False


def main():
    """Entry point for standalone subprocess launch"""
    if len(sys.argv) < 3:
        print("Usage: python advanced_editor.py <input_json> <output_json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not HAS_WXPYTHON:
        print("ERROR: wxPython not installed. Cannot launch advanced editor.")
        print("Install with: pip install wxPython")
        sys.exit(2)
    
    # Load input data
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            editor_data = json.load(f)
    except Exception as e:
        print(f"ERROR loading input file: {e}")
        sys.exit(3)
    
    # Launch wxPython application
    app = wx.App()
    editor = AdvancedEditorWx(None, editor_data, output_file)
    result = editor.ShowModal()
    
    # Exit with appropriate code
    if result == wx.ID_OK:
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Cancelled


class AdvancedEditorWx(wx.Dialog):
    """Advanced Editor using wxPython/Scintilla with code folding"""
    
    def __init__(self, parent, editor_data, output_file):
        super().__init__(
            parent,
            title="Advanced Editor - Suricata Rule Generator",
            size=(1000, 700),
            style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER | wx.MAXIMIZE_BOX
        )
        
        # Store data
        self.editor_data = editor_data
        self.rules = editor_data['rules']
        self.variables = editor_data['variables']
        self.output_file = output_file
        self.modified = False
        self.keywords_data = None
        
        # UI state
        self.dark_mode = False
        
        # Search state
        self.search_active = False
        self.search_term = ""
        self.replace_term = ""
        self.search_results = []  # List of (line_num, start_col, end_col, matched_text)
        self.current_search_index = -1
        self.search_field = "all"
        
        # Search configuration
        self.search_filters = {
            'pass': True,
            'drop': True,
            'reject': True,
            'alert': True,
            'comments': True
        }
        
        self.search_options = {
            'case_sensitive': False,
            'whole_word': False,
            'regex': False
        }
        
        # Validation storage for tooltips
        self.validation_errors = {}  # {line_num: [(start_col, end_col, msg)]}
        self.validation_warnings = {}
        
        # Initialize timers (used for debounced updates)
        self.validation_timer = None
        self.fold_timer = None
        self.coloring_timer = None
        
        # Load content keywords
        self.load_content_keywords()
        
        # Build UI
        self.setup_ui()
        
        # Populate with rules
        self.populate_editor()
        
        # Center on screen
        self.Centre()
        
        # Focus editor
        self.editor.SetFocus()
    
    def setup_ui(self):
        """Create the UI layout"""
        # Main panel
        panel = wx.Panel(self)
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Create Scintilla editor
        self.editor = stc.StyledTextCtrl(panel)
        
        # Configure editor basics
        self.setup_editor_config()
        self.setup_margins()
        self.setup_folding()
        self.setup_indicators()
        self.setup_events()
        
        main_sizer.Add(self.editor, 1, wx.EXPAND | wx.ALL, 5)
        
        # Status bar
        self.status_bar = self.create_status_bar(panel)
        main_sizer.Add(self.status_bar, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 5)
        
        # Button bar
        button_sizer = self.create_button_bar(panel)
        main_sizer.Add(button_sizer, 0, wx.EXPAND | wx.ALL, 5)
        
        panel.SetSizer(main_sizer)
    
    def setup_editor_config(self):
        """Configure basic editor properties"""
        # Font
        if wx.Platform == '__WXMSW__':
            face = 'Consolas'
        elif wx.Platform == '__WXMAC__':
            face = 'Monaco'
        else:
            face = 'Monospace'
        
        font = wx.Font(10, wx.FONTFAMILY_TELETYPE, wx.FONTSTYLE_NORMAL,
                      wx.FONTWEIGHT_NORMAL, faceName=face)
        self.editor.StyleSetFont(stc.STC_STYLE_DEFAULT, font)
        
        # Tab settings
        self.editor.SetTabWidth(4)
        self.editor.SetUseTabs(False)  # Use spaces
        
        # Undo
        self.editor.SetUndoCollection(True)
        self.editor.EmptyUndoBuffer()
        
        # Line wrapping (off)
        self.editor.SetWrapMode(stc.STC_WRAP_NONE)
        
        # Caret (cursor) settings
        self.editor.SetCaretLineVisible(True)
        self.editor.SetCaretLineBackground(wx.Colour(232, 232, 255))
        
        # Selection colors
        self.editor.SetSelBackground(True, wx.Colour(0, 120, 215))
        self.editor.SetSelForeground(True, wx.WHITE)
        
        # Configure autocomplete
        self.editor.AutoCompSetIgnoreCase(True)  # Case-insensitive matching
        self.editor.AutoCompSetMaxHeight(15)  # Show up to 15 items
        self.editor.AutoCompSetMaxWidth(0)  # Auto width
        
        # Configure bracket matching styles
        self.editor.StyleSetForeground(stc.STC_STYLE_BRACELIGHT, wx.Colour(0, 150, 0))
        self.editor.StyleSetBackground(stc.STC_STYLE_BRACELIGHT, wx.Colour(200, 255, 200))
        self.editor.StyleSetBold(stc.STC_STYLE_BRACELIGHT, True)
        self.editor.StyleSetForeground(stc.STC_STYLE_BRACEBAD, wx.RED)
        self.editor.StyleSetBold(stc.STC_STYLE_BRACEBAD, True)
        
        # Enable zoom with Ctrl+MouseWheel
        self.editor.SetZoom(0)  # Start at default zoom level
        
        # Clear Scintilla's default key commands for Ctrl+F, Ctrl+H, Ctrl+G
        # This prevents Scintilla from consuming these keys before our handlers see them
        self.editor.CmdKeyClear(ord('F'), stc.STC_KEYMOD_CTRL)
        self.editor.CmdKeyClear(ord('H'), stc.STC_KEYMOD_CTRL)
        self.editor.CmdKeyClear(ord('G'), stc.STC_KEYMOD_CTRL)
    
    def setup_margins(self):
        """Setup line numbers and fold margins"""
        # Line numbers margin (margin 0)
        self.editor.SetMarginType(0, stc.STC_MARGIN_NUMBER)
        self.editor.SetMarginWidth(0, 50)
        
        # Fold margin will be configured in setup_folding
    
    def setup_folding(self):
        """Configure code folding - THE KEY NEW FEATURE"""
        # Enable folding
        self.editor.SetProperty("fold", "1")
        
        # Setup fold margin (margin 2)
        self.editor.SetMarginType(2, stc.STC_MARGIN_SYMBOL)
        self.editor.SetMarginMask(2, stc.STC_MASK_FOLDERS)
        self.editor.SetMarginWidth(2, 16)
        self.editor.SetMarginSensitive(2, True)
        
        # Define fold markers - box style (like Notepad++)
        self.editor.MarkerDefine(stc.STC_MARKNUM_FOLDEROPEN, stc.STC_MARK_BOXMINUS)
        self.editor.MarkerDefine(stc.STC_MARKNUM_FOLDER, stc.STC_MARK_BOXPLUS)
        self.editor.MarkerDefine(stc.STC_MARKNUM_FOLDERSUB, stc.STC_MARK_VLINE)
        self.editor.MarkerDefine(stc.STC_MARKNUM_FOLDERTAIL, stc.STC_MARK_LCORNER)
        self.editor.MarkerDefine(stc.STC_MARKNUM_FOLDEREND, stc.STC_MARK_BOXPLUSCONNECTED)
        self.editor.MarkerDefine(stc.STC_MARKNUM_FOLDEROPENMID, stc.STC_MARK_BOXMINUSCONNECTED)
        self.editor.MarkerDefine(stc.STC_MARKNUM_FOLDERMIDTAIL, stc.STC_MARK_TCORNER)
        
        # Set fold margin colors
        self.editor.SetFoldMarginColour(True, wx.Colour(240, 240, 240))
        self.editor.SetFoldMarginHiColour(True, wx.WHITE)
    
    def setup_indicators(self):
        """Setup validation indicators (error/warning underlines and backgrounds)"""
        # Indicator 0: Error squiggle (red underline)
        self.editor.IndicatorSetStyle(0, stc.STC_INDIC_SQUIGGLE)
        self.editor.IndicatorSetForeground(0, wx.RED)
        self.editor.IndicatorSetOutlineAlpha(0, 255)
        self.editor.IndicatorSetUnder(0, True)
        
        # Indicator 1: Warning squiggle (orange underline)
        self.editor.IndicatorSetStyle(1, stc.STC_INDIC_SQUIGGLE)
        self.editor.IndicatorSetForeground(1, wx.Colour(255, 165, 0))
        self.editor.IndicatorSetOutlineAlpha(1, 255)
        self.editor.IndicatorSetUnder(1, True)
        
        # Indicator 2: Search highlights (yellow box)
        self.editor.IndicatorSetStyle(2, stc.STC_INDIC_ROUNDBOX)
        self.editor.IndicatorSetForeground(2, wx.Colour(255, 255, 0))
        self.editor.IndicatorSetAlpha(2, 100)
        
        # Indicator 3: Error background (red highlight)
        self.editor.IndicatorSetStyle(3, stc.STC_INDIC_ROUNDBOX)
        self.editor.IndicatorSetForeground(3, wx.Colour(255, 200, 200))  # Light red
        self.editor.IndicatorSetAlpha(3, 180)  # More opaque for visibility
        self.editor.IndicatorSetUnder(3, True)
        
        # Indicator 4: Warning background (orange highlight)
        self.editor.IndicatorSetStyle(4, stc.STC_INDIC_ROUNDBOX)
        self.editor.IndicatorSetForeground(4, wx.Colour(255, 235, 200))  # Light orange
        self.editor.IndicatorSetAlpha(4, 160)  # More opaque for visibility
        self.editor.IndicatorSetUnder(4, True)
        
        # Indicators 5-8: SIG type text coloring (traffic light scheme for safety levels)
        # Indicator 5: Generic/IPONLY (Crimson Red - DANGER: broad matching, risky)
        self.editor.IndicatorSetStyle(5, stc.STC_INDIC_TEXTFORE)
        self.editor.IndicatorSetForeground(5, wx.Colour(211, 47, 47))  # #D32F2F - Material Red 700
        self.editor.IndicatorSetUnder(5, False)
        
        # Indicator 6: Specific Protocol/PKT (Amber - CAUTION: flow keywords but limited specificity)
        self.editor.IndicatorSetStyle(6, stc.STC_INDIC_TEXTFORE)
        self.editor.IndicatorSetForeground(6, wx.Colour(255, 160, 0))  # #FFA000 - Material Amber 700
        self.editor.IndicatorSetUnder(6, False)
        
        # Indicator 7: Specific Network/Port/APPLAYER (Blue - GOOD: application layer protocols)
        self.editor.IndicatorSetStyle(7, stc.STC_INDIC_TEXTFORE)
        self.editor.IndicatorSetForeground(7, wx.Colour(25, 118, 210))  # #1976D2 - Material Blue 700
        self.editor.IndicatorSetUnder(7, False)
        
        # Indicator 8: Specific Protocol + Network/Port/APP_TX (Forest Green - BEST: most specific and safe)
        self.editor.IndicatorSetStyle(8, stc.STC_INDIC_TEXTFORE)
        self.editor.IndicatorSetForeground(8, wx.Colour(46, 125, 50))  # #2E7D32 - Material Green 700
        self.editor.IndicatorSetUnder(8, False)
    
    def setup_events(self):
        """Bind all event handlers"""
        # Text modification
        self.editor.Bind(stc.EVT_STC_MODIFIED, self.on_text_modified)
        
        # Hover for tooltips
        self.editor.SetMouseDwellTime(500)  # 500ms hover delay
        self.editor.Bind(stc.EVT_STC_DWELLSTART, self.on_hover_start)
        self.editor.Bind(stc.EVT_STC_DWELLEND, self.on_hover_end)
        
        # Character added (for auto-close and auto-complete trigger)
        self.editor.Bind(stc.EVT_STC_CHARADDED, self.on_char_added)
        
        # Autocomplete selection (when user picks a suggestion)
        self.editor.Bind(stc.EVT_STC_AUTOCOMP_SELECTION, self.on_autocomp_selected)
        
        # UI updates (cursor movement, etc.)
        self.editor.Bind(stc.EVT_STC_UPDATEUI, self.on_update_ui)
        
        # Margin click (for folding)
        self.editor.Bind(stc.EVT_STC_MARGINCLICK, self.on_margin_click)
        
        # Key down (for special handling)
        self.editor.Bind(wx.EVT_KEY_DOWN, self.on_key_down)
        
        # Char hook - highest priority for capturing Ctrl+F before Scintilla
        self.Bind(wx.EVT_CHAR_HOOK, self.on_char_hook)
        
        # Setup keyboard shortcuts
        self.setup_accelerators()
    
    def setup_accelerators(self):
        """Setup keyboard shortcuts"""
        # Define custom IDs for our commands
        self.ID_FIND = wx.NewIdRef()
        self.ID_GOTO = wx.NewIdRef()
        self.ID_COMMENT = wx.NewIdRef()
        self.ID_SHORTCUTS = wx.NewIdRef()
        
        accel_tbl = wx.AcceleratorTable([
            (wx.ACCEL_CTRL, ord('F'), self.ID_FIND),
            (wx.ACCEL_CTRL, ord('G'), self.ID_GOTO),
            (wx.ACCEL_CTRL, ord('/'), self.ID_COMMENT),
            (wx.ACCEL_NORMAL, wx.WXK_F3, wx.WXK_F3),
            (wx.ACCEL_NORMAL, wx.WXK_ESCAPE, wx.WXK_ESCAPE),
        ])
        self.SetAcceleratorTable(accel_tbl)
        
        # Bind handlers
        self.Bind(wx.EVT_MENU, self.on_find, id=self.ID_FIND)
        self.Bind(wx.EVT_MENU, self.on_goto_line, id=self.ID_GOTO)
        self.Bind(wx.EVT_MENU, self.on_toggle_comment, id=self.ID_COMMENT)
    
    def load_content_keywords(self):
        """Load content keywords from JSON - REUSES existing file"""
        try:
            # Look for content_keywords.json in same directory as this script
            keywords_file = os.path.join(os.path.dirname(__file__), 'content_keywords.json')
            if os.path.exists(keywords_file):
                with open(keywords_file, 'r', encoding='utf-8') as f:
                    self.keywords_data = json.load(f)
            else:
                self.keywords_data = None
        except json.JSONDecodeError:
            self.keywords_data = None
        except Exception:
            self.keywords_data = None
    
    def populate_editor(self):
        """Convert rules to text and populate editor"""
        text_lines = []
        
        for rule in self.rules:
            if rule.get('is_blank'):
                text_lines.append('')
            elif rule.get('is_comment'):
                text_lines.append(rule.get('comment_text', ''))
            else:
                text_lines.append(self._rule_to_string(rule))
        
        # Set text
        self.editor.SetText('\n'.join(text_lines))
        
        # Calculate fold levels
        self.calculate_fold_levels()
        
        # Don't apply initial SIG type coloring (disabled by default)
        # User must check the checkbox to enable it
        
        # Position cursor at start
        self.editor.GotoPos(0)
        
        # Clear modified flag
        self.modified = False
        
        # Update status
        self.update_status_bar()
    
    def calculate_fold_levels(self):
        """
        Calculate fold levels for code folding.
        Groups are separated by blank lines and can contain:
        - Comments only (2+ consecutive comments)
        - Rules only (2+ consecutive rules)
        - Comments followed by rules (all in one group starting at first comment)
        
        When collapsed, only the first line (header) remains visible.
        """
        text = self.editor.GetText()
        lines = text.split('\n')
        
        if not lines:
            return
        
        fold_level = stc.STC_FOLDLEVELBASE
        in_fold_group = False
        
        for line_num, line in enumerate(lines):
            stripped = line.strip()
            is_blank = not stripped
            is_comment = stripped.startswith('#')
            is_rule = stripped and not is_comment
            
            if is_blank:
                # Blank line ends any fold group
                self.editor.SetFoldLevel(line_num, fold_level)
                in_fold_group = False
            elif is_comment or is_rule:
                if not in_fold_group:
                    # Potential start of new fold group
                    # Look ahead to see if there's another non-blank line
                    has_next_content = False
                    for next_line_num in range(line_num + 1, len(lines)):
                        next_stripped = lines[next_line_num].strip()
                        if next_stripped:
                            has_next_content = True
                            break
                        if not next_stripped:
                            # Hit a blank line, no more content in this group
                            break
                    
                    if has_next_content:
                        # This is the start of a foldable group
                        in_fold_group = True
                        self.editor.SetFoldLevel(line_num, fold_level | stc.STC_FOLDLEVELHEADERFLAG)
                    else:
                        # Single line with no following content - no fold
                        self.editor.SetFoldLevel(line_num, fold_level)
                else:
                    # Continuation of fold group
                    self.editor.SetFoldLevel(line_num, fold_level + 1)
            else:
                # Shouldn't reach here, but handle gracefully
                self.editor.SetFoldLevel(line_num, fold_level)
    
    def _rule_to_string(self, rule_dict):
        """Convert rule dict to Suricata rule string"""
        if rule_dict.get('is_blank'):
            return ''
        elif rule_dict.get('is_comment'):
            return rule_dict.get('comment_text', '')
        else:
            # Use original_options if available for exact formatting
            if rule_dict.get('original_options'):
                opts = rule_dict['original_options']
                # Ensure it ends with semicolon
                if not opts.endswith(';'):
                    opts += ';'
                return (f"{rule_dict['action']} {rule_dict['protocol']} "
                       f"{rule_dict['src_net']} {rule_dict['src_port']} "
                       f"{rule_dict['direction']} {rule_dict['dst_net']} "
                       f"{rule_dict['dst_port']} ({opts})")
            else:
                # Fallback reconstruction
                options = []
                if rule_dict.get('message'):
                    options.append(f'msg:"{rule_dict["message"]}"')
                if rule_dict.get('content'):
                    options.append(rule_dict['content'])
                options.append(f"sid:{rule_dict.get('sid', 1)}")
                options.append(f"rev:{rule_dict.get('rev', 1)}")
                
                return (f"{rule_dict['action']} {rule_dict['protocol']} "
                       f"{rule_dict['src_net']} {rule_dict['src_port']} "
                       f"{rule_dict['direction']} {rule_dict['dst_net']} "
                       f"{rule_dict['dst_port']} ({'; '.join(options)};)")
    
    def create_status_bar(self, parent):
        """Create status bar with line/col/rule count"""
        status_panel = wx.Panel(parent)
        status_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        # Cursor position label (fixed width)
        self.cursor_label = wx.StaticText(status_panel, label="Ln 1, Col 1", size=(100, -1))
        status_sizer.Add(self.cursor_label, 0, wx.ALL, 5)
        
        # Separator
        status_sizer.Add(wx.StaticLine(status_panel, style=wx.LI_VERTICAL), 0, wx.EXPAND | wx.ALL, 5)
        
        # Lines label (fixed width)
        self.lines_label = wx.StaticText(status_panel, label="0 lines", size=(80, -1))
        status_sizer.Add(self.lines_label, 0, wx.ALL, 5)
        
        # Rule count label with moderate width (enough for longest SIG type + small buffer)
        # Longest SIG types are around 50-60 chars: "Rule 999/999 | Specific Protocol + Specific Network/Port"
        status_sizer.Add(wx.StaticLine(status_panel, style=wx.LI_VERTICAL), 0, wx.EXPAND | wx.ALL, 5)
        self.rule_label = wx.StaticText(status_panel, label="Rules: 0", size=(400, -1))
        status_sizer.Add(self.rule_label, 0, wx.ALL, 5)
        
        # Modified label (fixed width)
        status_sizer.Add(wx.StaticLine(status_panel, style=wx.LI_VERTICAL), 0, wx.EXPAND | wx.ALL, 5)
        self.modified_label = wx.StaticText(status_panel, label="(no changes)", size=(100, -1))
        status_sizer.Add(self.modified_label, 0, wx.ALL, 5)
        
        # Validation label (fixed width)
        status_sizer.Add(wx.StaticLine(status_panel, style=wx.LI_VERTICAL), 0, wx.EXPAND | wx.ALL, 5)
        self.validation_label = wx.StaticText(status_panel, label="✓ No errors", size=(120, -1))
        self.validation_label.SetForegroundColour(wx.Colour(0, 128, 0))
        status_sizer.Add(self.validation_label, 0, wx.ALL, 5)
        
        status_panel.SetSizer(status_sizer)
        return status_panel
    
    def create_button_bar(self, parent):
        """Create button bar with OK/Cancel"""
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        # Shortcuts button
        shortcuts_btn = wx.Button(parent, label="Shortcuts")
        shortcuts_btn.Bind(wx.EVT_BUTTON, self.on_show_shortcuts)
        button_sizer.Add(shortcuts_btn, 0, wx.ALL, 5)
        
        # Dark mode checkbox
        self.dark_mode_cb = wx.CheckBox(parent, label="Dark Mode")
        self.dark_mode_cb.Bind(wx.EVT_CHECKBOX, self.on_toggle_dark_mode)
        button_sizer.Add(self.dark_mode_cb, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        
        # SIG type coloring checkbox
        self.sig_coloring_cb = wx.CheckBox(parent, label="SIG Type Colors")
        self.sig_coloring_cb.SetValue(False)  # Disabled by default
        self.sig_coloring_cb.Bind(wx.EVT_CHECKBOX, self.on_toggle_sig_coloring)
        button_sizer.Add(self.sig_coloring_cb, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        
        # Spacer
        button_sizer.AddStretchSpacer()
        
        # Cancel button
        cancel_btn = wx.Button(parent, wx.ID_CANCEL, "Cancel")
        cancel_btn.Bind(wx.EVT_BUTTON, self.on_cancel)
        button_sizer.Add(cancel_btn, 0, wx.ALL, 5)
        
        # OK button
        ok_btn = wx.Button(parent, wx.ID_OK, "OK")
        ok_btn.Bind(wx.EVT_BUTTON, self.on_ok)
        button_sizer.Add(ok_btn, 0, wx.ALL, 5)
        
        return button_sizer
    
    def update_status_bar(self):
        """Update status bar information"""
        # Cursor position
        pos = self.editor.GetCurrentPos()
        line_num = self.editor.LineFromPosition(pos)
        col = self.editor.GetColumn(pos)
        self.cursor_label.SetLabel(f"Ln {line_num + 1}, Col {col + 1}")
        
        # Total lines
        line_count = self.editor.GetLineCount()
        self.lines_label.SetLabel(f"{line_count} lines")
        
        # Get current line content for SIG type detection
        current_line = self.editor.GetLine(line_num).rstrip()
        
        # Rule count and SIG type
        text = self.editor.GetText()
        lines = text.split('\n')
        total_rules = sum(1 for l in lines if l.strip() and not l.strip().startswith('#'))
        
        # SIG type colors for status bar (always colored) - traffic light scheme
        sig_colors = {
            'Generic': wx.Colour(211, 47, 47),  # Crimson Red - DANGER
            'Specific Protocol': wx.Colour(255, 160, 0),  # Amber - CAUTION
            'Specific Network/Port': wx.Colour(25, 118, 210),  # Blue - GOOD
            'Specific Protocol + Specific Network/Port': wx.Colour(46, 125, 50)  # Forest Green - BEST
        }
        
        # Calculate rule position and show SIG type if on a rule line
        if current_line.strip() and not current_line.strip().startswith('#'):
            # Count rules before this line
            rules_before = sum(1 for l in lines[:line_num] if l.strip() and not l.strip().startswith('#'))
            current_rule_num = rules_before + 1
            
            # Try to get SIG type for current line (show actual SIG type name)
            sig_type_text = ""
            if HAS_RULE_ANALYZER:
                try:
                    # Parse current line as rule
                    rule = SuricataRule.from_string(current_line.strip())
                    if rule:
                        # Get detailed SIG type classification (actual name)
                        rule_analyzer = RuleAnalyzer()
                        sig_type = rule_analyzer.get_detailed_suricata_rule_type(rule)
                        if sig_type:
                            sig_type_text = f" | {sig_type}"
                            # Map to color category for status bar coloring
                            color_category = self._map_detailed_sig_type_to_color(sig_type)
                            if color_category in sig_colors:
                                self.rule_label.SetForegroundColour(sig_colors[color_category])
                except:
                    pass  # If classification fails, just show rule number
            
            # Reset color if no SIG type
            if not sig_type_text:
                self.rule_label.SetForegroundColour(wx.BLACK if not self.dark_mode else wx.Colour(212, 212, 212))
            
            self.rule_label.SetLabel(f"Rule {current_rule_num}/{total_rules}{sig_type_text}")
        else:
            # Reset color for non-rule lines
            self.rule_label.SetForegroundColour(wx.BLACK if not self.dark_mode else wx.Colour(212, 212, 212))
            
            if current_line.strip().startswith('#'):
                self.rule_label.SetLabel("Comment")
            elif not current_line.strip():
                self.rule_label.SetLabel("Blank")
            else:
                self.rule_label.SetLabel(f"Rules: {total_rules}")
        
        # Modified status
        if self.modified:
            self.modified_label.SetLabel("Modified")
        else:
            self.modified_label.SetLabel("(no changes)")
    
    def on_text_modified(self, event):
        """Handle text changes"""
        # Only mark as modified for actual content changes (not just undo/redo operations)
        if event.GetModificationType() & (stc.STC_MOD_INSERTTEXT | stc.STC_MOD_DELETETEXT):
            self.modified = True
            self.update_status_bar()
            
            # Schedule validation with delay
            if self.validation_timer:
                self.validation_timer.Stop()
            self.validation_timer = wx.CallLater(500, self.perform_realtime_validation)
            
            # Schedule fold level recalculation with delay
            if self.fold_timer:
                self.fold_timer.Stop()
            self.fold_timer = wx.CallLater(500, self.calculate_fold_levels)
            
            # Schedule SIG type coloring with delay (if enabled)
            if self.sig_coloring_cb.GetValue():
                if self.coloring_timer:
                    self.coloring_timer.Stop()
                self.coloring_timer = wx.CallLater(500, self.apply_sig_type_coloring)
    
    def perform_realtime_validation(self):
        """Real-time validation with indicators"""
        # Clear previous indicators (squiggles and backgrounds)
        for indicator_id in [0, 1, 3, 4]:
            self.editor.SetIndicatorCurrent(indicator_id)
            self.editor.IndicatorClearRange(0, self.editor.GetLength())
        
        # Clear validation storage
        self.validation_errors = {}
        self.validation_warnings = {}
        
        # Validate each line
        text = self.editor.GetText()
        lines = text.split('\n')
        
        total_errors = 0
        total_warnings = 0
        
        for line_num, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Skip blank lines and comments
            if not line_stripped or line_stripped.startswith('#'):
                continue
            
            # Validate this line
            errors, warnings = self.validate_line(line, line_num)
            
            if errors:
                self.validation_errors[line_num] = errors
                total_errors += len(errors)
            if warnings:
                self.validation_warnings[line_num] = warnings
                total_warnings += len(warnings)
            
            # Apply error indicators (red squiggle + background)
            for start_col, end_col, msg in errors:
                pos = self.editor.PositionFromLine(line_num) + start_col
                length = end_col - start_col
                # Apply squiggle underline
                self.editor.SetIndicatorCurrent(0)
                self.editor.IndicatorFillRange(pos, length)
                # Apply background highlight
                self.editor.SetIndicatorCurrent(3)
                self.editor.IndicatorFillRange(pos, length)
            
            # Apply warning indicators (orange squiggle + background)
            for start_col, end_col, msg in warnings:
                pos = self.editor.PositionFromLine(line_num) + start_col
                length = end_col - start_col
                # Apply squiggle underline
                self.editor.SetIndicatorCurrent(1)
                self.editor.IndicatorFillRange(pos, length)
                # Apply background highlight
                self.editor.SetIndicatorCurrent(4)
                self.editor.IndicatorFillRange(pos, length)
        
        # Update validation status in status bar
        if total_errors > 0:
            error_text = "error" if total_errors == 1 else "errors"
            self.validation_label.SetLabel(f"✗ {total_errors} {error_text}")
            self.validation_label.SetForegroundColour(wx.Colour(255, 0, 0))  # Red
        elif total_warnings > 0:
            self.validation_label.SetLabel(f"⚠ {total_warnings} warnings")
            self.validation_label.SetForegroundColour(wx.Colour(255, 165, 0))  # Orange
        else:
            self.validation_label.SetLabel("✓ No errors")
            self.validation_label.SetForegroundColour(wx.Colour(0, 128, 0))  # Green
    
    def validate_line(self, line, line_num):
        """Validate a single line and return error/warning positions
        
        Returns:
            tuple: (errors_list, warnings_list) where each item is (start_col, end_col, message)
        """
        errors = []
        warnings = []
        
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            return errors, warnings
        
        # Parse the line into tokens
        tokens = self._parse_rule_tokens(line_stripped)
        
        # Find positions of each token in the original line
        current_pos = 0
        token_positions = []
        for token in tokens:
            start = line.find(token, current_pos)
            if start != -1:
                end = start + len(token)
                token_positions.append((start, end, token))
                current_pos = end
        
        # Validate action (first word)
        if len(token_positions) > 0:
            start, end, action = token_positions[0]
            if len(token_positions) > 1 or (len(tokens) == 1 and end < len(line) and line[end:].strip()):
                if action.lower() not in ['pass', 'alert', 'drop', 'reject']:
                    errors.append((start, end, f"Invalid action: {action}"))
        
        # Validate protocol (second word)
        if len(token_positions) > 1:
            start, end, protocol = token_positions[1]
            if len(token_positions) > 2 or (len(tokens) == 2 and end < len(line) and line[end:].strip()):
                if protocol.lower() not in [p.lower() for p in SuricataConstants.SUPPORTED_PROTOCOLS]:
                    errors.append((start, end, f"Invalid protocol: {protocol}"))
        
        # Validate source network
        if len(token_positions) > 2:
            start, end, src_net = token_positions[2]
            if len(token_positions) > 3 or (end < len(line) and line[end:].strip()):
                if not self._validate_network_format_silent(src_net):
                    errors.append((start, end, f"Invalid network: {src_net}"))
        
        # Validate direction
        if len(token_positions) > 4:
            start, end, direction = token_positions[4]
            if len(token_positions) > 5 or (end < len(line) and line[end:].strip()):
                if direction not in ['->', '<>']:
                    errors.append((start, end, f"Invalid direction: {direction}"))
        
        # Validate source port - always validate once we have it
        if len(token_positions) > 3:
            start, end, src_port = token_positions[3]
            # Skip validation if it's clearly a network (has CIDR notation)
            if '/' in src_port:
                pass  # This is a network, not a port
            else:
                # Validate port - always check once token exists
                if not self._validate_port_format(src_port):
                    errors.append((start, end, f"Invalid port: {src_port}"))
        
        # Validate destination network - always validate once we have it
        if len(token_positions) > 5:
            start, end, dst_net = token_positions[5]
            # Skip if it looks like a port (single number or bracketed port range)
            if dst_net.isdigit() or (dst_net.startswith('[') and ':' in dst_net and not '.' in dst_net):
                pass  # This is a port, not a network
            else:
                # Validate network - always check once token exists
                if not self._validate_network_format_silent(dst_net):
                    errors.append((start, end, f"Invalid network: {dst_net}"))
        
        # Validate destination port - always validate once we have it
        if len(token_positions) > 6:
            start, end, dest_port = token_positions[6]
            # Skip validation if it's clearly a network (has CIDR notation)
            if '/' in dest_port:
                pass  # This is a network, not a port
            else:
                # Validate port - always check once token exists
                if not self._validate_port_format(dest_port):
                    errors.append((start, end, f"Invalid port: {dest_port}"))
        
        # Check for parentheses and validate SID
        if '(' in line and ')' in line:
            paren_start = line.find('(')
            paren_end = line.rfind(')')
            content_section = line[paren_start+1:paren_end]
            
            # Validate SID format
            if 'sid:' in content_section.lower():
                sid_match = re.search(r'sid:\s*(\d+)', content_section, re.IGNORECASE)
                if sid_match:
                    sid_value = int(sid_match.group(1))
                    if sid_value < SuricataConstants.SID_MIN or sid_value > SuricataConstants.SID_MAX:
                        sid_start = line.find(sid_match.group(0), paren_start)
                        sid_end = sid_start + len(sid_match.group(0))
                        errors.append((sid_start, sid_end, f"SID must be between {SuricataConstants.SID_MIN}-{SuricataConstants.SID_MAX}"))
            
            # Check for missing semicolons and invalid keyword syntax
            # Parse through content more carefully to detect:
            # 1. Keywords missing semicolons (e.g., "to_client sid:100" - missing ; after to_client)
            # 2. Keywords with colons but no values (e.g., "sid;")
            
            # First, check if content section ends with semicolon
            content_stripped = content_section.strip()
            if content_stripped and not content_stripped.endswith(';'):
                # Content doesn't end with semicolon
                error_pos = paren_end
                errors.append((error_pos - 1, error_pos, 
                             "Missing semicolon - all keywords must end with ';'"))
            
            # Look for keywords that appear to be missing semicolons in the middle
            # Pattern: look for spaces followed by keyword names (indicating missing semicolon before)
            # This catches: "value1, value2 keyword:" where semicolon is missing after value2
            missing_semicolon_pattern = r'([a-zA-Z_]\w*)\s+(\w+(?:\.\w+)?):(?=\S)'
            for match in re.finditer(missing_semicolon_pattern, content_section):
                # match.group(1) is the value without semicolon
                # match.group(2) is the next keyword
                value_without_semicolon = match.group(1)
                next_keyword = match.group(2)
                
                # Position of the value that's missing semicolon
                value_pos = paren_start + 1 + match.start(1)
                value_end = value_pos + len(value_without_semicolon)
                
                errors.append((value_end, value_end + 1,
                             f"Missing semicolon after '{value_without_semicolon}'"))
            
            # Check for keywords with colon but no value (e.g., "sid;" or "sid:")
            empty_keyword_pattern = r'(\w+(?:\.\w+)?):(?:\s*;|\s*$|\s*\))'
            for match in re.finditer(empty_keyword_pattern, content_section):
                keyword_name = match.group(1)
                # Skip 'msg' keyword since it might have empty string
                if keyword_name.lower() != 'msg':
                    keyword_pos = paren_start + 1 + match.start()
                    keyword_end = keyword_pos + len(keyword_name) + 1  # Include colon
                    errors.append((keyword_pos, keyword_end,
                                 f"Keyword '{keyword_name}' requires a value"))
            
            # Validate keywords and their values
            if self.keywords_data:
                known_keywords = [kw.get('name', '') for kw in self.keywords_data.get('keywords', [])]
                statements = content_section.split(';')
                current_pos = 0
                
                for statement in statements:
                    statement = statement.strip()
                    if not statement:
                        current_pos += 1
                        continue
                    
                    # Extract keyword name and value
                    if ':' in statement:
                        keyword = statement.split(':', 1)[0].strip()
                        value_part = statement.split(':', 1)[1].strip() if len(statement.split(':', 1)) > 1 else ''
                    else:
                        keyword = statement.strip()
                        value_part = ''
                    
                    # Check if valid keyword name
                    if keyword and keyword.lower() not in [k.lower() for k in known_keywords]:
                        search_start = paren_start + current_pos
                        keyword_pos = line.find(keyword, search_start)
                        if keyword_pos != -1:
                            warnings.append((keyword_pos, keyword_pos + len(keyword), 
                                           f"Unknown keyword: {keyword}"))
                    # Validate keyword value if keyword has defined values
                    elif keyword and value_part:
                        # Find keyword definition
                        keyword_def = next((kw for kw in self.keywords_data.get('keywords', []) 
                                          if kw.get('name', '').lower() == keyword.lower()), None)
                        
                        if keyword_def and keyword_def.get('values'):
                            # Get valid values for this keyword
                            valid_values = [v.lower() for v in keyword_def.get('values', [])]
                            
                            # Check if syntax has comma-separated parameters (e.g., "geoip:<direction>,<country_code>")
                            # In these cases, only validate the first part before the comma
                            syntax = keyword_def.get('syntax', '')
                            validate_first_part_only = False
                            if ',' in syntax and '<' in syntax.split(',', 1)[1]:
                                # Syntax has comma followed by a parameter (indicated by <...>)
                                # Only validate the first part
                                validate_first_part_only = True
                            
                            # Handle multi-value keywords (comma-separated or | separated)
                            if keyword_def.get('multi_value'):
                                # Split by comma or pipe
                                if ',' in value_part:
                                    user_values = [v.strip() for v in value_part.split(',')]
                                elif '|' in value_part:
                                    user_values = [v.strip() for v in value_part.split('|')]
                                else:
                                    user_values = [value_part]
                            elif validate_first_part_only and ',' in value_part:
                                # For keywords like "geoip:dst,RU" or "flowbits:set,blocked"
                                # Only validate the first part (before comma)
                                first_part = value_part.split(',', 1)[0].strip()
                                user_values = [first_part]
                            else:
                                user_values = [value_part]
                            
                            # Check each value
                            for user_value in user_values:
                                # Handle negated values
                                check_value = user_value
                                if user_value.startswith('!'):
                                    check_value = user_value[1:].strip()
                                
                                # Validate the value
                                if check_value and check_value.lower() not in valid_values:
                                    # Find position of invalid value in line
                                    search_start = paren_start + current_pos
                                    value_pos = line.find(user_value, search_start)
                                    if value_pos != -1:
                                        errors.append((value_pos, value_pos + len(user_value),
                                                     f"Invalid value '{user_value}' for keyword '{keyword}'"))
                    
                    current_pos += len(statement) + 1
        
        # Check for undefined variables
        var_pattern = r'([\$@]\w+)'
        for match in re.finditer(var_pattern, line):
            var_name = match.group(1)
            var_pos = match.start()
            
            # Don't flag variables inside quoted strings
            in_quotes = False
            for i, char in enumerate(line[:var_pos]):
                if char == '"':
                    in_quotes = not in_quotes
            
            if not in_quotes and var_name not in self.variables:
                warnings.append((match.start(), match.end(), f"Undefined variable: {var_name}"))
        
        return errors, warnings
    
    def _parse_rule_tokens(self, line_stripped):
        """Parse rule into tokens, treating bracketed groups as single tokens"""
        tokens = []
        current_token = ""
        bracket_depth = 0
        paren_depth = 0
        in_quotes = False
        
        for char in line_stripped:
            if char == '"' and bracket_depth == 0 and paren_depth == 0:
                in_quotes = not in_quotes
                current_token += char
            elif in_quotes:
                current_token += char
            elif char == '[':
                bracket_depth += 1
                current_token += char
            elif char == ']':
                bracket_depth -= 1
                current_token += char
            elif char == '(':
                paren_depth += 1
                current_token += char
            elif char == ')':
                paren_depth -= 1
                current_token += char
            elif char == ' ' and bracket_depth == 0 and paren_depth == 0:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char
        
        # IMPORTANT: Add final token even if brackets/parens unclosed
        # This ensures incomplete tokens like "[90:99" get validated
        if current_token:
            tokens.append(current_token)
        
        return tokens
    
    def _validate_port_format(self, port_str):
        """Validate port format"""
        port_str = port_str.strip()
        
        # Handle negation
        if port_str.startswith('!'):
            inner = port_str[1:].strip()
            return self._validate_port_format(inner)
        
        # "any" is valid
        if port_str.lower() == 'any':
            return True
        
        # Variable reference ($VAR)
        if port_str.startswith('$'):
            return True
        
        if port_str.startswith('@'):
            return False  # @ not allowed for ports
        
        # Single port number
        if port_str.isdigit():
            port_num = int(port_str)
            return 1 <= port_num <= 65535
        
        # Check for mismatched brackets (starts with [ but no closing ] or has spaces inside)
        if port_str.startswith('['):
            if not port_str.endswith(']'):
                return False  # Incomplete bracket
            # Valid bracketed specification
            return True
        
        # Anything else with colons or commas requires brackets
        if ':' in port_str or ',' in port_str:
            return False
        
        return False
    
    def _validate_network_format_silent(self, network_str):
        """Validate network format"""
        network_str = network_str.strip()
        
        # Handle negation
        if network_str.startswith('!'):
            inner = network_str[1:].strip()
            return self._validate_network_format_silent(inner)
        
        # "any" is valid
        if network_str.lower() == 'any':
            return True
        
        # Variables are valid
        if network_str.startswith(('$', '@')):
            return True
        
        # Check for bracketed groups
        if network_str.startswith('[') and network_str.endswith(']'):
            group_content = network_str[1:-1].strip()
            if not group_content:
                return False
            
            items = [item.strip() for item in group_content.split(',')]
            for item in items:
                if not item:
                    return False
                
                if item.startswith('!'):
                    item = item[1:].strip()
                    if not item:
                        return False
                
                if not self._validate_single_network_item_silent(item):
                    return False
            
            return True
        
        # Single item validation
        return self._validate_single_network_item_silent(network_str)
    
    def _validate_single_network_item_silent(self, value):
        """Validate a single network item"""
        value = value.strip()
        
        # Variables are valid
        if value.startswith(('$', '@')):
            return True
        
        # "any" is valid
        if value.lower() == 'any':
            return True
        
        # Try to validate as CIDR or IP
        try:
            import ipaddress
            ipaddress.ip_network(value, strict=False)
            return True
        except (ValueError, AttributeError):
            return False
    
    def on_hover_start(self, event):
        """Handle mouse hover start - show tooltip for errors/warnings with valid options"""
        pos = event.GetPosition()
        line_num = self.editor.LineFromPosition(pos)
        col_num = pos - self.editor.PositionFromLine(line_num)
        
        # Check if there are errors or warnings on this line
        errors = self.validation_errors.get(line_num, [])
        warnings = self.validation_warnings.get(line_num, [])
        all_issues = errors + warnings
        
        # Find which issue (if any) is at the hover position
        tooltip_text = None
        for start_col, end_col, msg in all_issues:
            if start_col <= col_num < end_col:
                # Get the line content to extract the problematic word
                line_content = self.editor.GetLine(line_num)
                word = line_content[start_col:end_col]
                
                # Build tooltip with valid options based on error type
                tooltip_lines = []
                
                if 'Invalid action' in msg:
                    tooltip_lines.append(f"Invalid action: '{word}'")
                    tooltip_lines.append("\nValid actions:")
                    for action in ['pass', 'alert', 'drop', 'reject']:
                        tooltip_lines.append(f"  • {action}")
                elif 'Invalid protocol' in msg:
                    tooltip_lines.append(f"Invalid protocol: '{word}'")
                    tooltip_lines.append("\nValid protocols:")
                    protocols = SuricataConstants.SUPPORTED_PROTOCOLS[:10]
                    for protocol in protocols:
                        tooltip_lines.append(f"  • {protocol}")
                    if len(SuricataConstants.SUPPORTED_PROTOCOLS) > 10:
                        tooltip_lines.append("  • ...")
                elif 'Invalid direction' in msg:
                    tooltip_lines.append(f"Invalid direction: '{word}'")
                    tooltip_lines.append("\nValid directions:")
                    tooltip_lines.append("  • ->")
                    tooltip_lines.append("  • <>")
                elif 'Unknown keyword' in msg:
                    tooltip_lines.append(f"Unknown keyword: '{word}'")
                    if self.keywords_data:
                        tooltip_lines.append("\nValid keywords:")
                        known = sorted([kw.get('name', '') for kw in self.keywords_data.get('keywords', [])])[:15]
                        for keyword in known:
                            tooltip_lines.append(f"  • {keyword}")
                        if len(self.keywords_data.get('keywords', [])) > 15:
                            tooltip_lines.append("  • ...")
                    else:
                        tooltip_lines.append("\n(Load content_keywords.json for suggestions)")
                elif 'Invalid value' in msg:
                    # Extract keyword name from error message
                    keyword_match = re.search(r"for keyword '(\w+(?:\.\w+)?)'", msg)
                    if keyword_match and self.keywords_data:
                        keyword_name = keyword_match.group(1)
                        # Find keyword definition
                        keyword_def = next((kw for kw in self.keywords_data.get('keywords', []) 
                                          if kw.get('name', '').lower() == keyword_name.lower()), None)
                        if keyword_def and keyword_def.get('values'):
                            tooltip_lines.append(msg)
                            tooltip_lines.append(f"\nValid values for '{keyword_name}':")
                            valid_vals = keyword_def.get('values', [])[:10]
                            for val in valid_vals:
                                tooltip_lines.append(f"  • {val}")
                            if len(keyword_def.get('values', [])) > 10:
                                tooltip_lines.append("  • ...")
                        else:
                            tooltip_lines.append(msg)
                    else:
                        tooltip_lines.append(msg)
                elif 'Undefined variable' in msg:
                    tooltip_lines.append(f"Undefined variable: '{word}'")
                    tooltip_lines.append(f"\n{msg}")
                elif 'SID must be' in msg:
                    tooltip_lines.append(msg)
                    tooltip_lines.append(f"\nSID must be between {SuricataConstants.SID_MIN}-{SuricataConstants.SID_MAX}")
                elif 'Invalid port' in msg or 'Invalid network' in msg:
                    tooltip_lines.append(msg)
                else:
                    tooltip_lines.append(msg)
                
                tooltip_text = '\n'.join(tooltip_lines)
                break
        
        if tooltip_text:
            # Show tooltip using Scintilla's built-in CallTipShow
            self.editor.CallTipShow(pos, tooltip_text)
    
    def on_hover_end(self, event):
        """Handle mouse hover end - dismiss tooltip"""
        self.editor.CallTipCancel()
    
    def on_char_added(self, event):
        """Character added - trigger autocomplete or auto-close"""
        char_code = event.GetKey()
        
        # Skip if it's a special key
        if char_code > 255:
            return
        
        char = chr(char_code)
        
        # Auto-close brackets/quotes
        if char == '(':
            self.editor.AddText(')')
            self.editor.GotoPos(self.editor.GetCurrentPos() - 1)
        elif char == '[':
            self.editor.AddText(']')
            self.editor.GotoPos(self.editor.GetCurrentPos() - 1)
        elif char == '"':
            self.editor.AddText('";')
            self.editor.GotoPos(self.editor.GetCurrentPos() - 2)
        
        # Trigger autocomplete on any alphanumeric, space, or colon
        # Use shorter delay for more responsive filtering
        if char.isalnum() or char in (' ', ':', '$', '@'):
            wx.CallLater(50, self.check_autocomplete)
    
    def on_autocomp_selected(self, event):
        """Handle autocomplete selection - add trailing space and special behaviors"""
        selected_text = event.GetText()
        
        # Get current line context
        pos = self.editor.GetCurrentPos()
        line_num = self.editor.LineFromPosition(pos)
        line_start = self.editor.PositionFromLine(line_num)
        text_before = self.editor.GetTextRange(line_start, pos)
        
        # Check if this is rev:1; (complete rev keyword)
        if selected_text == 'rev:1;':
            # Rev keyword: insert without extra space
            def complete_rev():
                # Find closing paren
                current_pos = self.editor.GetCurrentPos()
                line = self.editor.GetLine(line_num)
                closing_paren_pos = line.find(')', current_pos - line_start)
                if closing_paren_pos != -1:
                    # Move to after closing paren
                    target_pos = line_start + closing_paren_pos + 1
                    self.editor.GotoPos(target_pos)
                # Add newline to complete rule
                self.editor.AddText('\n')
            wx.CallAfter(complete_rev)
        
        # Check if this is a SID value with semicolon (e.g., "100;")
        elif re.match(r'^\d+;$', selected_text):
            # SID value with semicolon - add space and trigger next autocomplete
            def after_sid():
                self.editor.AddText(' ')
                # Auto-trigger autocomplete for next field (rev)
                wx.CallLater(100, self.check_autocomplete)
            wx.CallAfter(after_sid)
        
        # Check if this is rev value with semicolon (e.g., "1;")
        elif selected_text == '1;' and 'rev:' in text_before[-10:]:
            # Rev value - no space needed, will complete rule
            def after_rev():
                # Find closing paren
                current_pos = self.editor.GetCurrentPos()
                line = self.editor.GetLine(line_num)
                closing_paren_pos = line.find(')', current_pos - line_start)
                if closing_paren_pos != -1:
                    # Move to after closing paren
                    target_pos = line_start + closing_paren_pos + 1
                    self.editor.GotoPos(target_pos)
                # Add newline
                self.editor.AddText('\n')
            wx.CallAfter(after_rev)
        
        # Check if this ends with colon (keyword like "msg:", "sid:", "flow:")
        elif selected_text.endswith(':'):
            # Don't add space, trigger autocomplete immediately for value suggestions
            # Trigger immediately without delay for instant response
            def trigger_immediate():
                self.check_autocomplete()
            wx.CallAfter(trigger_immediate)
        
        # Check if we're in a keyword value context (inside parentheses after a keyword)
        # This handles both initial values and comma-separated values
        elif '(' in text_before and not selected_text.endswith(':') and not selected_text.endswith(';'):
            # Check if we're in a keyword value context by looking for keyword: pattern
            # Extract content after opening paren
            paren_content = text_before.split('(')[-1]
            # Get the current statement (after last semicolon)
            if ';' in paren_content:
                current_statement = paren_content.split(';')[-1]
            else:
                current_statement = paren_content
            
            # If there's a colon in the current statement, we're in a keyword value context
            if ':' in current_statement:
                # Don't add trailing space - user needs to add comma or semicolon
                # No action needed - value inserted as-is
                pass
            else:
                # Not in a keyword value context, add space
                def after_insert():
                    self.editor.AddText(' ')
                    wx.CallLater(100, self.check_autocomplete)
                wx.CallAfter(after_insert)
        
        # Default: add trailing space and auto-trigger next autocomplete
        else:
            def after_insert():
                self.editor.AddText(' ')
                # Auto-trigger autocomplete for next field
                wx.CallLater(100, self.check_autocomplete)
            wx.CallAfter(after_insert)
    
    def check_autocomplete(self):
        """Check if autocomplete should be shown"""
        pos = self.editor.GetCurrentPos()
        line_num = self.editor.LineFromPosition(pos)
        line_start = self.editor.PositionFromLine(line_num)
        
        # Get text before cursor on current line
        text_before = self.editor.GetTextRange(line_start, pos)
        
        # Don't show for comments or blank lines
        if not text_before.strip() or text_before.strip().startswith('#'):
            return
        
        # Get autocomplete suggestions based on context
        suggestions = self.get_autocomplete_suggestions(text_before)
        
        if suggestions:
            # Get current word to determine how many chars to show
            current_word = self.get_current_word()
            word_len = len(current_word)
            
            # Filter suggestions by current word
            if current_word:
                filtered = [s for s in suggestions if s.lower().startswith(current_word.lower())]
            else:
                filtered = suggestions
            
            if filtered:
                # Show autocomplete (separator is space)
                self.editor.AutoCompShow(word_len, ' '.join(filtered))
    
    def get_current_word(self):
        """Get the word currently being typed"""
        pos = self.editor.GetCurrentPos()
        line_num = self.editor.LineFromPosition(pos)
        line_start = self.editor.PositionFromLine(line_num)
        text_before = self.editor.GetTextRange(line_start, pos)
        
        # Check if we're inside parentheses (content keywords context)
        if '(' in text_before and ')' not in text_before:
            paren_content = text_before.split('(')[-1]
            
            # Get content after last semicolon (or all if no semicolon)
            if ';' in paren_content:
                current_statement = paren_content.split(';')[-1].strip()
            else:
                current_statement = paren_content.strip()
            
            # Check if we have a keyword with colon (like "flow:to_server, s")
            if ':' in current_statement:
                # Split by colon to get keyword and values
                parts = current_statement.split(':', 1)
                if len(parts) == 2:
                    values_part = parts[1]
                    
                    # If there are commas, get the part after the last comma
                    # This handles "to_server, s" -> returns "s"
                    if ',' in values_part:
                        # Get part after last comma, strip leading spaces
                        after_comma = values_part.split(',')[-1].lstrip()
                        # Return just the current word being typed (no trailing space)
                        return after_comma.rstrip()
                    
                    # No comma, return the value part (e.g., "s" from "flow:s")
                    return values_part.strip()
                
                # Ends with colon, no value yet
                if current_statement.endswith(':'):
                    return ''
            
            # No colon, return the current word
            return current_statement
        
        # Not in parentheses - regular word extraction
        words = text_before.split()
        if words and not text_before.endswith(' '):
            return words[-1]
        return ''
    
    def get_autocomplete_suggestions(self, text_before):
        """Get autocomplete suggestions based on context"""
        words = text_before.split()
        word_count = len([w for w in words if w])
        
        # Action (first word)
        if word_count == 0 or (word_count == 1 and not text_before.endswith(' ')):
            return ['alert', 'pass', 'drop', 'reject']
        
        # Protocol (second word)
        if word_count == 1 or (word_count == 2 and not text_before.endswith(' ')):
            return SuricataConstants.SUPPORTED_PROTOCOLS
        
        # Source Network (third section)
        if word_count == 2 or (word_count == 3 and not text_before.endswith(' ')):
            # Start with common values
            suggestions = ['any', '$HOME_NET', '$EXTERNAL_NET']
            # Add IP set variables (filter out port sets)
            ip_vars = self._filter_ip_set_variables()
            # Deduplicate by using dict.fromkeys to preserve order
            all_suggestions = list(dict.fromkeys(suggestions + ip_vars))
            return all_suggestions
        
        # Source Port (fourth section)
        if word_count == 3 or (word_count == 4 and not text_before.endswith(' ')):
            # Start with common port values
            suggestions = ['any', '80', '443', '[80,443]', '[8080:8090]']
            # Add port set variables from Rule Variables
            port_vars = self._filter_port_set_variables()
            # Deduplicate by using dict.fromkeys to preserve order
            all_suggestions = list(dict.fromkeys(suggestions + port_vars))
            return all_suggestions
        
        # Direction (fifth section)
        if word_count == 4 or (word_count == 5 and not text_before.endswith(' ')):
            return ['->', '<>']
        
        # Destination Network (sixth section)
        if word_count == 5 or (word_count == 6 and not text_before.endswith(' ')):
            # Start with common values
            suggestions = ['any', '$HOME_NET', '$EXTERNAL_NET']
            # Add IP set variables (filter out port sets)
            ip_vars = self._filter_ip_set_variables()
            # Deduplicate by using dict.fromkeys to preserve order
            all_suggestions = list(dict.fromkeys(suggestions + ip_vars))
            return all_suggestions
        
        # Destination Port (seventh section)
        if word_count == 6 or (word_count == 7 and not text_before.endswith(' ')):
            # Start with common port values
            suggestions = ['any', '80', '443', '[80,443]']
            # Add port set variables from Rule Variables
            port_vars = self._filter_port_set_variables()
            # Deduplicate by using dict.fromkeys to preserve order
            all_suggestions = list(dict.fromkeys(suggestions + port_vars))
            return all_suggestions
        
        # Content keywords (inside parentheses)
        if '(' in text_before and ')' not in text_before:
            return self.get_content_keyword_suggestions(text_before)
        
        return []
    
    def _filter_ip_set_variables(self):
        """Filter variables to return only IP set variables (exclude port sets)
        
        Returns IP/network variables that start with $ or @, excluding those that
        look like port definitions.
        """
        ip_vars = []
        for var_name, var_data in self.variables.items():
            # Only include variables with $ or @ prefix
            if not var_name.startswith(('$', '@')):
                continue
            
            # Get the variable definition (handle both dict and string formats)
            if isinstance(var_data, dict):
                definition = var_data.get("definition", "")
            else:
                definition = var_data
            
            # Skip if it looks like a port definition
            if definition and self._looks_like_port_definition(definition):
                continue
            
            ip_vars.append(var_name)
        
        return sorted(ip_vars)
    
    def _filter_port_set_variables(self):
        """Filter variables to return only port set variables
        
        Returns port variables that start with $ and have port-like definitions.
        Only $ prefix is allowed for port variables per AWS Network Firewall requirements.
        """
        port_vars = []
        for var_name, var_data in self.variables.items():
            # Port variables must use $ prefix (not @)
            if not var_name.startswith('$'):
                continue
            
            # Get the variable definition (handle both dict and string formats)
            if isinstance(var_data, dict):
                definition = var_data.get("definition", "")
            else:
                definition = var_data
            
            # Include if it looks like a port definition
            if definition and self._looks_like_port_definition(definition):
                port_vars.append(var_name)
        
        return sorted(port_vars)
    
    def _looks_like_port_definition(self, definition):
        """Check if a variable definition looks like a port specification
        
        Detects patterns like:
        - Single port: 80
        - Port list: [80,443,8080]
        - Port range: [8000:9000]
        - Complex: [80,443,8000:9000]
        
        Args:
            definition: Variable definition string
            
        Returns:
            bool: True if definition looks like ports
        """
        if not definition:
            return False
        
        definition = definition.strip()
        
        # Check for bracketed port lists/ranges
        if definition.startswith('[') and definition.endswith(']'):
            inner = definition[1:-1].strip()
            # Check for port patterns: numbers, commas, colons, exclamation
            if all(c.isdigit() or c in ',: !' for c in inner.replace(' ', '')):
                return True
        
        # Check for single port number
        if definition.isdigit():
            port_num = int(definition)
            if 1 <= port_num <= 65535:
                return True
        
        # Check for simple port range without brackets (less common but valid)
        if ':' in definition:
            parts = definition.split(':')
            if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
                return True
        
        return False
    
    def get_content_keyword_suggestions(self, text_before):
        """Get content keyword suggestions"""
        # Check if right after completed sid keyword - suggest rev
        if re.search(r'sid:\s*\d+;\s*$', text_before):
            return ['rev:1;']  # Special format for auto-completion
        
        # Check for sid: suggest next SID with semicolon (allow immediate or with space)
        if 'sid:' in text_before and re.search(r'sid:\s*$', text_before):
            # Calculate next available SID from current editor
            text = self.editor.GetText()
            lines = text.split('\n')
            used_sids = set()
            
            for line in lines:
                sid_match = re.search(r'sid:\s*(\d+)', line)
                if sid_match:
                    used_sids.add(int(sid_match.group(1)))
            
            # Find next available SID (max + 1, like main program)
            if used_sids:
                next_sid = max(used_sids) + 1
            else:
                next_sid = 100
            
            return [f'{next_sid};']  # Include semicolon in suggestion
        
        # Check for rev: suggest default with semicolon (allow immediate or with space)
        if 'rev:' in text_before and re.search(r'rev:\s*$', text_before):
            return ['1;']  # Include semicolon
        
        # Check if typing a keyword value (after "keyword:")
        keyword_match = re.search(r'(\w+(?:\.\w+)?):([^;]*?)$', text_before)
        if keyword_match:
            keyword_name = keyword_match.group(1)
            
            # Find keyword values if keywords_data loaded
            if self.keywords_data:
                for kw in self.keywords_data.get('keywords', []):
                    if kw.get('name', '') == keyword_name:
                        values = kw.get('values', [])
                        if values:
                            return values
        
        # Default: show keyword names
        if not self.keywords_data:
            return ['msg:', 'sid:', 'rev:', 'content:', 'flow:']
        
        keywords = self.keywords_data.get('keywords', [])
        suggestions = []
        
        for kw in keywords:
            name = kw.get('name', '')
            if name:
                if kw.get('values'):
                    suggestions.append(f"{name}:")
                else:
                    syntax = kw.get('syntax', '')
                    if '<' in syntax:
                        suggestions.append(f"{name}:")
                    else:
                        suggestions.append(syntax if syntax else f"{name}:")
        
        return suggestions[:20]  # Limit to 20 suggestions
    
    def on_update_ui(self, event):
        """UI update - update status bar and check bracket matching"""
        self.update_status_bar()
        self.check_bracket_match()
    
    def check_bracket_match(self):
        """Check and highlight matching brackets/parentheses/quotes"""
        pos = self.editor.GetCurrentPos()
        
        # Check character at cursor and before cursor
        char_at = chr(self.editor.GetCharAt(pos)) if pos < self.editor.GetLength() else ''
        char_before = chr(self.editor.GetCharAt(pos - 1)) if pos > 0 else ''
        
        # Define bracket pairs to match
        open_brackets = '(["\''
        close_brackets = ')]\'"'
        bracket_pairs = {'(': ')', '[': ']', '"': '"', "'": "'"}
        
        match_pos = -1
        check_pos = -1
        
        # Check if cursor is after an opening or closing bracket
        if char_before in open_brackets or char_before in close_brackets:
            check_pos = pos - 1
        # Or if cursor is before an opening or closing bracket
        elif char_at in open_brackets or char_at in close_brackets:
            check_pos = pos
        
        if check_pos >= 0:
            # Find matching bracket
            match_pos = self.find_matching_bracket(check_pos)
            
            if match_pos >= 0:
                # Highlight both brackets
                self.editor.BraceHighlight(check_pos, match_pos)
            else:
                # Bad bracket (no match)
                self.editor.BraceBadLight(check_pos)
        else:
            # No bracket at cursor, clear highlighting
            self.editor.BraceHighlight(stc.STC_INVALID_POSITION, stc.STC_INVALID_POSITION)
    
    def find_matching_bracket(self, pos):
        """Find the matching bracket for the bracket at pos
        
        Supports nested brackets: ( ), [ ], " "
        Returns position of matching bracket or -1 if not found
        """
        if pos < 0 or pos >= self.editor.GetLength():
            return -1
        
        char = chr(self.editor.GetCharAt(pos))
        
        # Special handling for quotes (they're self-matching and need context to determine direction)
        if char == '"':
            # Get current line boundaries
            current_line_num = self.editor.LineFromPosition(pos)
            line_start = self.editor.PositionFromLine(current_line_num)
            line_end = self.editor.GetLineEndPosition(current_line_num)
            
            # Count unescaped quotes before this position on the same line
            quote_count = 0
            check_pos = line_start
            while check_pos < pos:
                if chr(self.editor.GetCharAt(check_pos)) == '"':
                    # Check if escaped
                    if check_pos > 0 and chr(self.editor.GetCharAt(check_pos - 1)) == '\\':
                        pass  # Escaped, don't count
                    else:
                        quote_count += 1
                check_pos += 1
            
            # Even count = this is an opening quote (search forward)
            # Odd count = this is a closing quote (search backward)
            if quote_count % 2 == 0:
                # Opening quote - search forward
                search_pos = pos + 1
                while search_pos < line_end:
                    if chr(self.editor.GetCharAt(search_pos)) == '"':
                        # Check if escaped
                        if search_pos > 0 and chr(self.editor.GetCharAt(search_pos - 1)) == '\\':
                            search_pos += 1
                            continue
                        return search_pos
                    search_pos += 1
                return -1
            else:
                # Closing quote - search backward
                search_pos = pos - 1
                while search_pos >= line_start:
                    if chr(self.editor.GetCharAt(search_pos)) == '"':
                        # Check if escaped
                        if search_pos > 0 and chr(self.editor.GetCharAt(search_pos - 1)) == '\\':
                            search_pos -= 1
                            continue
                        return search_pos
                    search_pos -= 1
                return -1
        
        # Define bracket pairs (not for quotes since handled above)
        opening = {'(': ')', '[': ']'}
        closing = {')': '(', ']': '['}
        
        # Determine if we're on an opening or closing bracket
        if char in opening:
            # Search forward for closing bracket
            target = opening[char]
            direction = 1
            start = pos + 1
            end = self.editor.GetLength()
            depth = 1
        elif char in closing:
            # Search backward for opening bracket
            target = closing[char]
            direction = -1
            start = pos - 1
            end = -1
            depth = 1
        else:
            return -1
        
        # For brackets and parentheses, handle nesting (limit to same line)
        current_line_num = self.editor.LineFromPosition(pos)
        line_start = self.editor.PositionFromLine(current_line_num)
        line_end = self.editor.GetLineEndPosition(current_line_num)
        
        search_pos = start
        while (direction > 0 and search_pos < end) or (direction < 0 and search_pos > end):
            # Stop if we've gone beyond the current line
            if direction > 0 and search_pos >= line_end:
                return -1
            if direction < 0 and search_pos < line_start:
                return -1
            
            check_char = chr(self.editor.GetCharAt(search_pos))
            
            if check_char == char:
                # Found another opening bracket, increase depth
                depth += 1
            elif check_char == target:
                # Found a closing bracket, decrease depth
                depth -= 1
                if depth == 0:
                    return search_pos
            
            search_pos += direction
        
        return -1
    
    def on_margin_click(self, event):
        """Handle margin click for folding"""
        # Check if click was on fold margin
        if event.GetMargin() == 2:
            line_num = self.editor.LineFromPosition(event.GetPosition())
            
            # Toggle fold
            self.editor.ToggleFold(line_num)
    
    def on_char_hook(self, event):
        """Character hook - highest priority event handler for capturing shortcuts"""
        key_code = event.GetKeyCode()
        ctrl_down = event.ControlDown() or event.CmdDown()
        
        # Ctrl+F for find/replace
        if ctrl_down and (key_code == ord('F') or key_code == ord('f') or key_code == 70):
            self.show_find_replace_dialog()
            return  # Don't skip - consume the event
        
        # Ctrl+G for go to line
        if ctrl_down and key_code == ord('G'):
            self.on_goto_line(event)
            return  # Don't skip - consume the event
        
        # Ctrl+/ for toggle comment
        if ctrl_down and key_code == ord('/'):
            self.on_toggle_comment(event)
            return  # Don't skip - consume the event
        
        # F3 for find next
        if key_code == wx.WXK_F3:
            if event.ShiftDown():
                self.find_previous()
            else:
                self.find_next()
            return  # Don't skip - consume the event
        
        # Escape to close search
        if key_code == wx.WXK_ESCAPE:
            if self.search_active:
                self.close_search()
                return  # Don't skip - consume the event
        
        # Allow all other events to propagate
        event.Skip()
    
    def on_key_down(self, event):
        """Handle special key combinations"""
        key_code = event.GetKeyCode()
        ctrl_down = event.ControlDown() or event.CmdDown()  # CmdDown for Mac
        
        # F3 for find next
        if key_code == wx.WXK_F3:
            if event.ShiftDown():
                self.find_previous()
            else:
                self.find_next()
            return
        
        # Escape to close search
        if key_code == wx.WXK_ESCAPE:
            if self.search_active:
                self.close_search()
            return
        
        # Backspace for smart delete of matching pairs
        if key_code == wx.WXK_BACK:
            pos = self.editor.GetCurrentPos()
            
            # Get character before and after cursor
            if pos > 0:
                char_before = self.editor.GetCharAt(pos - 1)
                char_after = self.editor.GetCharAt(pos)
                
                # Check for matching pairs
                pairs = {
                    ord('('): ord(')'),
                    ord('['): ord(']'),
                    ord('"'): ord('"')
                }
                
                # Special case for "; after quote
                if char_before == ord('"'):
                    # Check if next two characters are ";
                    if pos + 1 < self.editor.GetLength():
                        next_char = self.editor.GetCharAt(pos + 1)
                        if char_after == ord('"') and next_char == ord(';'):
                            # Delete all three: opening quote, closing quote, and semicolon
                            self.editor.SetSelection(pos - 1, pos + 2)
                            self.editor.ReplaceSelection('')
                            return
                
                # Check for standard pairs
                if char_before in pairs and char_after == pairs[char_before]:
                    # Delete both characters
                    self.editor.SetSelection(pos - 1, pos + 1)
                    self.editor.ReplaceSelection('')
                    return
            
            # If no pair matched, use default backspace behavior
            event.Skip()
            return
        
        # Tab key for smart navigation in rule options or regular tab
        if key_code == wx.WXK_TAB:
            # Check if autocomplete is active - if so, it will handle Tab
            if self.editor.AutoCompActive():
                event.Skip()
                return
            
            # Smart Tab: Jump to next semicolon when inside parentheses
            pos = self.editor.GetCurrentPos()
            line_num = self.editor.LineFromPosition(pos)
            line_start = self.editor.PositionFromLine(line_num)
            col = pos - line_start
            
            line_text = self.editor.GetLine(line_num)
            text_before = line_text[:col]
            text_after = line_text[col:]
            
            # Check if we're inside parentheses
            open_parens = text_before.count('(') - text_before.count(')')
            
            if open_parens > 0 and ')' in text_after:
                # Find next semicolon
                semicolon_pos = text_after.find(';')
                closing_paren_pos = text_after.find(')')
                
                if semicolon_pos != -1 and semicolon_pos < closing_paren_pos:
                    # Jump to after semicolon
                    new_pos = pos + semicolon_pos + 1
                    self.editor.GotoPos(new_pos)
                    return
                elif closing_paren_pos != -1:
                    # No semicolon, jump to after closing paren
                    new_pos = pos + closing_paren_pos + 1
                    self.editor.GotoPos(new_pos)
                    return
            
            # Default: insert 4 spaces
            self.editor.AddText('    ')
        else:
            event.Skip()
    
    def on_find(self, event):
        """Show find/replace dialog"""
        self.show_find_replace_dialog()
    
    def on_goto_line(self, event):
        """Go to specific line"""
        line_count = self.editor.GetLineCount()
        
        dlg = wx.TextEntryDialog(
            self,
            f"Enter line number (1-{line_count}):",
            "Go to Line"
        )
        
        if dlg.ShowModal() == wx.ID_OK:
            try:
                line_num = int(dlg.GetValue())
                if 1 <= line_num <= line_count:
                    # Go to line
                    pos = self.editor.PositionFromLine(line_num - 1)
                    self.editor.GotoPos(pos)
                    self.editor.SetSelection(pos, self.editor.GetLineEndPosition(line_num - 1))
                else:
                    wx.MessageBox(f"Line number must be between 1 and {line_count}", "Invalid Line")
            except ValueError:
                wx.MessageBox("Please enter a valid line number", "Invalid Input")
        
        dlg.Destroy()
    
    def on_toggle_comment(self, event):
        """Toggle comment for selected lines or current line"""
        # Get selection or current line
        if self.editor.GetSelectionStart() != self.editor.GetSelectionEnd():
            # Has selection
            start_pos = self.editor.GetSelectionStart()
            end_pos = self.editor.GetSelectionEnd()
            start_line = self.editor.LineFromPosition(start_pos)
            end_line = self.editor.LineFromPosition(end_pos)
            
            # If selection ends at start of line, don't include that line
            if self.editor.GetColumn(end_pos) == 0 and end_line > start_line:
                end_line -= 1
        else:
            # No selection - use current line
            pos = self.editor.GetCurrentPos()
            start_line = self.editor.LineFromPosition(pos)
            end_line = start_line
        
        # Check if all lines are comments
        all_comments = True
        for line_num in range(start_line, end_line + 1):
            line_text = self.editor.GetLine(line_num).strip()
            if line_text and not line_text.startswith('#'):
                all_comments = False
                break
        
        # Toggle comments
        for line_num in range(start_line, end_line + 1):
            line_start_pos = self.editor.PositionFromLine(line_num)
            line_end_pos = self.editor.GetLineEndPosition(line_num)
            line_text = self.editor.GetTextRange(line_start_pos, line_end_pos)
            line_stripped = line_text.lstrip()
            
            if not line_stripped:
                # Skip blank lines
                continue
            
            if all_comments:
                # Uncomment: remove # and space
                if line_stripped.startswith('# '):
                    new_line = line_text.replace('# ', '', 1)
                elif line_stripped.startswith('#'):
                    new_line = line_text.replace('#', '', 1)
                else:
                    continue
            else:
                # Comment: add # and space
                leading_spaces = len(line_text) - len(line_stripped)
                new_line = line_text[:leading_spaces] + '# ' + line_stripped
            
            # Replace the line
            self.editor.SetTargetStart(line_start_pos)
            self.editor.SetTargetEnd(line_end_pos)
            self.editor.ReplaceTarget(new_line)
    
    def on_show_shortcuts(self, event):
        """Display keyboard shortcuts"""
        shortcuts_text = """Advanced Editor Keyboard Shortcuts:

Editing:
  Ctrl+Z        Undo
  Ctrl+Y        Redo
  Ctrl+X        Cut
  Ctrl+C        Copy
  Ctrl+V        Paste
  Ctrl+A        Select All
  Ctrl+/        Toggle Comment
  Backspace     Smart delete matching pairs
  Tab           Jump to next semicolon (in rule options)

Auto-Complete:
  Type          Auto-trigger suggestions
  Tab/Enter     Accept suggestion
  Esc           Cancel auto-complete

Auto-Close:
  (             Auto-insert )
  [             Auto-insert ]
  "             Auto-insert ";

Search & Replace:
  Ctrl+F        Find and Replace
  F3            Find Next
  Shift+F3      Find Previous
  Escape        Close Search

Navigation:
  Ctrl+G        Go to Line
  Home/End      Start/End of Line

View:
  Ctrl+Scroll   Zoom In/Out

Code Folding:
  Click +/-     Collapse/Expand Groups
"""
        dlg = wx.MessageDialog(self, shortcuts_text, "Keyboard Shortcuts", wx.OK)
        dlg.ShowModal()
        dlg.Destroy()
    
    def show_find_replace_dialog(self):
        """Show unified Find and Replace dialog"""
        # Create dialog
        dlg = wx.Dialog(self, title="Find and Replace", size=(600, 750),
                       style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        dlg.CentreOnParent()
        
        # Main sizer
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # Search term section
        search_box = wx.StaticBoxSizer(wx.VERTICAL, dlg, "Search Term")
        
        find_label = wx.StaticText(search_box.GetStaticBox(), label="Find what:")
        search_box.Add(find_label, 0, wx.ALL, 5)
        search_ctrl = wx.TextCtrl(search_box.GetStaticBox(), value=self.search_term, size=(550, -1))
        search_box.Add(search_ctrl, 0, wx.EXPAND | wx.ALL, 5)
        
        replace_label = wx.StaticText(search_box.GetStaticBox(), label="Replace with:")
        search_box.Add(replace_label, 0, wx.ALL, 5)
        replace_ctrl = wx.TextCtrl(search_box.GetStaticBox(), value=self.replace_term, size=(550, -1))
        search_box.Add(replace_ctrl, 0, wx.EXPAND | wx.ALL, 5)
        
        main_sizer.Add(search_box, 0, wx.EXPAND | wx.ALL, 10)
        
        # Field-specific search section
        field_box = wx.StaticBoxSizer(wx.VERTICAL, dlg, "Field-Specific Search")
        field_panel = wx.Panel(field_box.GetStaticBox())
        field_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        search_in_label = wx.StaticText(field_panel, label="Search in:")
        field_sizer.Add(search_in_label, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 10)
        
        field_choices = ["All fields", "Message", "Content", "Networks (src/dst)", 
                        "Ports (src/dst)", "SID", "Protocol"]
        field_choice = wx.Choice(field_panel, choices=field_choices)
        field_choice.SetSelection(0)  # Default to "All fields"
        field_sizer.Add(field_choice, 1, wx.EXPAND)
        
        field_panel.SetSizer(field_sizer)
        field_box.Add(field_panel, 0, wx.EXPAND | wx.ALL, 5)
        
        main_sizer.Add(field_box, 0, wx.EXPAND | wx.ALL, 10)
        
        # Action-based filtering section
        action_box = wx.StaticBoxSizer(wx.VERTICAL, dlg, "Action-Based Filtering")
        action_panel = wx.Panel(action_box.GetStaticBox())
        action_grid = wx.GridSizer(3, 2, 5, 20)
        
        pass_cb = wx.CheckBox(action_panel, label="Pass rules")
        pass_cb.SetValue(self.search_filters['pass'])
        drop_cb = wx.CheckBox(action_panel, label="Drop rules")
        drop_cb.SetValue(self.search_filters['drop'])
        reject_cb = wx.CheckBox(action_panel, label="Reject rules")
        reject_cb.SetValue(self.search_filters['reject'])
        alert_cb = wx.CheckBox(action_panel, label="Alert rules")
        alert_cb.SetValue(self.search_filters['alert'])
        comments_cb = wx.CheckBox(action_panel, label="Comments")
        comments_cb.SetValue(self.search_filters['comments'])
        
        action_grid.Add(pass_cb)
        action_grid.Add(drop_cb)
        action_grid.Add(reject_cb)
        action_grid.Add(alert_cb)
        action_grid.Add(comments_cb)
        
        action_panel.SetSizer(action_grid)
        action_box.Add(action_panel, 0, wx.EXPAND | wx.ALL, 5)
        
        # Select/Deselect buttons
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        select_all_btn = wx.Button(action_box.GetStaticBox(), label="Select All")
        deselect_all_btn = wx.Button(action_box.GetStaticBox(), label="Deselect All")
        
        def on_select_all(e):
            pass_cb.SetValue(True)
            drop_cb.SetValue(True)
            reject_cb.SetValue(True)
            alert_cb.SetValue(True)
            comments_cb.SetValue(True)
        
        def on_deselect_all(e):
            pass_cb.SetValue(False)
            drop_cb.SetValue(False)
            reject_cb.SetValue(False)
            alert_cb.SetValue(False)
            comments_cb.SetValue(False)
        
        select_all_btn.Bind(wx.EVT_BUTTON, on_select_all)
        deselect_all_btn.Bind(wx.EVT_BUTTON, on_deselect_all)
        
        btn_sizer.Add(select_all_btn, 0, wx.RIGHT, 5)
        btn_sizer.Add(deselect_all_btn)
        action_box.Add(btn_sizer, 0, wx.ALL, 5)
        
        main_sizer.Add(action_box, 0, wx.EXPAND | wx.ALL, 10)
        
        # Advanced search options
        options_box = wx.StaticBoxSizer(wx.VERTICAL, dlg, "Advanced Search Options")
        options_panel = wx.Panel(options_box.GetStaticBox())
        options_grid = wx.GridSizer(2, 2, 5, 20)
        
        case_cb = wx.CheckBox(options_panel, label="Case sensitive")
        case_cb.SetValue(self.search_options['case_sensitive'])
        whole_word_cb = wx.CheckBox(options_panel, label="Whole word matching")
        whole_word_cb.SetValue(self.search_options['whole_word'])
        regex_cb = wx.CheckBox(options_panel, label="Regular expression")
        regex_cb.SetValue(self.search_options['regex'])
        
        options_grid.Add(case_cb)
        options_grid.Add(whole_word_cb)
        options_grid.Add(regex_cb)
        
        options_panel.SetSizer(options_grid)
        options_box.Add(options_panel, 0, wx.EXPAND | wx.ALL, 5)
        
        main_sizer.Add(options_box, 0, wx.EXPAND | wx.ALL, 10)
        
        # Buttons
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        button_sizer.AddStretchSpacer()
        
        find_btn = wx.Button(dlg, label="Find")
        find_next_btn = wx.Button(dlg, label="Find Next")
        replace_btn = wx.Button(dlg, label="Replace")
        replace_all_btn = wx.Button(dlg, label="Replace All")
        close_btn = wx.Button(dlg, wx.ID_CLOSE, "Close")
        
        def on_find(e):
            term = search_ctrl.GetValue().strip()
            if not term:
                wx.MessageBox("Please enter a search term.", "Find", wx.OK | wx.ICON_WARNING, dlg)
                return
            
            self.search_term = term
            self.replace_term = replace_ctrl.GetValue()
            
            # Get field selection
            field_map = ["all", "message", "content", "networks", "ports", "sid", "protocol"]
            self.search_field = field_map[field_choice.GetSelection()]
            
            # Update filters
            self.search_filters['pass'] = pass_cb.GetValue()
            self.search_filters['drop'] = drop_cb.GetValue()
            self.search_filters['reject'] = reject_cb.GetValue()
            self.search_filters['alert'] = alert_cb.GetValue()
            self.search_filters['comments'] = comments_cb.GetValue()
            
            # Update options
            self.search_options['case_sensitive'] = case_cb.GetValue()
            self.search_options['whole_word'] = whole_word_cb.GetValue()
            self.search_options['regex'] = regex_cb.GetValue()
            
            # Perform search
            self.perform_search()
            
            if self.search_results:
                wx.MessageBox(f"Found {len(self.search_results)} matches.\n\nPress F3 for next, Shift+F3 for previous, Escape to close.",
                            "Search", wx.OK | wx.ICON_INFORMATION, self)
            
            dlg.Close()
        
        def on_find_next(e):
            term = search_ctrl.GetValue().strip()
            if not term:
                wx.MessageBox("Please enter a search term.", "Find", wx.OK | wx.ICON_WARNING, dlg)
                return
            
            # Update search if term or filters changed
            if (not self.search_active or self.search_term != term or
                self.search_filters['pass'] != pass_cb.GetValue() or
                self.search_filters['drop'] != drop_cb.GetValue() or
                self.search_filters['reject'] != reject_cb.GetValue() or
                self.search_filters['alert'] != alert_cb.GetValue() or
                self.search_filters['comments'] != comments_cb.GetValue()):
                
                self.search_term = term
                self.replace_term = replace_ctrl.GetValue()
                
                # Get field selection
                field_map = ["all", "message", "content", "networks", "ports", "sid", "protocol"]
                self.search_field = field_map[field_choice.GetSelection()]
                
                # Update filters
                self.search_filters['pass'] = pass_cb.GetValue()
                self.search_filters['drop'] = drop_cb.GetValue()
                self.search_filters['reject'] = reject_cb.GetValue()
                self.search_filters['alert'] = alert_cb.GetValue()
                self.search_filters['comments'] = comments_cb.GetValue()
                
                # Update options
                self.search_options['case_sensitive'] = case_cb.GetValue()
                self.search_options['whole_word'] = whole_word_cb.GetValue()
                self.search_options['regex'] = regex_cb.GetValue()
                
                # Perform new search
                self.perform_search()
            else:
                # Just move to next
                if self.search_results:
                    self.find_next()
                else:
                    wx.MessageBox("No matches found.", "Find", wx.OK | wx.ICON_INFORMATION, dlg)
        
        def on_replace(e):
            term = search_ctrl.GetValue().strip()
            if not term:
                wx.MessageBox("Please enter a search term.", "Replace", wx.OK | wx.ICON_WARNING, dlg)
                return
            
            self.replace_term = replace_ctrl.GetValue()
            
            # If search not active or term changed, perform search first
            if not self.search_active or self.search_term != term:
                on_find_next(e)
                return
            
            # Replace current match
            if self.search_results and self.current_search_index >= 0:
                self.replace_current()
                if not self.search_results:
                    wx.MessageBox("No more matches found. All replacements complete.",
                                "Replace", wx.OK | wx.ICON_INFORMATION, dlg)
            else:
                wx.MessageBox("No match at current position.", "Replace", wx.OK | wx.ICON_INFORMATION, dlg)
        
        def on_replace_all(e):
            term = search_ctrl.GetValue().strip()
            if not term:
                wx.MessageBox("Please enter a search term.", "Replace All", wx.OK | wx.ICON_WARNING, dlg)
                return
            
            self.search_term = term
            self.replace_term = replace_ctrl.GetValue()
            
            # Get field selection
            field_map = ["all", "message", "content", "networks", "ports", "sid", "protocol"]
            self.search_field = field_map[field_choice.GetSelection()]
            
            # Update filters
            self.search_filters['pass'] = pass_cb.GetValue()
            self.search_filters['drop'] = drop_cb.GetValue()
            self.search_filters['reject'] = reject_cb.GetValue()
            self.search_filters['alert'] = alert_cb.GetValue()
            self.search_filters['comments'] = comments_cb.GetValue()
            
            # Update options
            self.search_options['case_sensitive'] = case_cb.GetValue()
            self.search_options['whole_word'] = whole_word_cb.GetValue()
            self.search_options['regex'] = regex_cb.GetValue()
            
            # Perform replacement
            count = self.replace_all()
            dlg.Close()
            
            if count > 0:
                wx.MessageBox(f"Replaced {count} occurrences.", "Replace All",
                            wx.OK | wx.ICON_INFORMATION, self)
            else:
                wx.MessageBox("No occurrences found to replace.", "Replace All",
                            wx.OK | wx.ICON_INFORMATION, self)
        
        def on_close(e):
            self.close_search()
            dlg.Close()
        
        find_btn.Bind(wx.EVT_BUTTON, on_find)
        find_next_btn.Bind(wx.EVT_BUTTON, on_find_next)
        replace_btn.Bind(wx.EVT_BUTTON, on_replace)
        replace_all_btn.Bind(wx.EVT_BUTTON, on_replace_all)
        close_btn.Bind(wx.EVT_BUTTON, on_close)
        
        button_sizer.Add(find_btn, 0, wx.ALL, 5)
        button_sizer.Add(find_next_btn, 0, wx.ALL, 5)
        button_sizer.Add(replace_btn, 0, wx.ALL, 5)
        button_sizer.Add(replace_all_btn, 0, wx.ALL, 5)
        button_sizer.Add(close_btn, 0, wx.ALL, 5)
        
        main_sizer.Add(button_sizer, 0, wx.EXPAND | wx.ALL, 10)
        
        dlg.SetSizer(main_sizer)
        dlg.ShowModal()
        dlg.Destroy()
    
    def perform_search(self):
        """Perform search with current settings using Scintilla's search"""
        if not self.search_term:
            return
        
        # Clear previous search results
        self.clear_search_highlights()
        self.search_results = []
        self.current_search_index = -1
        
        # Get all text
        text = self.editor.GetText()
        lines = text.split('\n')
        
        # Compile regex if needed
        regex_pattern = None
        if self.search_options['regex']:
            try:
                flags = 0 if self.search_options['case_sensitive'] else re.IGNORECASE
                regex_pattern = re.compile(self.search_term, flags)
            except re.error as e:
                wx.MessageBox(f"Invalid regular expression: {str(e)}", "Regex Error",
                            wx.OK | wx.ICON_ERROR, self)
                return
        
        # Search through lines
        for line_num, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Skip blank lines
            if not line_stripped:
                continue
            
            # Check if comment
            is_comment = line_stripped.startswith('#')
            
            # Apply action filters
            if is_comment:
                if not self.search_filters['comments']:
                    continue
            else:
                # Parse action
                tokens = line_stripped.split()
                if tokens:
                    action = tokens[0].lower()
                    if action not in ['pass', 'drop', 'reject', 'alert']:
                        continue
                    if not self.search_filters.get(action, True):
                        continue
            
            # Get search text based on field filter
            search_text = self.get_search_text_from_line(line, line_stripped, is_comment)
            if search_text is None:
                continue
            
            # Find matches in this line
            matches = self.find_matches_in_text(search_text, line, line_num, regex_pattern)
            self.search_results.extend(matches)
        
        # Show results
        if self.search_results:
            self.search_active = True
            self.current_search_index = 0
            self.highlight_current_match()
        else:
            self.search_active = False
    
    def get_search_text_from_line(self, line, line_stripped, is_comment):
        """Extract appropriate text to search based on field filter"""
        if is_comment:
            return line if self.search_field == "all" else line if self.search_field == "message" else None
        
        # For rules, parse components
        if self.search_field == "all":
            return line
        
        # Parse rule to extract fields
        try:
            tokens = line_stripped.split()
            if len(tokens) < 7:
                return None
            
            action = tokens[0]
            protocol = tokens[1]
            src_net = tokens[2]
            src_port = tokens[3]
            dst_net = tokens[5] if len(tokens) > 5 else ""
            dst_port = tokens[6] if len(tokens) > 6 else ""
            
            # Extract message and SID from options
            message = ""
            sid = ""
            content = ""
            
            if '(' in line and ')' in line:
                opts_start = line.find('(')
                opts_end = line.rfind(')')
                options = line[opts_start+1:opts_end]
                
                msg_match = re.search(r'msg:"([^"]*)"', options)
                if msg_match:
                    message = msg_match.group(1)
                
                sid_match = re.search(r'sid:(\d+)', options)
                if sid_match:
                    sid = sid_match.group(1)
                
                content = options
            
            # Return appropriate field
            if self.search_field == "message":
                return message
            elif self.search_field == "content":
                return content
            elif self.search_field == "networks":
                return f"{src_net} {dst_net}"
            elif self.search_field == "ports":
                return f"{src_port} {dst_port}"
            elif self.search_field == "sid":
                return sid
            elif self.search_field == "protocol":
                return protocol
        except:
            return None
        
        return line
    
    def find_matches_in_text(self, search_text, original_line, line_num, regex_pattern):
        """Find all matches in text and return positions"""
        matches = []
        searching_full_line = (self.search_field == "all")
        
        if regex_pattern:
            # Regex search
            text_to_search = original_line if searching_full_line else search_text
            for match in regex_pattern.finditer(text_to_search):
                if searching_full_line:
                    start_col = match.start()
                    end_col = match.end()
                    matched_text = match.group(0)
                    matches.append((line_num, start_col, end_col, matched_text))
                else:
                    # Find position in original line
                    field_pos = original_line.find(search_text)
                    if field_pos >= 0:
                        start_col = field_pos + match.start()
                        end_col = field_pos + match.end()
                        matched_text = match.group(0)
                        matches.append((line_num, start_col, end_col, matched_text))
        elif self.search_options['whole_word']:
            # Whole word matching
            pattern = r'\b' + re.escape(self.search_term) + r'\b'
            flags = 0 if self.search_options['case_sensitive'] else re.IGNORECASE
            text_to_search = original_line if searching_full_line else search_text
            
            for match in re.finditer(pattern, text_to_search, flags):
                if searching_full_line:
                    start_col = match.start()
                    end_col = match.end()
                    matched_text = match.group(0)
                    matches.append((line_num, start_col, end_col, matched_text))
                else:
                    field_pos = original_line.find(search_text)
                    if field_pos >= 0:
                        start_col = field_pos + match.start()
                        end_col = field_pos + match.end()
                        matched_text = match.group(0)
                        matches.append((line_num, start_col, end_col, matched_text))
        else:
            # Simple substring search
            text_to_search = original_line if searching_full_line else search_text
            search_in = text_to_search if self.search_options['case_sensitive'] else text_to_search.lower()
            search_term = self.search_term if self.search_options['case_sensitive'] else self.search_term.lower()
            
            start_pos = 0
            while True:
                pos = search_in.find(search_term, start_pos)
                if pos == -1:
                    break
                
                if searching_full_line:
                    start_col = pos
                    end_col = pos + len(self.search_term)
                    matched_text = original_line[pos:end_col]
                    matches.append((line_num, start_col, end_col, matched_text))
                else:
                    field_pos = original_line.find(search_text)
                    if field_pos >= 0:
                        start_col = field_pos + pos
                        end_col = field_pos + pos + len(self.search_term)
                        matched_text = original_line[start_col:end_col]
                        matches.append((line_num, start_col, end_col, matched_text))
                
                start_pos = pos + 1
        
        return matches
    
    def highlight_current_match(self):
        """Highlight current match using Indicator 2"""
        if not self.search_results or self.current_search_index < 0:
            return
        
        # Clear search highlights
        self.editor.SetIndicatorCurrent(2)
        self.editor.IndicatorClearRange(0, self.editor.GetLength())
        
        # Highlight all matches in gray/yellow
        for i, (line_num, start_col, end_col, matched_text) in enumerate(self.search_results):
            pos = self.editor.PositionFromLine(line_num) + start_col
            length = end_col - start_col
            
            self.editor.SetIndicatorCurrent(2)
            self.editor.IndicatorFillRange(pos, length)
        
        # Scroll to current match
        current_match = self.search_results[self.current_search_index]
        line_num, start_col, end_col, matched_text = current_match
        pos = self.editor.PositionFromLine(line_num) + start_col
        
        self.editor.GotoPos(pos)
        self.editor.SetSelection(pos, pos + (end_col - start_col))
        
        # Update status bar
        self.update_status_bar()
    
    def find_next(self):
        """Find next search result"""
        if not self.search_active or not self.search_results:
            return
        
        self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
        self.highlight_current_match()
    
    def find_previous(self):
        """Find previous search result"""
        if not self.search_active or not self.search_results:
            return
        
        self.current_search_index = (self.current_search_index - 1) % len(self.search_results)
        self.highlight_current_match()
    
    def replace_current(self):
        """Replace current match using Scintilla's ReplaceTarget"""
        if not self.search_results or self.current_search_index < 0:
            return
        
        # Get current match
        line_num, start_col, end_col, matched_text = self.search_results[self.current_search_index]
        pos = self.editor.PositionFromLine(line_num) + start_col
        length = end_col - start_col
        
        # Use Scintilla's replace target
        self.editor.SetTargetStart(pos)
        self.editor.SetTargetEnd(pos + length)
        self.editor.ReplaceTarget(self.replace_term)
        
        # Calculate position shift
        position_shift = len(self.replace_term) - length
        
        # Update positions of remaining matches on same line
        if position_shift != 0:
            for i in range(self.current_search_index + 1, len(self.search_results)):
                match_line, match_start, match_end, match_text = self.search_results[i]
                if match_line == line_num:
                    self.search_results[i] = (match_line, match_start + position_shift,
                                             match_end + position_shift, match_text)
        
        # Remove current match
        del self.search_results[self.current_search_index]
        
        # Move to next or close if done
        if self.search_results:
            if self.current_search_index >= len(self.search_results):
                self.current_search_index = 0
            self.highlight_current_match()
        else:
            self.close_search()
    
    def replace_all(self):
        """Replace all matches"""
        if not self.search_term:
            return 0
        
        # Perform search first
        if not self.search_results:
            self.perform_search()
        
        if not self.search_results:
            return 0
        
        # Replace in reverse order to maintain positions
        count = 0
        for line_num, start_col, end_col, matched_text in reversed(self.search_results):
            pos = self.editor.PositionFromLine(line_num) + start_col
            length = end_col - start_col
            
            self.editor.SetTargetStart(pos)
            self.editor.SetTargetEnd(pos + length)
            self.editor.ReplaceTarget(self.replace_term)
            count += 1
        
        # Close search
        self.close_search()
        
        return count
    
    def clear_search_highlights(self):
        """Clear search highlights (Indicator 2)"""
        self.editor.SetIndicatorCurrent(2)
        self.editor.IndicatorClearRange(0, self.editor.GetLength())
    
    def close_search(self):
        """Close search mode"""
        self.search_active = False
        self.search_results = []
        self.current_search_index = -1
        self.clear_search_highlights()
        self.update_status_bar()
    
    def on_toggle_dark_mode(self, event):
        """Toggle dark mode"""
        self.dark_mode = self.dark_mode_cb.GetValue()
        self.apply_theme()
    
    def on_toggle_sig_coloring(self, event):
        """Toggle SIG type coloring"""
        sig_coloring_enabled = self.sig_coloring_cb.GetValue()
        
        if sig_coloring_enabled:
            # Apply SIG type coloring
            self.apply_sig_type_coloring()
        else:
            # Remove SIG type coloring - reset to default text color
            self.clear_sig_type_coloring()
    
    def _map_detailed_sig_type_to_color(self, detailed_sig_type):
        """Map detailed SIG type to one of the 4 color categories
        
        Maps the 10 detailed Suricata SIG types to 4 visual color categories:
        - Generic (IPONLY, LIKE_IPONLY, DEONLY): Basic rules, least specific
        - Specific Protocol (PKT, PKT_STREAM, STREAM, PDONLY): Flow/content rules
        - Specific Network/Port (APPLAYER): Application protocols
        - Specific Protocol + Specific Network/Port (APP_TX): App-layer transaction rules, most specific
        
        Args:
            detailed_sig_type: One of the 10 SIG_TYPE_* constants
            
        Returns:
            str: Color category name
        """
        # Map detailed types to color categories
        sig_type_mapping = {
            'SIG_TYPE_IPONLY': 'Generic',
            'SIG_TYPE_LIKE_IPONLY': 'Generic',
            'SIG_TYPE_DEONLY': 'Generic',
            'SIG_TYPE_PKT': 'Specific Protocol',
            'SIG_TYPE_PKT_STREAM': 'Specific Protocol',
            'SIG_TYPE_STREAM': 'Specific Protocol',
            'SIG_TYPE_PDONLY': 'Specific Protocol',
            'SIG_TYPE_APPLAYER': 'Specific Network/Port',
            'SIG_TYPE_APP_TX': 'Specific Protocol + Specific Network/Port',
            'SIG_TYPE_NOT_SET': 'Generic'
        }
        
        return sig_type_mapping.get(detailed_sig_type, 'Generic')
    
    def apply_sig_type_coloring(self):
        """Apply SIG type text coloring to all rule lines using indicators"""
        if not HAS_RULE_ANALYZER:
            return
        
        # Clear any existing SIG type coloring first (all 4 indicators)
        for indicator_id in [5, 6, 7, 8]:
            self.editor.SetIndicatorCurrent(indicator_id)
            self.editor.IndicatorClearRange(0, self.editor.GetLength())
        
        text = self.editor.GetText()
        lines = text.split('\n')
        
        # Map color categories to their indicator IDs
        category_to_indicator = {
            'Generic': 5,
            'Specific Protocol': 6,
            'Specific Network/Port': 7,
            'Specific Protocol + Specific Network/Port': 8
        }
        
        rule_analyzer = RuleAnalyzer()
        
        for line_num, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Skip blank lines and comments
            if not line_stripped or line_stripped.startswith('#'):
                continue
            
            # Try to parse and classify the rule
            try:
                rule = SuricataRule.from_string(line_stripped)
                if rule:
                    # Get detailed SIG type from RuleAnalyzer
                    detailed_sig_type = rule_analyzer.get_detailed_suricata_rule_type(rule)
                    
                    # Map detailed type to color category
                    color_category = self._map_detailed_sig_type_to_color(detailed_sig_type)
                    
                    # Get the appropriate indicator ID for this category
                    if color_category in category_to_indicator:
                        indicator_id = category_to_indicator[color_category]
                        
                        # Apply indicator to the entire line
                        line_start = self.editor.PositionFromLine(line_num)
                        line_end = self.editor.GetLineEndPosition(line_num)
                        line_length = line_end - line_start
                        
                        # Set current indicator and fill range
                        self.editor.SetIndicatorCurrent(indicator_id)
                        self.editor.IndicatorFillRange(line_start, line_length)
            except:
                pass  # If classification fails, leave default color
    
    def clear_sig_type_coloring(self):
        """Clear SIG type coloring and restore default text color"""
        # Clear all 4 SIG type indicators from entire document
        for indicator_id in [5, 6, 7, 8]:
            self.editor.SetIndicatorCurrent(indicator_id)
            self.editor.IndicatorClearRange(0, self.editor.GetLength())
    
    def apply_theme(self):
        """Apply color theme"""
        if self.dark_mode:
            # VS Code dark theme colors
            bg = wx.Colour(30, 30, 30)
            fg = wx.Colour(212, 212, 212)
            
            # Editor colors
            self.editor.StyleSetBackground(stc.STC_STYLE_DEFAULT, bg)
            self.editor.StyleSetForeground(stc.STC_STYLE_DEFAULT, fg)
            self.editor.StyleClearAll()  # Apply to all styles
            
            # Selection
            self.editor.SetSelBackground(True, wx.Colour(38, 79, 120))
            
            # Caret
            self.editor.SetCaretForeground(wx.Colour(174, 175, 173))
            self.editor.SetCaretLineBackground(wx.Colour(44, 44, 44))
            
            # Line numbers
            self.editor.StyleSetBackground(stc.STC_STYLE_LINENUMBER, wx.Colour(37, 37, 38))
            self.editor.StyleSetForeground(stc.STC_STYLE_LINENUMBER, wx.Colour(133, 133, 133))
            
            # Fold margin
            self.editor.SetFoldMarginColour(True, wx.Colour(37, 37, 38))
            self.editor.SetFoldMarginHiColour(True, wx.Colour(37, 37, 38))
        else:
            # Light theme (default)
            bg = wx.WHITE
            fg = wx.BLACK
            
            self.editor.StyleSetBackground(stc.STC_STYLE_DEFAULT, bg)
            self.editor.StyleSetForeground(stc.STC_STYLE_DEFAULT, fg)
            self.editor.StyleClearAll()
            
            # Selection
            self.editor.SetSelBackground(True, wx.Colour(0, 120, 215))
            
            # Caret
            self.editor.SetCaretForeground(wx.BLACK)
            self.editor.SetCaretLineBackground(wx.Colour(232, 232, 255))
            
            # Line numbers
            self.editor.StyleSetBackground(stc.STC_STYLE_LINENUMBER, wx.Colour(240, 240, 240))
            self.editor.StyleSetForeground(stc.STC_STYLE_LINENUMBER, wx.BLACK)
            
            # Fold margin
            self.editor.SetFoldMarginColour(True, wx.Colour(240, 240, 240))
            self.editor.SetFoldMarginHiColour(True, wx.WHITE)
    
    def on_ok(self, event):
        """Handle OK button"""
        # Validate and parse rules
        parsed_rules, errors, warnings, undefined_vars = self.validate_and_parse_rules()
        
        # Show validation results if there are issues
        if errors or warnings:
            report = "Validation Results:\n\n"
            
            if errors:
                report += "ERRORS (rules commented out):\n"
                for line_num, error_msg in errors[:10]:  # Show first 10
                    report += f"- Line {line_num}: {error_msg}\n"
                if len(errors) > 10:
                    report += f"... and {len(errors) - 10} more errors\n"
                report += "\n"
            
            if warnings:
                report += "WARNINGS (rules preserved):\n"
                for line_num, warning_msg in warnings[:10]:
                    report += f"- Line {line_num}: {warning_msg}\n"
                if len(warnings) > 10:
                    report += f"... and {len(warnings) - 10} more warnings\n"
                report += "\n"
            
            if undefined_vars:
                report += f"Undefined variables will be auto-created:\n"
                for var in sorted(list(undefined_vars)[:5]):
                    report += f"- {var}\n"
                if len(undefined_vars) > 5:
                    report += f"... and {len(undefined_vars) - 5} more\n"
                report += "\n"
            
            report += "Continue with these changes?"
            
            dlg = wx.MessageDialog(self, report, "Validation Results",
                                  wx.YES_NO | wx.ICON_QUESTION)
            if dlg.ShowModal() != wx.ID_YES:
                dlg.Destroy()
                return
            dlg.Destroy()
        
        # Auto-create undefined variables
        for var in undefined_vars:
            if var not in self.variables:
                self.variables[var] = ""
        
        # Get result data with validated rules
        result_data = {
            'ok': True,
            'rules': [self._rule_dict_from_suricata_rule(r) for r in parsed_rules],
            'variables': self.variables
        }
        
        # Write to output file
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=2)
            
            self.EndModal(wx.ID_OK)
        except Exception as e:
            wx.MessageBox(f"Error saving result: {e}", "Error", wx.OK | wx.ICON_ERROR)
    
    def on_cancel(self, event):
        """Handle Cancel button"""
        if self.modified:
            dlg = wx.MessageDialog(
                self,
                "You have unsaved changes. Discard them?",
                "Unsaved Changes",
                wx.YES_NO | wx.ICON_WARNING
            )
            if dlg.ShowModal() != wx.ID_YES:
                dlg.Destroy()
                return
            dlg.Destroy()
        
        self.EndModal(wx.ID_CANCEL)
    
    def validate_and_parse_rules(self):
        """Validate rules and parse text back to rule objects (mimics tkinter version)
        
        Returns:
            tuple: (rules_list, errors_list, warnings_list, undefined_vars)
        """
        text = self.editor.GetText()
        lines = text.split('\n')
        
        # Parse rules from editor
        edited_rules = []
        errors = []
        warnings = []
        undefined_vars = set()
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Blank line
            if not line_stripped:
                blank_rule = SuricataRule()
                blank_rule.is_blank = True
                edited_rules.append(blank_rule)
                continue
            
            # Comment line
            if line_stripped.startswith('#'):
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = line.rstrip()
                edited_rules.append(comment_rule)
                continue
            
            # Check for validation errors using validate_line (catches semicolon issues, etc.)
            line_errors, line_warnings = self.validate_line(line, i - 1)
            
            # Add any validation errors found
            for start_col, end_col, msg in line_errors:
                errors.append((i, msg))
            
            # Add any validation warnings found
            for start_col, end_col, msg in line_warnings:
                warnings.append((i, msg))
            
            # Try to parse as rule
            try:
                rule = SuricataRule.from_string(line)
                if rule:
                    # Basic validation
                    error_found = len(line_errors) > 0  # If validate_line found errors, mark as error
                    
                    # Validate action
                    if rule.action.lower() not in ['pass', 'alert', 'drop', 'reject']:
                        if not any('Invalid action' in msg for _, msg in errors if _ == i):
                            errors.append((i, f"Invalid action: {rule.action}"))
                            error_found = True
                    
                    # Validate protocol
                    if rule.protocol.lower() not in [p.lower() for p in SuricataConstants.SUPPORTED_PROTOCOLS]:
                        if not any('Invalid protocol' in msg for _, msg in errors if _ == i):
                            errors.append((i, f"Invalid protocol: {rule.protocol}"))
                            error_found = True
                    
                    # Check for undefined variables
                    for field in [rule.src_net, rule.dst_net, rule.src_port, rule.dst_port]:
                        if field.startswith(('$', '@')) and field not in self.variables:
                            undefined_vars.add(field)
                            if not any(field in msg for _, msg in warnings if _ == i):
                                warnings.append((i, f"Undefined variable: {field}"))
                    
                    if error_found:
                        # Comment out the rule
                        comment_rule = SuricataRule()
                        comment_rule.is_comment = True
                        comment_rule.comment_text = f"# [SYNTAX ERROR] {line}"
                        edited_rules.append(comment_rule)
                    else:
                        edited_rules.append(rule)
                else:
                    errors.append((i, "Failed to parse rule"))
                    comment_rule = SuricataRule()
                    comment_rule.is_comment = True
                    comment_rule.comment_text = f"# [SYNTAX ERROR] {line}"
                    edited_rules.append(comment_rule)
            except Exception as e:
                errors.append((i, f"Parse error: {str(e)}"))
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = f"# [SYNTAX ERROR] {line}"
                edited_rules.append(comment_rule)
        
        return edited_rules, errors, warnings, undefined_vars
    
    def _rule_dict_from_suricata_rule(self, rule):
        """Convert SuricataRule object to dict for JSON serialization"""
        return {
            'is_blank': getattr(rule, 'is_blank', False),
            'is_comment': getattr(rule, 'is_comment', False),
            'comment_text': getattr(rule, 'comment_text', ''),
            'action': getattr(rule, 'action', ''),
            'protocol': getattr(rule, 'protocol', ''),
            'src_net': getattr(rule, 'src_net', ''),
            'src_port': getattr(rule, 'src_port', ''),
            'direction': getattr(rule, 'direction', ''),
            'dst_net': getattr(rule, 'dst_net', ''),
            'dst_port': getattr(rule, 'dst_port', ''),
            'message': getattr(rule, 'message', ''),
            'content': getattr(rule, 'content', ''),
            'sid': getattr(rule, 'sid', 0),
            'rev': getattr(rule, 'rev', 1),
            'original_options': getattr(rule, 'original_options', '')
        }


# Entry point
if __name__ == '__main__':
    main()
