"""
Suricata Rule Data Model

This module contains the core SuricataRule class for representing and manipulating
individual Suricata rules with parsing, validation, and formatting capabilities.
"""

import re
from typing import Optional
from constants import SuricataConstants, ValidationMessages


class SuricataRule:
    """Represents a single Suricata rule with all its components"""
    
    def __init__(self, action="pass", protocol="tcp", src_net="$HOME_NET", src_port="any", 
                 dst_net="$EXTERNAL_NET", dst_port="any", message="", content="", sid=1, 
                 direction="->", original_options="", rev=1):
        # Core rule components
        self.action = action
        self.protocol = protocol
        self.src_net = src_net
        self.src_port = src_port
        self.dst_net = dst_net
        self.dst_port = dst_port
        self.message = message
        self.content = content
        self.sid = sid
        self.rev = rev
        self.direction = direction
        # Preserve original rule syntax to maintain exact formatting
        self.original_options = original_options
        # Special rule types
        self.is_comment = False
        self.comment_text = ""
        self.is_blank = False
    
    def to_string(self) -> str:
        """Convert rule to Suricata format string"""
        # Handle special rule types first
        if self.is_blank:
            return ""
        
        if self.is_comment:
            return self.comment_text
        
        # Build normal Suricata rule string
        rule_parts = [
            self.action,
            self.protocol,
            self.src_net,
            self.src_port,
            self.direction,
            self.dst_net,
            self.dst_port
        ]
        
        options = []
        if self.content:
            # Strip trailing semicolon from content to prevent double semicolons
            content_cleaned = self.content.rstrip(';')
            options.append(content_cleaned)
        if self.message:
            # Use proper double quotes as required by Suricata
            options.append(f'msg:"{self.message}"')
        options.append(f"sid:{self.sid}")
        options.append(f"rev:{self.rev}")
        
        rule_str = " ".join(rule_parts)
        if options:
            rule_str += f" ({'; '.join(options)};)"
        
        return rule_str
    
    @classmethod
    def from_string(cls, rule_str: str) -> Optional['SuricataRule']:
        """Parse Suricata rule string into SuricataRule object with support for bracketed CIDR ranges"""
        rule_str = rule_str.strip()
        # Skip empty lines and comments
        if not rule_str or rule_str.startswith('#'):
            return None
        
        # Enhanced parsing to handle bracketed network specifications
        # First, extract the options part if it exists
        options_match = re.search(r'\(([^)]*)\)$', rule_str)
        options_str = options_match.group(1) if options_match else ""
        
        # Remove options part from rule string for field parsing
        if options_match:
            rule_without_options = rule_str[:options_match.start()].strip()
        else:
            rule_without_options = rule_str
        
        # Split into tokens, handling bracketed expressions as single tokens
        tokens = []
        current_token = ""
        bracket_depth = 0
        
        for char in rule_without_options:
            if char == '[':
                bracket_depth += 1
                current_token += char
            elif char == ']':
                bracket_depth -= 1
                current_token += char
            elif char.isspace() and bracket_depth == 0:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char
        
        # Don't forget the last token
        if current_token:
            tokens.append(current_token)
        
        # We should have exactly 7 tokens: action protocol src_net src_port direction dst_net dst_port
        if len(tokens) != 7:
            return None
        
        action, protocol, src_net, src_port, direction, dst_net, dst_port = tokens
        
        # Validate direction token
        if direction not in ['->', '<>']:
            return None
        
        # Initialize default values
        message = ""
        content = ""
        sid = SuricataConstants.SID_MIN
        rev = 1
        original_options = options_str or ""
        
        if options_str:
            # Extract message from msg:"text" format
            msg_match = re.search(r'msg:"([^"]*)"', options_str)
            if msg_match:
                message = msg_match.group(1)
            
            # Extract SID number
            sid_match = re.search(r'sid:(\d+)', options_str)
            if sid_match:
                try:
                    sid = int(sid_match.group(1))
                    if not (SuricataConstants.SID_MIN <= sid <= SuricataConstants.SID_MAX):
                        sid = SuricataConstants.SID_MIN  # Use default if out of range
                except (ValueError, OverflowError):
                    sid = SuricataConstants.SID_MIN  # Use default if parsing fails
            
            # Extract REV number
            rev_match = re.search(r'rev:(\d+)', options_str)
            if rev_match:
                try:
                    rev = int(rev_match.group(1))
                    if rev < 1:
                        rev = 1  # Use default if invalid
                except (ValueError, OverflowError):
                    rev = 1  # Use default if parsing fails
            
            # Extract all other content (keywords, flow, etc.) excluding msg, sid, and rev
            content_parts = []
            parts = options_str.split(';')
            for part in parts:
                part = part.strip()
                if (part and 
                    not part.startswith('msg:') and 
                    not part.startswith('sid:') and 
                    not part.startswith('rev:') and 
                    part != ''):
                    content_parts.append(part)
            content = '; '.join(content_parts)
        
        return cls(action, protocol, src_net, src_port, dst_net, dst_port, message, content, sid, direction, original_options, rev)
