"""
Revision Manager Module for Suricata Rule Generator

Handles per-rule revision history and rollback operations.
Integrates with existing change tracking system (.history files).
Uses GUID-based tracking for robust rule identity across SID changes.
"""

import os
import json
import datetime
import uuid
from typing import List, Optional, Dict, Tuple
from suricata_rule import SuricataRule


class RevisionManager:
    """Manages per-rule revision history with optimized inline storage"""
    
    def __init__(self, history_file: str):
        """Initialize RevisionManager
        
        Args:
            history_file: Path to .history file
        """
        self.history_file = history_file
        self.changes = []
        self.format_version = "1.0"
        self.sid_index = {}  # Performance optimization: {sid: [change_indices]}
        self.tracking_enabled = None
        self.file = None
        self.load_history()
    
    def load_history(self):
        """Load change history from .history file with format detection"""
        if not os.path.exists(self.history_file):
            return
        
        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check format version
            self.format_version = data.get('format_version', '1.0')
            self.changes = data.get('changes', [])
            self.tracking_enabled = data.get('tracking_enabled')
            self.file = data.get('file')
            
            # Build SID index for performance optimization
            self._build_sid_index()
            
        except (json.JSONDecodeError, IOError, KeyError):
            # Corrupted or unreadable - gracefully degrade
            self.changes = []
            self.format_version = "1.0"
    
    def _build_sid_index(self):
        """Build index mapping SID to change indices for O(1) lookups"""
        self.sid_index = {}
        for i, change in enumerate(self.changes):
            sid = change.get('details', {}).get('sid')
            if sid:
                sid_key = str(sid)
                if sid_key not in self.sid_index:
                    self.sid_index[sid_key] = []
                self.sid_index[sid_key].append(i)
    
    def generate_rule_guid(self) -> str:
        """Generate unique identifier for a rule"""
        return str(uuid.uuid4())
    
    def save_change_with_snapshot(self, rule: SuricataRule, action: str, 
                                  details: dict, generator_version: str,
                                  timestamp: str = None, defer_write: bool = True,
                                  rule_guid: str = None) -> dict:
        """Create a change entry with embedded rule snapshot
        
        Args:
            rule: The SuricataRule in its NEW state (after modification)
            action: The action type (e.g., 'rule_modified', 'rule_added')
            details: Change details dict (already contains sid, changes, etc.)
            generator_version: Version of the generator
            timestamp: Optional timestamp (defaults to now)
            defer_write: If True, return entry without writing to disk (default)
            rule_guid: Optional GUID for the rule (generated if not provided)
            
        Returns:
            dict: The change entry with embedded snapshot
        """
        if not timestamp:
            timestamp = datetime.datetime.now().isoformat()
        
        # Generate GUID if not provided
        if not rule_guid:
            rule_guid = self.generate_rule_guid()
        
        # Create snapshot of rule's current state with GUID
        rule_snapshot = {
            'rule_guid': rule_guid,
            'sid': rule.sid,
            'action': rule.action,
            'protocol': rule.protocol,
            'src_net': rule.src_net,
            'src_port': rule.src_port,
            'direction': rule.direction,
            'dst_net': rule.dst_net,
            'dst_port': rule.dst_port,
            'message': rule.message,
            'content': rule.content,
            'rev': rule.rev,
            'original_options': rule.original_options
        }
        
        # Add GUID and snapshot to details
        details['rule_guid'] = rule_guid
        details['rule_snapshot'] = rule_snapshot
        
        # Create change entry
        change_entry = {
            'timestamp': timestamp,
            'version': generator_version,
            'action': action,
            'details': details
        }
        
        # Return entry for deferred writing (default behavior)
        return change_entry
    
    def write_pending_snapshots(self, pending_entries: List[dict]) -> bool:
        """Write pending snapshot entries to history file
        
        Called during file save to commit all pending snapshots at once.
        
        Args:
            pending_entries: List of change entries with snapshots
            
        Returns:
            bool: True if saved successfully
        """
        if not pending_entries:
            return True
        
        # Load existing history data
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
            else:
                history_data = {
                    'format_version': '2.0',
                    'file': os.path.basename(self.history_file.replace('.history', '.suricata')),
                    'tracking_enabled': datetime.datetime.now().isoformat(),
                    'changes': []
                }
        except (json.JSONDecodeError, IOError):
            # If corrupt, start fresh
            history_data = {
                'format_version': '2.0',
                'file': os.path.basename(self.history_file.replace('.history', '.suricata')),
                'tracking_enabled': datetime.datetime.now().isoformat(),
                'changes': []
            }
        
        # Append all pending entries
        if 'changes' not in history_data:
            history_data['changes'] = []
        history_data['changes'].extend(pending_entries)
        
        # Set format version ONLY if not already set (don't force upgrade)
        if 'format_version' not in history_data:
            history_data['format_version'] = '2.0'
        
        # Save to file
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, indent=2, ensure_ascii=False)
            
            # Update in-memory state
            self.changes = history_data['changes']
            self.format_version = '2.0'
            self._build_sid_index()
            
            return True
            
        except IOError as e:
            # Log error but don't crash
            print(f"Warning: Failed to save revision history: {e}")
            return False
    
    def get_revisions(self, sid: int = None, rule_guid: str = None) -> List[dict]:
        """Get all revisions for a rule by GUID (preferred) or SID (fallback)
        
        Uses GUID for primary lookup, falls back to SID for backward compatibility.
        
        Args:
            sid: Rule SID (for backward compatibility)
            rule_guid: Rule GUID (preferred method)
        
        Returns:
            List of revision objects, sorted by rev number (ascending)
        """
        revisions = []
        
        # Primary method: lookup by GUID
        if rule_guid:
            for change in self.changes:
                details = change.get('details', {})
                snapshot = details.get('rule_snapshot', {})
                
                # Check both details and snapshot for GUID (flexible matching)
                change_guid = details.get('rule_guid') or snapshot.get('rule_guid')
                
                if change_guid == rule_guid and 'rule_snapshot' in details:
                    snapshot_copy = snapshot.copy()
                    snapshot_copy['timestamp'] = change['timestamp']
                    revisions.append(snapshot_copy)
        
        # Fallback method: lookup by SID (for backward compatibility)
        elif sid is not None:
            sid_key = str(sid)
            
            # Use index if available (performance optimization)
            if self.sid_index and sid_key in self.sid_index:
                change_indices = self.sid_index[sid_key]
                for idx in change_indices:
                    if idx < len(self.changes):
                        change = self.changes[idx]
                        details = change.get('details', {})
                        if 'rule_snapshot' in details:
                            snapshot = details['rule_snapshot'].copy()
                            snapshot['timestamp'] = change['timestamp']
                            revisions.append(snapshot)
            else:
                # Fallback to linear scan if no index
                for change in self.changes:
                    details = change.get('details', {})
                    if details.get('sid') == sid and 'rule_snapshot' in details:
                        snapshot = details['rule_snapshot'].copy()
                        snapshot['timestamp'] = change['timestamp']
                        revisions.append(snapshot)
        
        # Sort by rev number
        revisions.sort(key=lambda r: r.get('rev', 0))
        
        return revisions
    
    def get_revision(self, sid: int = None, rev: int = None, rule_guid: str = None) -> Optional[dict]:
        """Get a specific revision for a rule by GUID (preferred) or SID (fallback)
        
        Args:
            sid: Rule SID (for backward compatibility)
            rev: Revision number
            rule_guid: Rule GUID (preferred method)
        
        Returns:
            Revision object or None if not found
        """
        revisions = self.get_revisions(sid=sid, rule_guid=rule_guid)
        for revision in revisions:
            if revision.get('rev') == rev:
                return revision
        return None
    
    def restore_revision(self, sid: int = None, rev: int = None, rule_guid: str = None) -> Optional[SuricataRule]:
        """Restore a rule to a specific revision by GUID (preferred) or SID (fallback)
        
        Args:
            sid: Rule SID (for backward compatibility)
            rev: Revision number
            rule_guid: Rule GUID (preferred method)
        
        Returns:
            SuricataRule object with historical state or None if not found
        """
        revision = self.get_revision(sid=sid, rev=rev, rule_guid=rule_guid)
        if not revision:
            return None
        
        try:
            # Create SuricataRule from historical snapshot
            # CRITICAL: Get SID from snapshot, not from parameter (which may be None when using GUID lookup)
            snapshot_sid = revision.get('sid', sid)
            if snapshot_sid is None:
                # Last resort: try to extract from original_options
                import re
                options = revision.get('original_options', '')
                sid_match = re.search(r'sid:(\d+)', options)
                if sid_match:
                    snapshot_sid = int(sid_match.group(1))
                else:
                    return None  # Can't determine SID
            
            rule = SuricataRule(
                action=revision['action'],
                protocol=revision['protocol'],
                src_net=revision['src_net'],
                src_port=revision['src_port'],
                dst_net=revision['dst_net'],
                dst_port=revision['dst_port'],
                message=revision['message'],
                content=revision['content'],
                sid=snapshot_sid,
                direction=revision.get('direction', '->'),
                rev=revision['rev'],
                original_options=revision.get('original_options', '')
            )
            
            return rule
            
        except (KeyError, TypeError, ValueError):
            # Corrupted snapshot data
            return None
    
    def detect_format_and_upgrade_needed(self) -> Tuple[bool, str]:
        """Detect .history format version and check if upgrade needed
        
        Returns:
            Tuple of (needs_upgrade, current_version)
        """
        # Already version 2.0
        if self.format_version == '2.0':
            return False, '2.0'
        
        # Version 1.0 (legacy): No format_version key or explicitly 1.0
        # Check if any changes have rule_snapshot (partially upgraded)
        has_snapshots = any('rule_snapshot' in c.get('details', {}) 
                           for c in self.changes)
        
        if has_snapshots:
            return False, '2.0'  # Already upgraded
        else:
            return True, '1.0'  # Needs upgrade
    
    def upgrade_history_format(self, current_rules: List[SuricataRule],
                               generator_version: str,
                               progress_callback=None) -> bool:
        """Upgrade legacy .history format to version 2.0
        
        Creates baseline snapshots for all current rules.
        
        Args:
            current_rules: Current rules in the file
            generator_version: Version of the generator
            progress_callback: Optional callback(current, total) for progress updates
            
        Returns:
            bool: True if upgraded successfully
        """
        try:
            # Load existing history data
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
            else:
                history_data = {
                    'file': os.path.basename(self.history_file.replace('.history', '.suricata')),
                    'tracking_enabled': datetime.datetime.now().isoformat(),
                    'changes': []
                }
            
            # Mark as version 2.0
            history_data['format_version'] = '2.0'
            
            # Create baseline snapshots for all current rules
            timestamp = datetime.datetime.now().isoformat()
            
            # Filter actual rules (non-comment, non-blank)
            actual_rules = [r for r in current_rules 
                           if not getattr(r, 'is_comment', False) 
                           and not getattr(r, 'is_blank', False)]
            
            total_rules = len(actual_rules)
            
            for i, rule in enumerate(actual_rules):
                # Update progress if callback provided
                if progress_callback:
                    progress_callback(i + 1, total_rules)
                
                # Generate GUID for this rule's baseline snapshot
                rule_guid = self.generate_rule_guid()
                
                # Create baseline snapshot entry with GUID
                baseline_entry = {
                    'timestamp': timestamp,
                    'version': generator_version,
                    'action': 'baseline_snapshot',
                    'details': {
                        'sid': rule.sid,
                        'message': rule.message,
                        'rule_guid': rule_guid,
                        'rule_snapshot': {
                            'rule_guid': rule_guid,
                            'sid': rule.sid,
                            'action': rule.action,
                            'protocol': rule.protocol,
                            'src_net': rule.src_net,
                            'src_port': rule.src_port,
                            'direction': rule.direction,
                            'dst_net': rule.dst_net,
                            'dst_port': rule.dst_port,
                            'message': rule.message,
                            'content': rule.content,
                            'rev': rule.rev,
                            'original_options': rule.original_options
                        }
                    }
                }
                
                if 'changes' not in history_data:
                    history_data['changes'] = []
                history_data['changes'].append(baseline_entry)
            
            # Save upgraded format
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, indent=2, ensure_ascii=False)
            
            # Update in-memory state
            self.changes = history_data['changes']
            self.format_version = '2.0'
            self._build_sid_index()
            
            return True
            
        except (IOError, OSError, json.JSONDecodeError) as e:
            print(f"Error upgrading history format: {e}")
            return False
    
    def extract_rule_guids(self) -> dict:
        """Extract GUIDs from all snapshots and map to current SIDs
        
        Returns:
            dict: {sid: guid} mapping for active rules
        """
        sid_guid_map = {}
        
        # Track the most recent GUID for each SID
        for change in self.changes:
            details = change.get('details', {})
            snapshot = details.get('rule_snapshot', {})
            
            # Get GUID from details or snapshot
            rule_guid = details.get('rule_guid') or snapshot.get('rule_guid')
            sid = details.get('sid') or snapshot.get('sid')
            
            if rule_guid and sid:
                # Use most recent GUID for each SID
                sid_guid_map[sid] = rule_guid
        
        return sid_guid_map
    
    def get_history_summary(self) -> Dict:
        """Get summary statistics about revision history
        
        Returns:
            Dict with statistics
        """
        total_changes = len(self.changes)
        rules_with_history = len(self.sid_index)
        
        # Count snapshots
        snapshot_count = sum(1 for c in self.changes 
                           if 'rule_snapshot' in c.get('details', {}))
        
        # Get file size if exists
        file_size_mb = 0
        if os.path.exists(self.history_file):
            file_size_mb = os.path.getsize(self.history_file) / (1024 * 1024)
        
        return {
            'format_version': self.format_version,
            'total_changes': total_changes,
            'rules_with_history': rules_with_history,
            'snapshot_count': snapshot_count,
            'file_size_mb': round(file_size_mb, 2)
        }
