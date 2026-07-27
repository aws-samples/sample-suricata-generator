"""
Local File Loader

This module provides functionality for loading and parsing local .suricata files,
reading companion .history files for rule age computation, and deduplicating SIDs
across multiple sources with defined precedence rules.
"""

import json
import os
import datetime
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from src.core.suricata_rule import SuricataRule


# Source type constants for SID attribution
SOURCE_CURRENT_FILE = "current_file"
SOURCE_LOCAL_FILE_PREFIX = "local:"  # e.g., "local:extra.suricata"
SOURCE_MANAGED_PREFIX = "managed:"   # e.g., "managed:ThreatSignaturesPhishing"


@dataclass
class LocalFileMetadata:
    """Metadata for a single additional local .suricata file"""
    path: str               # Absolute path to the file
    filename: str           # os.path.basename(path)
    rule_count: int         # Number of valid Suricata rules
    sids: List[int]         # All SIDs extracted from the file
    unlogged_sids: List[int] = field(default_factory=list)  # SIDs classified as unlogged
    history_available: bool = False  # Whether .history companion exists
    exists_on_disk: bool = True     # For deserialized results, whether file still exists


@dataclass
class LoadedFile:
    """Result of loading and parsing a single .suricata file"""
    path: str                          # Absolute file path
    filename: str                      # Base filename only
    rules: List[SuricataRule] = field(default_factory=list)  # Fully parsed rules
    sids: List[int] = field(default_factory=list)            # All SIDs in file
    unlogged_sids: Set[int] = field(default_factory=set)     # SIDs classified as unlogged
    rule_count: int = 0                # Total valid rules
    history_available: bool = False    # Whether companion .history exists
    error: Optional[str] = None        # Error message if file failed to load


class LocalFileLoader:
    """Loads and parses local .suricata files for rule usage analysis"""

    def load_files(
        self,
        file_paths: List[str],
        progress_callback: Optional[Callable] = None
    ) -> List[LoadedFile]:
        """Load and parse multiple .suricata files with progress feedback.

        Args:
            file_paths: List of absolute paths to .suricata files
            progress_callback: Optional callback(current_index, total, filename) for progress

        Returns:
            List of LoadedFile objects, one per input path
        """
        results = []
        total = len(file_paths)

        for idx, file_path in enumerate(file_paths):
            filename = os.path.basename(file_path)

            if progress_callback:
                progress_callback(idx + 1, total, filename)

            loaded_file = self._load_single_file(file_path)
            results.append(loaded_file)

        return results

    def _load_single_file(self, file_path: str) -> LoadedFile:
        """Parse a single .suricata file and return a LoadedFile result.

        Handles error cases:
        - File not found
        - Permission denied
        - Encoding errors (tries utf-8, then system default)
        - Empty files
        - Files with no valid rules
        """
        filename = os.path.basename(file_path)
        loaded = LoadedFile(path=file_path, filename=filename)

        # Check file existence
        if not os.path.exists(file_path):
            loaded.error = f"File not found: {file_path}"
            return loaded

        # Check companion .history file
        history_path = self._get_history_path(file_path)
        loaded.history_available = os.path.exists(history_path)

        # Read file content
        content = self._read_file_content(file_path)
        if content is None:
            loaded.error = f"Cannot read file: {file_path}"
            return loaded

        # Parse rules from content
        lines = content.splitlines()
        if not lines:
            # Empty file - not an error, just 0 rules
            return loaded

        rules = []
        sids = []
        unlogged_sids = set()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            rule = SuricataRule.from_string(line)
            if rule is not None:
                rules.append(rule)
                sids.append(rule.sid)
                if self._is_unlogged_rule(rule):
                    unlogged_sids.add(rule.sid)

        loaded.rules = rules
        loaded.sids = sids
        loaded.unlogged_sids = unlogged_sids
        loaded.rule_count = len(rules)

        if not rules and lines:
            # File had content but no valid rules
            loaded.error = f"No valid Suricata rules found in: {filename}"

        return loaded

    def get_rule_history_dates(
        self,
        history_path: str,
        sid: int
    ) -> Tuple[Optional[int], Optional[datetime.date]]:
        """Read rule creation age AND last modified date from companion .history file.

        Returns both:
        - creation_days: days since Rev 1 (same as get_rule_age_from_history)
        - last_modified_date: datetime.date of the highest revision number

        Args:
            history_path: Path to the .history file
            sid: The SID to look up

        Returns:
            Tuple of (creation_days, last_modified_date), either may be None
        """
        if not os.path.exists(history_path):
            return (None, None)

        try:
            with open(history_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError, OSError):
            return (None, None)

        changes = data.get('changes', [])
        if not changes:
            return (None, None)

        # Collect all revisions for this SID
        sid_entries = []
        for change in changes:
            details = change.get('details', {})
            change_sid = details.get('sid')
            if change_sid == sid:
                snapshot = details.get('rule_snapshot', {})
                timestamp = change.get('timestamp')
                rev = snapshot.get('rev', details.get('rev'))
                if timestamp:
                    sid_entries.append({
                        'timestamp': timestamp,
                        'rev': rev
                    })

        if not sid_entries:
            return (None, None)

        # Find Rev 1 timestamp for creation_days
        rev1_timestamp = None
        for entry in sid_entries:
            if entry.get('rev') == 1:
                rev1_timestamp = entry['timestamp']
                break
        if rev1_timestamp is None:
            # Fallback: earliest timestamp
            sid_entries_sorted = sorted(sid_entries, key=lambda e: e.get('timestamp', ''))
            rev1_timestamp = sid_entries_sorted[0]['timestamp']

        # Find highest revision timestamp for last_modified_date
        highest_rev_entry = max(sid_entries, key=lambda e: e.get('rev') or 0)
        highest_rev_timestamp = highest_rev_entry['timestamp']

        # Compute creation_days
        creation_days = None
        try:
            rev1_date = self._parse_timestamp_to_date(rev1_timestamp)
            if rev1_date is not None:
                today = datetime.date.today()
                creation_days = (today - rev1_date).days
        except (ValueError, TypeError, OverflowError):
            pass

        # Compute last_modified_date
        last_modified_date = None
        try:
            last_modified_date = self._parse_timestamp_to_date(highest_rev_timestamp)
        except (ValueError, TypeError, OverflowError):
            pass

        return (creation_days, last_modified_date)

    def get_rule_age_from_history(
        self,
        history_path: str,
        sid: int
    ) -> Optional[int]:
        """Read rule age (days) from companion .history file for a given SID.

        The rule age is computed as the number of calendar days between the
        Rev 1 timestamp and the current date.

        Args:
            history_path: Path to the .history file
            sid: The SID to look up

        Returns:
            Number of days since Rev 1, or None if not available
        """
        if not os.path.exists(history_path):
            return None

        try:
            with open(history_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError, OSError):
            return None

        changes = data.get('changes', [])
        if not changes:
            return None

        # Find the earliest revision (Rev 1) for this SID
        rev1_timestamp = self._find_rev1_timestamp(changes, sid)
        if rev1_timestamp is None:
            return None

        # Compute calendar days between Rev 1 date and current date
        try:
            rev1_date = self._parse_timestamp_to_date(rev1_timestamp)
            if rev1_date is None:
                return None
            today = datetime.date.today()
            delta = today - rev1_date
            return delta.days
        except (ValueError, TypeError, OverflowError):
            return None

    def deduplicate_sids(
        self,
        current_file_sids: Set[int],
        local_files: List[LoadedFile],
        managed_sids: Set[int]
    ) -> Tuple[Dict[int, str], Set[int]]:
        """Deduplicate SIDs across sources, returning attribution map and unique set.

        Precedence: current_file > local files (in selection order) > managed groups.

        Args:
            current_file_sids: SIDs from the currently open file
            local_files: List of LoadedFile objects (order matters for precedence)
            managed_sids: SIDs from managed rule groups

        Returns:
            Tuple of (sid_to_source map, unique_sid_set)
            sid_to_source maps each SID to its authoritative source label.
        """
        sid_to_source: Dict[int, str] = {}
        unique_sids: Set[int] = set()

        # 1. Current file takes highest precedence
        for sid in current_file_sids:
            if sid not in sid_to_source:
                sid_to_source[sid] = SOURCE_CURRENT_FILE
                unique_sids.add(sid)

        # 2. Local files in selection order (earlier files take precedence)
        for loaded_file in local_files:
            source_label = f"{SOURCE_LOCAL_FILE_PREFIX}{loaded_file.filename}"
            for sid in loaded_file.sids:
                if sid not in sid_to_source:
                    sid_to_source[sid] = source_label
                    unique_sids.add(sid)

        # 3. Managed groups have lowest precedence
        for sid in managed_sids:
            if sid not in sid_to_source:
                sid_to_source[sid] = f"{SOURCE_MANAGED_PREFIX}"
                unique_sids.add(sid)

        return sid_to_source, unique_sids

    # --- Private helper methods ---

    def _get_history_path(self, suricata_path: str) -> str:
        """Derive the companion .history file path from a .suricata file path."""
        history_path = suricata_path.replace('.suricata', '.history')
        if not history_path.endswith('.history'):
            history_path += '.history'
        return history_path

    def _read_file_content(self, file_path: str) -> Optional[str]:
        """Read file content, trying utf-8 first, then system default encoding.

        Returns None if the file cannot be read.
        """
        # Try UTF-8 first
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            pass
        except PermissionError:
            return None
        except OSError:
            return None

        # Fallback to system default encoding
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except (UnicodeDecodeError, PermissionError, OSError):
            return None

    def _is_unlogged_rule(self, rule: SuricataRule) -> bool:
        """Determine if a rule doesn't write to CloudWatch Logs.

        Uses the same logic as RuleUsageAnalyzer.is_unlogged_rule():
        - Pass rules WITHOUT the 'alert' keyword -> unlogged
        - Drop/reject rules WITH the 'noalert' keyword -> unlogged
        """
        import re

        # Skip comments and blanks
        if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
            return False

        action = rule.action.lower()

        # Combine content and original_options for keyword search
        options_text = f"{rule.content} {rule.original_options}".lower()

        # Pass rules don't log UNLESS they have the 'alert' keyword
        if action == "pass":
            if re.search(r'\balert\b', options_text):
                return False  # Has alert keyword, so it DOES log
            else:
                return True   # No alert keyword, so it does NOT log

        # Drop/reject rules don't log if they have 'noalert' keyword
        if action in ["drop", "reject"]:
            if "noalert" in options_text:
                return True   # Has noalert, so it does NOT log
            else:
                return False  # No noalert, so it DOES log

        # Alert rules always log
        return False

    def _find_rev1_timestamp(self, changes: List[dict], sid: int) -> Optional[str]:
        """Find the timestamp of the Rev 1 entry for a given SID in the history changes.

        Looks for the earliest change entry (by rev number) for the given SID
        that contains a rule_snapshot with rev == 1.
        Falls back to the earliest timestamp for that SID if no rev 1 found.
        """
        sid_entries = []

        for change in changes:
            details = change.get('details', {})
            change_sid = details.get('sid')
            if change_sid == sid:
                snapshot = details.get('rule_snapshot', {})
                timestamp = change.get('timestamp')
                rev = snapshot.get('rev', details.get('rev'))
                if timestamp:
                    sid_entries.append({
                        'timestamp': timestamp,
                        'rev': rev
                    })

        if not sid_entries:
            return None

        # Look for Rev 1 specifically
        for entry in sid_entries:
            if entry.get('rev') == 1:
                return entry['timestamp']

        # Fallback: return the earliest timestamp for this SID
        sid_entries.sort(key=lambda e: e.get('timestamp', ''))
        return sid_entries[0]['timestamp'] if sid_entries else None

    def _parse_timestamp_to_date(self, timestamp_str: str) -> Optional[datetime.date]:
        """Parse an ISO format timestamp string to a date object.

        Handles various ISO 8601 formats:
        - 2024-01-15T10:30:00
        - 2024-01-15T10:30:00.123456
        - 2024-01-15
        """
        if not timestamp_str:
            return None

        try:
            # Try full ISO format with datetime
            dt = datetime.datetime.fromisoformat(timestamp_str)
            return dt.date()
        except (ValueError, TypeError):
            pass

        try:
            # Try date-only format
            return datetime.date.fromisoformat(timestamp_str[:10])
        except (ValueError, TypeError, IndexError):
            return None
