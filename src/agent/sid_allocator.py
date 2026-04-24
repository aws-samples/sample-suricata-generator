"""
SID Allocator for the Suricata Rule Generator AI Agent Layer.

Assigns unique SIDs within the valid range, tracking existing SIDs to avoid collisions.
"""

from typing import Optional
from src.core.constants import SuricataConstants


class SIDAllocator:
    """Assigns unique SIDs within SuricataConstants.SID_MIN to SID_MAX."""

    def __init__(
        self,
        existing_sids: Optional[set[int]] = None,
        start: int = 100,
    ):
        self.existing = existing_sids or set()
        # Start from max existing SID + 1, or the provided start value,
        # matching the main editor's behavior (blank file starts at 100)
        if self.existing:
            self._next = max(max(self.existing) + 1, start)
        else:
            self._next = start

    def next_sid(self) -> int:
        """Returns the next available SID, skipping any in the existing set."""
        while self._next in self.existing and self._next <= SuricataConstants.SID_MAX:
            self._next += 1
        if self._next > SuricataConstants.SID_MAX:
            raise ValueError(f"No available SIDs in range {SuricataConstants.SID_MIN}-{SuricataConstants.SID_MAX}")
        sid = self._next
        self.existing.add(sid)
        self._next += 1
        return sid
