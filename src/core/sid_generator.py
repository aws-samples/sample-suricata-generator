"""
SID Generator Module

Centralized logic for suggesting the next Suricata rule SID.

The default scheme is date-based: ``YYMMDDNNNN`` — a 6-digit date prefix
(2-digit year, month, day) followed by a 4-digit daily counter, giving up to
10,000 auto-numbered rules per day. Example for 2026-08-22: ``2608220001``,
``2608220002``, ... ``2608229999``.

Design notes:
- The largest date SID (``YYMMDD9999``) is well under the AWS Network Firewall
  maximum of ``4294967294`` (an unsigned 32-bit integer), so the scheme is safe
  through the 2-digit-year rollover.
- This module is intentionally free of any UI/tkinter dependencies so it can be
  imported both by the main application and by the standalone (subprocess)
  Advanced Editor.
- ``suggest_next_sid`` accepts a ``scheme`` parameter so an alternative
  ("sequential") numbering mode can be added later without touching call sites.
  Only the date-based scheme is wired up today.
"""

from datetime import date
from typing import Iterable, Optional, Set

try:
    from src.core.constants import SuricataConstants
    _SID_MIN = SuricataConstants.SID_MIN
    _SID_MAX = SuricataConstants.SID_MAX
except Exception:  # pragma: no cover - defensive fallback when run standalone
    _SID_MIN = 1
    _SID_MAX = 4294967294


# Number of digits reserved for the daily counter (0001-9999).
_COUNTER_DIGITS = 4
_COUNTER_SPAN = 10 ** _COUNTER_DIGITS  # 10000 slots per day (0000-9999)


def date_base_sid(today: Optional[date] = None) -> int:
    """Return the base SID for a given day (the ``YYMMDD0000`` value).

    Args:
        today: Date to base the SID on. Defaults to the current local date.

    Returns:
        The day's base SID, e.g. 2026-08-22 -> ``2608220000``.
    """
    if today is None:
        today = date.today()
    yy = today.year % 100
    prefix = yy * 10000 + today.month * 100 + today.day  # YYMMDD
    return prefix * _COUNTER_SPAN


def _first_free_at_or_after(candidate: int, used: Set[int], upper: int) -> Optional[int]:
    """Return the first value >= candidate not in ``used`` and <= ``upper``.

    Returns None if no free value exists within [candidate, upper].
    """
    if candidate < _SID_MIN:
        candidate = _SID_MIN
    while candidate <= upper:
        if candidate not in used:
            return candidate
        candidate += 1
    return None


def _normalize_used(existing_sids: Iterable[int]) -> Set[int]:
    """Coerce an iterable of SIDs into a set of ints, ignoring non-integers."""
    used: Set[int] = set()
    for sid in existing_sids:
        try:
            used.add(int(sid))
        except (TypeError, ValueError):
            continue
    return used


def suggest_next_sid(existing_sids: Iterable[int],
                     today: Optional[date] = None,
                     scheme: str = "date") -> int:
    """Suggest the next SID given the set of SIDs already in use.

    Args:
        existing_sids: SIDs currently in use (comments/blank lines excluded by
            the caller). Any iterable of ints; non-integers are ignored.
        today: Date used for the date-based scheme. Defaults to current date.
        scheme: "date" (default, ``YYMMDDNNNN``) or "sequential" (max + 1).

    Returns:
        A suggested SID guaranteed not to collide with ``existing_sids`` when a
        free value is available, and clamped to the valid SID range.

    Fallback order (date scheme):
        D-1: Next free slot within today's ``YYMMDD`` block.
        D-2: If today's block is full, ``max(existing) + 1``.
        D-3: If that collides or overflows past SID_MAX, scan for any free SID.
    """
    used = _normalize_used(existing_sids)

    if scheme == "sequential":
        return _sequential_suggestion(used)

    # Date-based scheme (default)
    base = date_base_sid(today)
    day_start = base + 1  # reserve NNNN=0000 conceptually; first rule is ...0001
    day_end = base + (_COUNTER_SPAN - 1)  # ...9999

    # Highest SID already used within today's block (if any).
    used_today = [s for s in used if day_start <= s <= day_end]
    if used_today:
        candidate = max(used_today) + 1
    else:
        candidate = day_start

    # D-1: first free slot within today's block at or after the candidate.
    free_in_day = _first_free_at_or_after(candidate, used, day_end)
    if free_in_day is not None:
        return free_in_day

    # D-2 / D-3: today's block is exhausted; fall back to global sequential.
    return _sequential_suggestion(used)


def _sequential_suggestion(used: Set[int]) -> int:
    """Return ``max(used) + 1``, with defensive fallbacks within the SID range.

    Used both for the explicit "sequential" scheme and as the date scheme's
    day-exhaustion fallback (D-2/D-3).
    """
    candidate = max(used, default=_SID_MIN - 1) + 1
    if candidate < _SID_MIN:
        candidate = _SID_MIN

    # D-3: if the natural next value is taken or over the max, scan for any hole.
    if candidate in used or candidate > _SID_MAX:
        free = _first_free_at_or_after(_SID_MIN, used, _SID_MAX)
        if free is not None:
            return free
        # No free SID anywhere in range (pathological); return max as a last
        # resort so the caller's uniqueness validation surfaces the problem.
        return _SID_MAX

    return candidate
