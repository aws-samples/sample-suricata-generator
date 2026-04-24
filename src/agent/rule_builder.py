"""
Rule Builder for the Suricata Rule Generator AI Agent Layer.

Maps DetectionIntent to SuricataRule using the existing suricata_rule.py,
assigns SIDs via SIDAllocator, and produces deterministic rule strings.
"""

from src.agent.models import DetectionIntent
from src.agent.sid_allocator import SIDAllocator
from src.core.suricata_rule import SuricataRule


class RuleBuilder:
    """Builds validated Suricata rule strings from DetectionIntent objects."""

    def __init__(self, sid_allocator: SIDAllocator):
        self.sid_allocator = sid_allocator

    def build(self, intent: DetectionIntent) -> str:
        """Convert a DetectionIntent into a Suricata rule string.

        Uses SuricataRule.to_string() for deterministic assembly — never raw LLM text.
        Strips any msg/sid/rev from content to avoid duplicates since to_string() adds them.
        Honors user-specified SID/rev when provided in the intent.
        """
        kwargs = intent.to_suricata_kwargs()

        # Use user-specified SID if provided, otherwise auto-assign
        if "sid" not in kwargs or kwargs["sid"] is None:
            kwargs["sid"] = self.sid_allocator.next_sid()
        else:
            # Register user-specified SID to avoid future collisions
            self.sid_allocator.existing.add(kwargs["sid"])

        # Use user-specified rev if provided, otherwise default to 1
        if "rev" not in kwargs or kwargs["rev"] is None:
            kwargs["rev"] = 1

        # Clean content: remove msg, sid, rev keywords since to_string() adds them
        if kwargs.get("content"):
            parts = [p.strip() for p in kwargs["content"].split(";")]
            cleaned = [
                p for p in parts
                if p and not p.startswith("msg:") and not p.startswith("sid:") and not p.startswith("rev:")
            ]
            kwargs["content"] = "; ".join(cleaned)

        rule = SuricataRule(**kwargs)
        return rule.to_string()

    def build_multiple(self, intents: list[DetectionIntent]) -> list[str]:
        """Build multiple rules from a list of intents."""
        return [self.build(intent) for intent in intents]
