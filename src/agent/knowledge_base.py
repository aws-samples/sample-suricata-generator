"""
Knowledge Base for the Suricata Rule Generator AI Agent Layer.

Loads and caches content_keywords.json and rule_templates.json from local files
or optionally from S3. Provides grounding data for the NL Parser.
"""

import json
import os
from typing import Optional


class KnowledgeBase:
    """Loads and caches grounding data from local files or S3."""

    def __init__(
        self,
        local_data_dir: str = "data/",
        s3_client=None,
        bucket: Optional[str] = None,
    ):
        self.local_data_dir = local_data_dir
        self.s3 = s3_client
        self.bucket = bucket
        self._keywords_cache: Optional[list[dict]] = None
        self._templates_cache: Optional[list[dict]] = None
        self._examples_cache: Optional[list[dict]] = None
        self._definitions_cache: Optional[dict] = None
        self._docs_cache: Optional[dict[str, str]] = None

    def get_keywords(self) -> list[dict]:
        """Returns content_keywords.json entries. Cached in-process."""
        if self._keywords_cache is None:
            self._keywords_cache = self._load_json("content_keywords.json")
            # Extract the keywords list from the top-level structure
            if isinstance(self._keywords_cache, dict) and "keywords" in self._keywords_cache:
                self._keywords_cache = self._keywords_cache["keywords"]
        return self._keywords_cache

    def get_templates(self) -> list[dict]:
        """Returns rule_templates.json entries. Cached in-process."""
        if self._templates_cache is None:
            self._templates_cache = self._load_json("rule_templates.json")
            # Handle nested structure if present
            if isinstance(self._templates_cache, dict) and "templates" in self._templates_cache:
                self._templates_cache = self._templates_cache["templates"]
        return self._templates_cache

    def get_keyword_names(self) -> set[str]:
        """Returns the set of valid keyword names for validation."""
        keywords = self.get_keywords()
        return {kw["name"] for kw in keywords if "name" in kw}
    def get_examples(self) -> list[dict]:
        """Returns aws_rule_examples.json entries. Cached in-process."""
        if self._examples_cache is None:
            self._examples_cache = self._load_json("aws_rule_examples.json")
            if isinstance(self._examples_cache, dict) and "examples" in self._examples_cache:
                self._examples_cache = self._examples_cache["examples"]
        return self._examples_cache
    def get_definitions(self) -> dict:
        """Returns suricata_rule_definitions.json content. Cached in-process."""
        if self._definitions_cache is None:
            self._definitions_cache = self._load_json("suricata_rule_definitions.json")
            if not isinstance(self._definitions_cache, dict):
                self._definitions_cache = {}
        return self._definitions_cache
    def get_doc(self, name: str) -> str:
        """Returns content of a markdown doc file from data/ directory. Cached in-process."""
        if self._docs_cache is None:
            self._docs_cache = {}
        if name not in self._docs_cache:
            local_path = os.path.join(self.local_data_dir, name)
            if os.path.exists(local_path):
                with open(local_path, "r", encoding="utf-8") as f:
                    self._docs_cache[name] = f.read()
            else:
                self._docs_cache[name] = ""
        return self._docs_cache[name]

    def _load_json(self, filename: str):
        """Load JSON from local file, falling back to S3 if configured."""
        # Try local file first
        local_path = os.path.join(self.local_data_dir, filename)
        if os.path.exists(local_path):
            with open(local_path, "r", encoding="utf-8") as f:
                return json.load(f)

        # Fall back to S3 if configured
        if self.s3 and self.bucket:
            try:
                response = self.s3.get_object(Bucket=self.bucket, Key=f"data/{filename}")
                return json.loads(response["Body"].read().decode("utf-8"))
            except Exception:
                pass

        return []
