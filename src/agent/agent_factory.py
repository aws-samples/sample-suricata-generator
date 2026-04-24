"""
Agent Factory for the Suricata Rule Generator AI Agent Layer.

Constructs and caches the full AgentLoop pipeline, wiring together all
components. Isolates pipeline construction from the UI layer.
"""

import logging
from typing import Optional

from src.agent.agent_loop import AgentLoop
from src.agent.best_practice_checker import BestPracticeChecker
from src.agent.knowledge_base import KnowledgeBase
from src.agent.nl_parser import NLParser
from src.agent.rule_analyzer_wrapper import RuleAnalyzerWrapper
from src.agent.rule_builder import RuleBuilder
from src.agent.rule_validator import RuleValidator
from src.agent.sid_allocator import SIDAllocator

# Guard boto3 import — AI features degrade gracefully when absent
HAS_BOTO3 = False
try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    boto3 = None

logger = logging.getLogger(__name__)


class AgentFactory:
    """Constructs and caches the AgentLoop pipeline."""

    def __init__(self, aws_session, data_dir: str = "data/"):
        """Initialise the factory.

        Args:
            aws_session: An AWSSessionManager instance used to create
                         Bedrock clients with the correct profile/credentials.
            data_dir:    Path to the local data directory for the KnowledgeBase.
        """
        self._aws_session = aws_session
        self._data_dir = data_dir
        self._agent: Optional[AgentLoop] = None
        self._region: Optional[str] = None
        self._model_id: Optional[str] = None
        self._sid_allocator: Optional[SIDAllocator] = None

    def get_or_create_agent(
        self,
        region: str,
        model_id: str,
        existing_sids: set[int],
    ) -> AgentLoop:
        """Return a cached AgentLoop or build a new one if config changed.

        The pipeline is rebuilt when *region* or *model_id* differ from the
        previously cached values, or after an explicit ``invalidate()`` call.
        The SIDAllocator's existing SIDs are always updated to the latest set.

        Args:
            region:        AWS region for the Bedrock client (e.g. ``us-east-1``).
            model_id:      Bedrock model / inference-profile ID.
            existing_sids: Current SIDs in the Generator's rule list.

        Returns:
            A fully wired AgentLoop instance.
        """
        config_changed = (region != self._region or model_id != self._model_id)

        if self._agent is None or config_changed:
            logger.info(
                "Building agent pipeline (region=%s, model=%s)", region, model_id
            )

            # 1. Knowledge base — loads from the shared data/ directory
            knowledge_base = KnowledgeBase(local_data_dir=self._data_dir)

            # 2. SID allocator — seeded with the Generator's current SIDs
            self._sid_allocator = SIDAllocator(existing_sids=set(existing_sids))

            # 3. NL parser — needs a bedrock-runtime client for the target region
            bedrock_client = self._aws_session.get_client(
                "bedrock-runtime", region_name=region
            )
            nl_parser = NLParser(
                knowledge_base=knowledge_base,
                bedrock_client=bedrock_client,
                model_id=model_id,
                region=region,
            )

            # 4. Rule builder — wired to the SID allocator
            rule_builder = RuleBuilder(sid_allocator=self._sid_allocator)

            # 5. Rule validator — uses the knowledge base for keyword validation
            rule_validator = RuleValidator(knowledge_base=knowledge_base)

            # 6. Rule analyzer wrapper
            rule_analyzer = RuleAnalyzerWrapper()

            # 7. Best-practice checker
            best_practice_checker = BestPracticeChecker()

            # 8. Agent loop — orchestrates the full pipeline
            self._agent = AgentLoop(
                nl_parser=nl_parser,
                rule_builder=rule_builder,
                rule_validator=rule_validator,
                rule_analyzer=rule_analyzer,
                best_practice_checker=best_practice_checker,
            )

            self._region = region
            self._model_id = model_id
        else:
            # Config unchanged — just refresh the SID allocator's existing set
            if self._sid_allocator is not None:
                self._sid_allocator.existing = set(existing_sids)

        return self._agent

    def invalidate(self) -> None:
        """Force a full rebuild on the next ``get_or_create_agent()`` call.

        Useful after an AWS profile change or credential refresh.
        """
        self._agent = None
        self._region = None
        self._model_id = None
        self._sid_allocator = None

    @staticmethod
    def list_models(aws_session, region: str) -> list[dict]:
        """Query Bedrock for available foundation models / inference profiles.

        Only returns models with ACTIVE lifecycle status. Legacy and
        end-of-life models are filtered out so users only see models
        that will actually work.

        Args:
            aws_session: An AWSSessionManager instance.
            region:      AWS region to query.

        Returns:
            A list of dicts with ``modelId`` and ``modelName`` keys, or an
            empty list if boto3 is unavailable or the API call fails.
        """
        if not HAS_BOTO3:
            return []

        try:
            client = aws_session.get_client("bedrock", region_name=region)

            # 1. Build a set of ACTIVE foundation model IDs for filtering
            active_model_ids: set[str] = set()
            try:
                response = client.list_foundation_models(
                    byOutputModality="TEXT",
                )
                for model in response.get("modelSummaries", []):
                    status = (
                        model.get("modelLifecycle", {})
                        .get("status", "")
                        .upper()
                    )
                    if status == "ACTIVE":
                        active_model_ids.add(model.get("modelId", ""))
            except Exception:
                pass

            models: list[dict] = []

            # 2. List inference profiles and keep only those backed by
            #    active foundation models
            try:
                response = client.list_inference_profiles()
                for profile in response.get("inferenceProfileSummaries", []):
                    profile_id = profile.get("inferenceProfileId", "")
                    profile_name = profile.get("inferenceProfileName", "")

                    # Check if any underlying model is active
                    underlying = profile.get("models", [])
                    if underlying:
                        is_active = any(
                            m.get("modelArn", "").split("/")[-1] in active_model_ids
                            for m in underlying
                        )
                    else:
                        # No model info — check if the base model ID
                        # (strip the region prefix) is in the active set
                        parts = profile_id.split(".", 1)
                        base_id = (
                            "anthropic." + parts[1]
                            if len(parts) == 2
                            else profile_id
                        )
                        is_active = base_id in active_model_ids

                    if is_active:
                        models.append({
                            "modelId": profile_id,
                            "modelName": profile_name,
                        })
            except Exception:
                pass

            # 3. If no inference profiles matched, fall back to active
            #    foundation models directly
            if not models:
                for mid in sorted(active_model_ids):
                    models.append({
                        "modelId": mid,
                        "modelName": mid,
                    })

            return models

        except Exception as exc:
            logger.warning("Failed to list Bedrock models in %s: %s", region, exc)
            return []
