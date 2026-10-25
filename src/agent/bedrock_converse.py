"""
Shared, UI-free wrapper around the Amazon Bedrock Converse API.

Some newer models (for example Claude Opus 5.5) reject the ``temperature``
inference parameter with a ValidationException such as
"`temperature` is deprecated for this model". The AI features in this app
send ``temperature: 0.0`` for deterministic output, so :func:`converse`
transparently retries once without ``temperature`` when a model rejects it,
and remembers that model so later calls omit it up front.

Callers may also request a large ``maxTokens`` (AI Analysis asks for 32000).
Models whose output limit is lower reject that with a ValidationException;
:func:`converse` then retries once with ``maxTokens`` capped to a fallback
(:data:`FALLBACK_MAX_TOKENS`, 8192 unless the caller passes
``fallback_max_tokens=``) and remembers the cap for that model.

Both adjustments compose: one call can retry for ``temperature`` and then for
``maxTokens`` (at most :data:`_MAX_RETRIES` retries, and never twice for the
same parameter), so there is no unbounded retry loop.

Newer models may also return non-text content blocks (for example
``reasoningContent``) before the answer, so callers read the answer with
:func:`response_text` instead of assuming ``content[0]`` is text. Use
:func:`response_stop_reason` to detect an answer that was cut off at the
output token limit (``stopReason == "max_tokens"``).
"""
from __future__ import annotations

import logging
import re
import threading
from typing import Any, Dict, List, Optional, Set

# Guard botocore import - module loads successfully without boto3/botocore
HAS_BOTOCORE = False
try:
    from botocore.exceptions import ClientError
    HAS_BOTOCORE = True
except ImportError:  # pragma: no cover - exercised only without botocore
    ClientError = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# Output-token value used when a model rejects a larger ``maxTokens``.
FALLBACK_MAX_TOKENS = 8192

# A single converse() call retries at most this many times, and each retry
# must fix a parameter that no earlier retry already fixed.
_MAX_RETRIES = 2

# Model IDs known to reject the ``temperature`` / ``topP`` inference params.
_NO_TEMPERATURE_MODELS: Set[str] = set()
_NO_TOP_P_MODELS: Set[str] = set()
# Model ID -> capped ``maxTokens`` after the model rejected a larger value.
_MAX_TOKENS_CAP: Dict[str, int] = {}
_LOCK = threading.Lock()

# "maxTokens", "max_tokens", "max tokens", "max-tokens" (any case).
_MAX_TOKENS_RE = re.compile(r"max[\s_\-]?tokens")
# Words that indicate the value is too large / out of range.
_TOO_LARGE_HINTS = (
    "exceed", "greater than", "larger than", "too large", "too high",
    "too big", "less than", "at most", "maximum", "limit", "invalid",
    "out of range", "not valid", "must be", "<=", ">",
)


class BedrockEmptyResponseError(RuntimeError):
    """Raised when a Converse response contains no answer text."""

    def __init__(self, message: str, stop_reason: Optional[str] = None) -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


class BedrockTruncatedResponseError(RuntimeError):
    """Raised when the model's answer was cut off at the output token limit.

    The (incomplete) answer is never parsed or cached. ``max_tokens`` is the
    output limit that was in effect for the request.
    """

    def __init__(
        self,
        max_tokens: Optional[int],
        advice: str = "Try again, or select a different model.",
    ) -> None:
        super().__init__(truncated_response_message(max_tokens, advice))
        self.max_tokens = max_tokens
        self.stop_reason = "max_tokens"


def truncated_response_message(
    max_tokens: Optional[int],
    advice: str = "Try again, or select a different model.",
) -> str:
    """Return the user-facing message for an answer cut off at the limit."""
    if max_tokens:
        limit = "the output token limit (%d tokens)" % max_tokens
    else:
        limit = "the output token limit"
    return "The model's answer was cut off at %s, so it couldn't be read. %s" % (
        limit, advice,
    )


def _empty_response_message(stop_reason: Optional[str], block_types: List[str]) -> str:
    """Build a user-facing explanation for a response with no answer text."""
    if stop_reason == "max_tokens":
        message = (
            "The model returned no answer text because it hit the output "
            "token limit (stopReason: max_tokens). The limit may have been "
            "used up by the model's reasoning. Try again, or select a "
            "different model."
        )
    else:
        message = (
            "The model returned no answer text (stopReason: %s). Try again, "
            "or select a different model." % (stop_reason or "unknown")
        )
    if block_types:
        message += " Response content blocks: %s." % ", ".join(block_types)
    return message


def response_stop_reason(response: Any) -> Optional[str]:
    """Return the Converse ``stopReason`` (e.g. ``"max_tokens"``) or None."""
    if isinstance(response, dict):
        value = response.get("stopReason")
        if isinstance(value, str):
            return value
    return None


def response_text(response: Any) -> str:
    """Return the answer text from a Bedrock Converse *response*.

    Joins the ``text`` of every content block that has a top-level ``text``
    string, in order. Other blocks (``reasoningContent``, ``toolUse``, ...)
    are ignored, so reasoning text is never returned. Blocks are joined with
    ``""`` because a model may split one answer (e.g. a JSON document)
    across blocks; inserting a separator could alter that text.

    Raises:
        BedrockEmptyResponseError: if output/message/content is missing or
            no non-blank answer text is present. The message includes the
            response's ``stopReason``.
    """
    stop_reason = response.get("stopReason") if isinstance(response, dict) else None
    try:
        content = response["output"]["message"]["content"]
    except (KeyError, TypeError, IndexError):
        content = None

    parts: List[str] = []
    block_types: List[str] = []
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
            else:
                block_types.extend(str(key) for key in block)

    joined = "".join(parts)
    if not joined.strip():
        raise BedrockEmptyResponseError(
            _empty_response_message(stop_reason, block_types), stop_reason
        )
    return joined


def reset_cache() -> None:
    """Forget per-model parameter adjustments (used by tests)."""
    with _LOCK:
        _NO_TEMPERATURE_MODELS.clear()
        _NO_TOP_P_MODELS.clear()
        _MAX_TOKENS_CAP.clear()


def effective_max_tokens(model_id: str, requested: int) -> int:
    """Return the ``maxTokens`` :func:`converse` sends for *model_id*.

    This is *requested* unless the model is known to need a lower cap.
    """
    with _LOCK:
        cap = _MAX_TOKENS_CAP.get(model_id)
    if cap is not None and requested > cap:
        return cap
    return requested


def _validation_message(exc: BaseException) -> Optional[str]:
    """Return the error message if *exc* is a Bedrock ValidationException."""
    if not HAS_BOTOCORE or not isinstance(exc, ClientError):
        return None
    error = (getattr(exc, "response", None) or {}).get("Error", {}) or {}
    if error.get("Code") != "ValidationException":
        return None
    return str(error.get("Message") or exc)


def _is_max_tokens_error(lower_message: str) -> bool:
    """True if a (lower-cased) error message says maxTokens is too large."""
    if not _MAX_TOKENS_RE.search(lower_message):
        return False
    return any(hint in lower_message for hint in _TOO_LARGE_HINTS)


def _adjust_params(
    kwargs: Dict[str, Any],
    drop_temperature: bool,
    drop_top_p: bool,
    max_tokens_cap: Optional[int] = None,
) -> Dict[str, Any]:
    """Return a copy of *kwargs* with the requested inference adjustments.

    Removes ``temperature`` / ``topP`` and lowers ``maxTokens`` to
    *max_tokens_cap* when it is larger. The caller's dicts are not mutated.
    """
    new_kwargs = dict(kwargs)
    config = new_kwargs.get("inferenceConfig")
    if isinstance(config, dict):
        config = dict(config)
        if drop_temperature:
            config.pop("temperature", None)
        if drop_top_p:
            config.pop("topP", None)
        max_tokens = config.get("maxTokens")
        if (
            max_tokens_cap is not None
            and isinstance(max_tokens, int)
            and max_tokens > max_tokens_cap
        ):
            config["maxTokens"] = max_tokens_cap
        new_kwargs["inferenceConfig"] = config
    return new_kwargs


def _plan_retry(
    exc: BaseException,
    call_kwargs: Dict[str, Any],
    model_id: str,
    fallback_max_tokens: int,
    already_fixed: Set[str],
) -> Optional[Dict[str, Any]]:
    """Return adjusted kwargs for a retry after *exc*, or None to re-raise.

    Only parameters not in *already_fixed* are eligible; the ones fixed by
    this retry are added to it and remembered for *model_id*.
    """
    message = _validation_message(exc)
    if message is None:
        return None
    config = call_kwargs.get("inferenceConfig")
    if not isinstance(config, dict):
        return None
    lower = message.lower()

    retry_temp = (
        "temperature" not in already_fixed
        and "temperature" in lower and "temperature" in config
    )
    retry_top_p = (
        "topP" not in already_fixed
        and "topp" in lower and "topP" in config
    )
    max_tokens = config.get("maxTokens")
    retry_max_tokens = (
        "maxTokens" not in already_fixed
        and isinstance(max_tokens, int)
        and max_tokens > fallback_max_tokens
        and _is_max_tokens_error(lower)
    )
    if not (retry_temp or retry_top_p or retry_max_tokens):
        return None

    with _LOCK:
        if retry_temp:
            _NO_TEMPERATURE_MODELS.add(model_id)
        if retry_top_p:
            _NO_TOP_P_MODELS.add(model_id)
        if retry_max_tokens:
            _MAX_TOKENS_CAP[model_id] = fallback_max_tokens

    dropped = [
        name for name, flag in (("temperature", retry_temp), ("topP", retry_top_p))
        if flag
    ]
    if dropped:
        already_fixed.update(dropped)
        logger.warning(
            "Model %s rejected inference parameter(s) %s; retrying without them. "
            "Details: %s",
            model_id, ", ".join(dropped), message,
        )
    if retry_max_tokens:
        already_fixed.add("maxTokens")
        logger.warning(
            "Model %s rejected maxTokens=%s; retrying with maxTokens=%d. "
            "Details: %s",
            model_id, max_tokens, fallback_max_tokens, message,
        )
    return _adjust_params(
        call_kwargs, retry_temp, retry_top_p,
        fallback_max_tokens if retry_max_tokens else None,
    )


def converse(
    client: Any,
    model_id: str,
    *,
    fallback_max_tokens: int = FALLBACK_MAX_TOKENS,
    **kwargs: Any,
) -> Any:
    """Call ``client.converse(modelId=model_id, **kwargs)`` tolerantly.

    If the model is known (or discovered) to reject ``temperature``, the
    parameter is removed from ``inferenceConfig`` and the call is retried.
    ``topP`` is only removed when the error message names it. If the model
    rejects ``maxTokens`` as too large and it exceeds *fallback_max_tokens*,
    the call is retried with ``maxTokens = fallback_max_tokens`` and that cap
    is used up front for later calls to the same model.

    *fallback_max_tokens* is consumed here and never sent to the client.
    At most :data:`_MAX_RETRIES` retries happen, each fixing a different
    parameter. The caller's ``inferenceConfig`` dict is never mutated. Any
    other error (or a repeat failure for an already-fixed parameter)
    propagates unchanged.
    """
    with _LOCK:
        drop_temp = model_id in _NO_TEMPERATURE_MODELS
        drop_top_p = model_id in _NO_TOP_P_MODELS
        cap = _MAX_TOKENS_CAP.get(model_id)
    call_kwargs = _adjust_params(kwargs, drop_temp, drop_top_p, cap)

    already_fixed: Set[str] = set()
    retries = 0
    while True:
        try:
            return client.converse(modelId=model_id, **call_kwargs)
        except Exception as exc:
            if retries >= _MAX_RETRIES:
                raise
            retry_kwargs = _plan_retry(
                exc, call_kwargs, model_id, fallback_max_tokens, already_fixed
            )
            if retry_kwargs is None:
                raise
        # Retry outside the except block so a retry failure is raised on its own.
        retries += 1
        call_kwargs = retry_kwargs
