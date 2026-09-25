"""UI-free Feature Model for the AWS Setup IAM policy generator and tester.

This module is the single source of truth mapping each user-facing tool feature
to (1) the IAM actions it requires and (2) the connection-test probes that verify
those actions. Both the generated IAM policy and the permission test are derived
from this one model, so they can never cover different features.

Design constraints (see .kiro/specs/iam-feature-selector):
- Standard library only. No tkinter, no boto3 — so the model and its pure
  assembly functions are fully unit-testable without a display or AWS.
- At Full_Selection (every feature selected) the assembled policy JSON is
  byte-for-byte identical to the hand-authored ``AWS_SETUP_IAM_POLICY_JSON``
  that shipped before this feature (Requirement 8.2), including action ordering.

Ordering note: the canonical action order is defined by ``_ORDERED_ACTIONS``
below, where each action is tagged with its owning feature. This models one
real-world quirk: ``sts:GetCallerIdentity`` is functionally a Container
Association Manager permission (used on load to detect account ownership) but,
in the shipped policy, is emitted near the end — after the RAM (Cross-account
Sharing) block and immediately before the Bedrock actions. Tagging each action
with its owner and preserving the shipped sequence lets a subset selection drop
exactly the right actions while keeping the survivors in their original order.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class Feature:
    """A user-facing capability that requires AWS permissions.

    Attributes:
        id: Stable identifier (e.g. ``"container_associations"``).
        label: User-facing checkbox label.
        parent_id: For a Dependent_Feature (sub-option), the id of the feature
            it depends on. ``None`` for a top-level feature.
        breakdown: Ordered tuples of ``(title, lines)`` — the human-readable
            permission groups this feature contributes to the Permission
            Breakdown. A single feature can contribute more than one titled
            group (the Container Association Manager does), so this is a tuple
            of groups rather than one title + lines.
        probe_ids: Identifiers the GUI maps to live boto3 probe functions. The
            model only declares *which* probes belong to *which* feature; the
            actual AWS calls live in the GUI layer to keep this module pure.
    """

    id: str
    label: str
    parent_id: Optional[str] = None
    breakdown: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    probe_ids: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Canonical action ordering.
#
# Each entry is (feature_id, iam_action) in the EXACT order the action appears
# in the shipped AWS_SETUP_IAM_POLICY_JSON. selected_actions() filters this list
# by the selected feature ids, which both (a) preserves the shipped order and
# (b) drops a feature's actions cleanly when it is unselected. Do not reorder
# without updating the exact-match test.
# ---------------------------------------------------------------------------
_ORDERED_ACTIONS: Tuple[Tuple[str, str], ...] = (
    # CloudWatch Logs
    ("cloudwatch", "logs:DescribeLogGroups"),
    ("cloudwatch", "logs:StartQuery"),
    ("cloudwatch", "logs:GetQueryResults"),
    ("cloudwatch", "logs:StopQuery"),
    # Network Firewall rule-group read (Import / Managed analysis)
    ("rg_import", "network-firewall:ListRuleGroups"),
    ("rg_import", "network-firewall:DescribeRuleGroup"),
    # Network Firewall rule-group write (Export)
    ("rg_export", "network-firewall:CreateRuleGroup"),
    ("rg_export", "network-firewall:UpdateRuleGroup"),
    # Container Association Manager: container-association actions
    ("container_associations", "network-firewall:ListContainerAssociations"),
    ("container_associations", "network-firewall:DescribeContainerAssociation"),
    ("container_associations", "network-firewall:CreateContainerAssociation"),
    ("container_associations", "network-firewall:UpdateContainerAssociation"),
    ("container_associations", "network-firewall:DeleteContainerAssociation"),
    # Container Association Manager: tag actions
    ("container_associations", "network-firewall:TagResource"),
    ("container_associations", "network-firewall:UntagResource"),
    ("container_associations", "network-firewall:ListTagsForResource"),
    # Container Association Manager: EventBridge managed rule (ECS)
    ("container_associations", "events:PutRule"),
    ("container_associations", "events:PutTargets"),
    ("container_associations", "events:DescribeRule"),
    ("container_associations", "events:DeleteRule"),
    ("container_associations", "events:RemoveTargets"),
    # Container Association Manager: ECS discovery
    ("container_associations", "ecs:ListClusters"),
    ("container_associations", "ecs:DescribeClusters"),
    ("container_associations", "ecs:ListContainerInstances"),
    ("container_associations", "ecs:DescribeContainerInstances"),
    # Container Association Manager: EKS discovery
    ("container_associations", "eks:ListClusters"),
    ("container_associations", "eks:DescribeCluster"),
    # Container Association Manager: service-linked role (first use)
    ("container_associations", "iam:CreateServiceLinkedRole"),
    # Cross-account Sharing (RAM) — dependent on Container Association Manager
    ("sharing", "ram:CreateResourceShare"),
    ("sharing", "ram:AssociateResourceShare"),
    ("sharing", "ram:DisassociateResourceShare"),
    ("sharing", "ram:GetResourceShares"),
    ("sharing", "ram:GetResourceShareAssociations"),
    ("sharing", "ram:ListResources"),
    # Container Association Manager: ownership detection — emitted here, after
    # the RAM block and just before Bedrock, to match the shipped policy.
    ("container_associations", "sts:GetCallerIdentity"),
    # AI Rule Assistant (Bedrock) — emitted last
    ("bedrock", "bedrock:InvokeModel"),
    ("bedrock", "bedrock:ListFoundationModels"),
    ("bedrock", "bedrock:ListInferenceProfiles"),
)


# ---------------------------------------------------------------------------
# Feature declarations (canonical order). Labels and breakdown text mirror the
# shipped AWS_SETUP_PERMISSION_BREAKDOWN so build_breakdown(ALL_FEATURE_IDS)
# reproduces it exactly.
# ---------------------------------------------------------------------------
FEATURES: Tuple[Feature, ...] = (
    Feature(
        id="cloudwatch",
        label="Rule Usage Analyzer & Traffic Analysis",
        breakdown=(
            (
                "CloudWatch Logs (Rule Usage Analyzer & Traffic Analysis):",
                (
                    "logs:DescribeLogGroups - List available log groups",
                    "logs:StartQuery - Initiates CloudWatch Logs Insights queries",
                    "logs:GetQueryResults - Retrieves query results",
                    "logs:StopQuery - Cancels running queries",
                ),
            ),
        ),
        probe_ids=("cloudwatch",),
    ),
    Feature(
        id="rg_import",
        label="Rule Group Direct Import",
        breakdown=(
            (
                "Network Firewall (Rule Group Import & Managed Rule Analysis):",
                (
                    "network-firewall:ListRuleGroups - Browse account and managed rule groups",
                    "network-firewall:DescribeRuleGroup - View rule group details and rules",
                ),
            ),
        ),
        probe_ids=("rule_group_import",),
    ),
    Feature(
        id="rg_export",
        label="Rule Group Direct Export",
        breakdown=(
            (
                "Network Firewall (Rule Group Export):",
                (
                    "network-firewall:CreateRuleGroup - Deploy new rule groups",
                    "network-firewall:UpdateRuleGroup - Overwrite existing rule groups",
                ),
            ),
        ),
        probe_ids=("rule_group_export",),
    ),
    Feature(
        id="container_associations",
        label="Container Association Manager",
        breakdown=(
            (
                "Network Firewall (Container Association Manager):",
                (
                    "network-firewall:List/Describe ContainerAssociation - list & inspect",
                    "network-firewall:Create/Update/Delete ContainerAssociation - manage",
                    "network-firewall:TagResource/UntagResource/ListTagsForResource - tags",
                    "events:PutRule/PutTargets/DescribeRule/DeleteRule/RemoveTargets - for ECS,",
                    "  Network Firewall creates/removes a managed EventBridge rule (NetworkFirewallManagedRule-*)",
                    "  on your behalf to receive ECS task state-change events; your identity must allow these",
                    "sts:GetCallerIdentity - determine your account to flag owned vs. shared-in associations",
                ),
            ),
            (
                "Cluster & attribute discovery (Container Association Manager):",
                (
                    "ecs:ListClusters/DescribeClusters/ListContainerInstances/DescribeContainerInstances",
                    "eks:ListClusters/DescribeCluster",
                ),
            ),
            (
                "Service-linked role (first use):",
                (
                    "iam:CreateServiceLinkedRole - created automatically on first CreateContainerAssociation",
                ),
            ),
        ),
        probe_ids=("container_associations",),
    ),
    Feature(
        id="sharing",
        label="Cross-account Sharing",
        parent_id="container_associations",
        breakdown=(
            (
                "Cross-account sharing via AWS RAM (Container Association Manager):",
                (
                    "ram:CreateResourceShare/AssociateResourceShare/DisassociateResourceShare - share/unshare",
                    "ram:GetResourceShares - find the tool-managed resource share to reuse before sharing",
                    "ram:GetResourceShareAssociations/ListResources - show \u201cShared with\u201d",
                ),
            ),
        ),
        probe_ids=("sharing",),
    ),
    Feature(
        id="bedrock",
        label="AI Rule Assistant",
        breakdown=(
            (
                "Amazon Bedrock (AI Rule Assistant):",
                (
                    "bedrock:InvokeModel - Send prompts to Claude for rule generation",
                    "bedrock:ListFoundationModels - Discover available models",
                    "bedrock:ListInferenceProfiles - List inference profiles for model selection",
                    "Note: Model access must also be enabled in the Bedrock console",
                ),
            ),
        ),
        probe_ids=("bedrock",),
    ),
)

ALL_FEATURE_IDS: Tuple[str, ...] = tuple(f.id for f in FEATURES)

# Fast lookup by id, preserving declaration order semantics elsewhere.
_FEATURES_BY_ID: Dict[str, Feature] = {f.id: f for f in FEATURES}

# The IAM policy envelope (matches the shipped constant exactly).
_POLICY_SID = "SuricataGeneratorAWSPermissions"
_POLICY_VERSION = "2012-10-17"


def get_feature(feature_id: str) -> Optional[Feature]:
    """Return the Feature with the given id, or None if unknown."""
    return _FEATURES_BY_ID.get(feature_id)


def resolve_selection(ids) -> Set[str]:
    """Enforce feature dependencies on a raw selection.

    A Dependent_Feature (one with a ``parent_id``) is only kept if its parent
    is also selected. Unknown ids are dropped. Returns a set of surviving ids.

    This backs Requirements 2.3/2.4: a dependent (Cross-account Sharing) cannot
    survive without its parent (Container Association Manager), so the generated
    policy never includes RAM actions without the container-association
    permissions they depend on.
    """
    requested = {i for i in ids if i in _FEATURES_BY_ID}
    resolved = set()
    for fid in requested:
        feature = _FEATURES_BY_ID[fid]
        if feature.parent_id is not None and feature.parent_id not in requested:
            # Dependent feature without its parent — drop it.
            continue
        resolved.add(fid)
    return resolved


def selected_actions(ids) -> List[str]:
    """Return the de-duplicated union of the selected features' IAM actions.

    Ordering is canonical: actions appear in the fixed ``_ORDERED_ACTIONS``
    sequence (which, at Full_Selection, equals the shipped policy order), and an
    action shared by multiple features appears once, at its first occurrence.
    Dependencies are resolved first (Requirement 2.4), so deselecting a parent
    removes its dependent's actions too.
    """
    resolved = resolve_selection(ids)
    seen = set()
    actions: List[str] = []
    for feature_id, action in _ORDERED_ACTIONS:
        if feature_id not in resolved:
            continue
        if action in seen:
            continue
        seen.add(action)
        actions.append(action)
    return actions


def build_policy_json(ids) -> Optional[str]:
    """Return the formatted IAM policy JSON for the selection.

    Returns ``None`` when the (resolved) selection contributes no actions, which
    the GUI renders as the "No features selected" message with Copy/Test
    disabled (Requirement 3.6). At Full_Selection the returned string is
    byte-for-byte identical to the shipped ``AWS_SETUP_IAM_POLICY_JSON``.
    """
    actions = selected_actions(ids)
    if not actions:
        return None

    # Build the exact shipped shape by hand-formatting so the output matches the
    # original triple-quoted literal character-for-character (2-space indent,
    # the "[{" statement opening on the Statement line, and the trailing "}]").
    lines = [
        "{",
        '  "Version": "%s",' % _POLICY_VERSION,
        '  "Statement": [{',
        '    "Sid": "%s",' % _POLICY_SID,
        '    "Effect": "Allow",',
        '    "Action": [',
    ]
    for i, action in enumerate(actions):
        comma = "," if i < len(actions) - 1 else ""
        lines.append('      "%s"%s' % (action, comma))
    lines.append("    ],")
    lines.append('    "Resource": "*"')
    lines.append("  }]")
    lines.append("}")
    return "\n".join(lines)


def build_breakdown(ids) -> str:
    """Return the feature-grouped Permission_Breakdown text for the selection.

    Only the selected (resolved) features' groups appear, in canonical feature
    order (Requirement 3.7). At Full_Selection this equals the shipped
    ``AWS_SETUP_PERMISSION_BREAKDOWN``. Returns an empty string when nothing is
    selected.
    """
    resolved = resolve_selection(ids)
    groups: List[str] = []
    for feature in FEATURES:
        if feature.id not in resolved:
            continue
        for title, group_lines in feature.breakdown:
            block = title + "\n" + "\n".join("\u2022 " + ln for ln in group_lines)
            groups.append(block)
    return "\n\n".join(groups)


def selected_probe_ids(ids) -> List[str]:
    """Return the probe ids for the selected features, in canonical order.

    Used by the GUI to run only the selected features' live probes. Dependencies
    are resolved first, so a dependent's probes are excluded when its parent is
    unselected.
    """
    resolved = resolve_selection(ids)
    probes: List[str] = []
    for feature in FEATURES:
        if feature.id in resolved:
            probes.extend(feature.probe_ids)
    return probes
