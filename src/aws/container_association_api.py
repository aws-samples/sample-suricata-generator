"""
UI-free API layer for the Container Association Manager.

This module contains thin, testable wrappers over the boto3 calls the
Container Association Manager needs, plus pure request/diff builders. It has
no tkinter dependency: every function that talks to AWS takes an explicit
boto3 client, so it can be unit-tested with mocked clients.

Responsibilities:
- Network Firewall container-association CRUD + tagging wrappers.
- Pure request builders (build_create_request / build_update_request) and the
  edit diff (diff_association) used by the Review screen.
- ECS / EKS cluster listing and ECS attribute discovery.
- AWS RAM sharing (share / unshare) and shared-with detection + availability.

All wrappers pass the AWS response through (or a lightly normalized shape);
error handling and dialogs live in the UI layer (container_association_manager).
The pure builders never call AWS and never raise on empty/optional fields.

Verified AWS shapes (Network Firewall API Reference / Developer Guide):
- CreateContainerAssociation: ContainerAssociationName, Type (ECS|EKS),
  ContainerMonitoringConfigurations [{ClusterArn, AttributeFilters:[{Key,Value}]}],
  optional Description, optional Tags [{Key,Value}].
- UpdateContainerAssociation: ContainerAssociationArn, Type, UpdateToken,
  ContainerMonitoringConfigurations, optional Description.
- DescribeContainerAssociation returns the config plus Status and UpdateToken.
- DeleteContainerAssociation is async (Status -> DELETING) and is blocked while
  a rule group references the association.
"""

from typing import Optional


# ===========================================================================
# Network Firewall: container association CRUD + tags
# ===========================================================================

def list_container_associations(nfw_client) -> list:
    """List all container associations in the client's account/Region.

    Handles NextToken pagination transparently and normalizes each summary to
    a consistent shape. The AWS ListContainerAssociations response returns
    ContainerAssociationSummary objects with only `Arn` and `Name` (Type and
    Status are NOT in the list — they come from DescribeContainerAssociation).

    Args:
        nfw_client: A boto3 'network-firewall' client.

    Returns:
        List of dicts, each {'arn': str, 'name': str}.
    """
    associations = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs['NextToken'] = next_token
        response = nfw_client.list_container_associations(**kwargs)
        for summary in response.get('ContainerAssociations', []):
            arn = summary.get('Arn', '')
            name = summary.get('Name') or (arn.split('/')[-1] if arn else '')
            associations.append({'arn': arn, 'name': name})
        next_token = response.get('NextToken')
        if not next_token:
            break
    return associations


def describe_container_association(nfw_client, arn: str) -> dict:
    """Describe a single container association (raw AWS response).

    The response is a FLAT object (not nested under 'ContainerAssociation'):
    ContainerAssociationArn, ContainerAssociationName, Type, Status,
    ContainerMonitoringConfigurations, Description, Tags, UpdateToken, ...

    Args:
        nfw_client: A boto3 'network-firewall' client.
        arn: The container association ARN.

    Returns:
        The full AWS response dict.
    """
    return nfw_client.describe_container_association(ContainerAssociationArn=arn)


def describe_container_association_normalized(nfw_client, arn: str) -> dict:
    """Describe an association and return a normalized, tool-friendly dict.

    Reads the flat DescribeContainerAssociation response and maps it to the
    keys the manager/edit form use.

    Args:
        nfw_client: A boto3 'network-firewall' client.
        arn: The container association ARN.

    Returns:
        {'arn', 'name', 'type', 'status', 'description', 'update_token',
         'monitoring': [{'cluster_arn', 'filters': [{'key','value'}]}],
         'tags': {k: v}}  (tags is populated only if present on the response).
    """
    resp = nfw_client.describe_container_association(ContainerAssociationArn=arn)
    monitoring = []
    for cfg in resp.get('ContainerMonitoringConfigurations', []):
        monitoring.append({
            'cluster_arn': cfg.get('ClusterArn', ''),
            'filters': [{'key': f.get('Key', ''), 'value': f.get('Value', '')}
                        for f in cfg.get('AttributeFilters', [])],
        })
    tags = {t['Key']: t['Value'] for t in resp.get('Tags', [])}
    return {
        'arn': resp.get('ContainerAssociationArn', arn),
        'name': resp.get('ContainerAssociationName', ''),
        'type': resp.get('Type', ''),
        'status': resp.get('Status', ''),
        'description': resp.get('Description', '') or '',
        'update_token': resp.get('UpdateToken', ''),
        'monitoring': monitoring,
        'tags': tags,
    }


def create_container_association(nfw_client, params: dict) -> dict:
    """Create a container association.

    Args:
        nfw_client: A boto3 'network-firewall' client.
        params: Request params from build_create_request().

    Returns:
        The AWS response dict (includes 'ContainerAssociationArn' and 'Status').
    """
    return nfw_client.create_container_association(**params)


def update_container_association(nfw_client, params: dict) -> dict:
    """Update a container association.

    Args:
        nfw_client: A boto3 'network-firewall' client.
        params: Request params from build_update_request() (includes UpdateToken).

    Returns:
        The AWS response dict.
    """
    return nfw_client.update_container_association(**params)


def delete_container_association(nfw_client, arn: str) -> dict:
    """Delete a container association (asynchronous; transitions to DELETING).

    AWS rejects the call while a rule group still references the association;
    the caller surfaces that error verbatim.

    Args:
        nfw_client: A boto3 'network-firewall' client.
        arn: The container association ARN.

    Returns:
        The AWS response dict.
    """
    return nfw_client.delete_container_association(ContainerAssociationArn=arn)


def list_tags(nfw_client, arn: str) -> dict:
    """Return the association's tags as a {key: value} dict.

    Args:
        nfw_client: A boto3 'network-firewall' client.
        arn: The container association ARN.

    Returns:
        Dict mapping tag keys to values ({} when there are none).
    """
    response = nfw_client.list_tags_for_resource(ResourceArn=arn)
    return {t['Key']: t['Value'] for t in response.get('Tags', [])}


def tag_resource(nfw_client, arn: str, tags: dict) -> None:
    """Add or overwrite tags on the association.

    TagResource overwrites the value of an existing key, so this covers both
    "add tag" and "change tag value".

    Args:
        nfw_client: A boto3 'network-firewall' client.
        arn: The container association ARN.
        tags: {key: value} pairs to apply. No-op when empty.
    """
    if not tags:
        return
    nfw_client.tag_resource(
        ResourceArn=arn,
        Tags=[{'Key': k, 'Value': v} for k, v in tags.items()],
    )


def untag_resource(nfw_client, arn: str, keys: list) -> None:
    """Remove tags (by key) from the association.

    Args:
        nfw_client: A boto3 'network-firewall' client.
        arn: The container association ARN.
        keys: Tag keys to remove. No-op when empty.
    """
    if not keys:
        return
    nfw_client.untag_resource(ResourceArn=arn, TagKeys=list(keys))


# ===========================================================================
# Pure request / diff builders (no AWS calls)
# ===========================================================================

def _build_monitoring_configurations(monitoring: list) -> list:
    """Build the ContainerMonitoringConfigurations list from state.

    Each config becomes {'ClusterArn': ...} plus, only when it has filters,
    {'AttributeFilters': [{'Key', 'Value'}, ...]}. Empty filter lists omit the
    AttributeFilters key entirely (correct for ECS Fargate / no-filter configs).
    """
    configs = []
    for c in monitoring or []:
        entry = {'ClusterArn': c['cluster_arn']}
        filters = c.get('filters') or []
        if filters:
            entry['AttributeFilters'] = [
                {'Key': f['key'], 'Value': f['value']} for f in filters
            ]
        configs.append(entry)
    return configs


def build_create_request(state: dict) -> dict:
    """Build CreateContainerAssociation params from the in-memory add state.

    Omits AttributeFilters for configs with no filters, and omits Description
    and Tags when they are empty. Never calls AWS.

    Args:
        state: The add/edit state dict (see design Data Models). Requires
               'name', 'type', and 'monitoring'; optional 'description', 'tags'.

    Returns:
        Params dict suitable for create_container_association().
    """
    params = {
        'ContainerAssociationName': state['name'],
        'Type': state['type'],
        'ContainerMonitoringConfigurations': _build_monitoring_configurations(
            state.get('monitoring', [])
        ),
    }
    description = (state.get('description') or '').strip()
    if description:
        params['Description'] = description
    tags = state.get('tags') or {}
    if tags:
        params['Tags'] = [{'Key': k, 'Value': v} for k, v in tags.items()]
    return params


def build_update_request(state: dict, update_token: str) -> dict:
    """Build UpdateContainerAssociation params from the edit state.

    Type and name are immutable, so they are not changed here; the ARN and the
    UpdateToken (for optimistic concurrency) identify the target. Description is
    always included so it can be cleared (empty string) or set. Tags are applied
    separately via tag_resource/untag_resource, not through this call.

    Args:
        state: The edit state dict; requires 'arn', 'type', 'monitoring';
               optional 'description'.
        update_token: The UpdateToken captured from the describe response.

    Returns:
        Params dict suitable for update_container_association().
    """
    return {
        'ContainerAssociationArn': state['arn'],
        'Type': state['type'],
        'UpdateToken': update_token,
        'ContainerMonitoringConfigurations': _build_monitoring_configurations(
            state.get('monitoring', [])
        ),
        'Description': (state.get('description') or '').strip(),
    }


def _monitoring_as_map(monitoring: list) -> dict:
    """Index monitoring configs by cluster ARN, with filters as a {key: value} map.

    Note: this collapses multiple configs that share a cluster ARN and is only
    safe when each cluster appears once. The diff uses _config_signatures()
    instead so that multiple configurations on the same cluster (the AZ-OR
    pattern) are compared correctly.
    """
    result = {}
    for c in monitoring or []:
        filters = {f['key']: f['value'] for f in (c.get('filters') or [])}
        result[c['cluster_arn']] = filters
    return result


def _config_signature(cfg: dict) -> str:
    """Return a stable, human-readable signature for one monitoring configuration.

    Combines the cluster ARN with its (order-independent) set of key=value
    filters, so two configurations are 'the same' only when they target the
    same cluster AND carry the same filters. This lets the diff treat multiple
    configurations on the same cluster (each with different filters) as distinct
    units instead of collapsing them by cluster ARN.
    """
    cluster = cfg.get('cluster_arn', '')
    filters = sorted(f"{f.get('key','')}={f.get('value','')}"
                     for f in (cfg.get('filters') or []))
    return cluster + " || " + ", ".join(filters) if filters else cluster + " || (no filters)"


def _config_signatures(monitoring: list) -> list:
    """Return the list of (signature, cfg) pairs for a monitoring list."""
    return [(_config_signature(c), c) for c in (monitoring or [])]


def diff_association(loaded: dict, edited: dict) -> dict:
    """Compute a human-readable diff between the loaded and edited state.

    Used by the edit Review screen to show precisely what Deploy will change.
    Pure; never calls AWS.

    Args:
        loaded: Snapshot of the association as loaded (keys: description,
                monitoring, tags, share).
        edited: The current edited state (same keys).

    Returns:
        Dict describing changes:
          {
            'description': None | (old, new),
            'configs_added': [signature, ...],    # whole configurations added
            'configs_removed': [signature, ...],  # whole configurations removed
            'tags_added': [(k, v)], 'tags_removed': [k],
            'tags_changed': [(k, old, new)],
            'share': None | (old_desc, new_desc),
          }
        A configuration signature is 'cluster-arn || key=value, key=value' (or
        '... || (no filters)'). Editing a configuration's filters shows as one
        configuration removed and one added. Only changed sections are
        populated; unchanged fields are omitted so the caller renders only what
        differs.
    """
    diff = {}

    # Description
    old_desc = (loaded.get('description') or '').strip()
    new_desc = (edited.get('description') or '').strip()
    if old_desc != new_desc:
        diff['description'] = (old_desc, new_desc)

    # Monitoring configurations, compared as whole units (cluster + its filter
    # set). This correctly represents multiple configurations on the SAME
    # cluster with different filters (the AZ-OR pattern): adding "cluster/X with
    # AZ=2b" alongside an existing "cluster/X with AZ=2a" shows as an ADDED
    # configuration, not a filter change. Compared as multisets so duplicates
    # are handled.
    from collections import Counter
    old_sigs = Counter(sig for sig, _ in _config_signatures(loaded.get('monitoring', [])))
    new_pairs = _config_signatures(edited.get('monitoring', []))
    new_sigs = Counter(sig for sig, _ in new_pairs)

    added_sigs = new_sigs - old_sigs
    removed_sigs = old_sigs - new_sigs

    if added_sigs:
        diff['configs_added'] = sorted(added_sigs.elements())
    if removed_sigs:
        diff['configs_removed'] = sorted(removed_sigs.elements())

    # Tags
    old_tags = loaded.get('tags') or {}
    new_tags = edited.get('tags') or {}
    t_added = [(k, new_tags[k]) for k in new_tags if k not in old_tags]
    t_removed = [k for k in old_tags if k not in new_tags]
    t_changed = [(k, old_tags[k], new_tags[k])
                 for k in new_tags if k in old_tags and old_tags[k] != new_tags[k]]
    if t_added:
        diff['tags_added'] = sorted(t_added)
    if t_removed:
        diff['tags_removed'] = sorted(t_removed)
    if t_changed:
        diff['tags_changed'] = sorted(t_changed)

    # Sharing
    old_share = _describe_share(loaded.get('share'))
    new_share = _describe_share(edited.get('share'))
    if old_share != new_share:
        diff['share'] = (old_share, new_share)

    return diff


def _describe_share(share: Optional[dict]) -> str:
    """Render a share state ({'enabled': bool, 'account_id': str}) as text."""
    if not share or not share.get('enabled'):
        return 'not shared'
    account = share.get('account_id') or '(unspecified)'
    return f'share with {account}'


# ===========================================================================
# ECS / EKS cluster listing and ECS attribute discovery
# ===========================================================================

def list_ecs_clusters(ecs_client) -> list:
    """List ECS clusters (name + ARN) in the client's Region.

    ecs:ListClusters returns cluster ARNs; the name is derived from the ARN.
    Handles NextToken pagination.

    Args:
        ecs_client: A boto3 'ecs' client.

    Returns:
        List of {'name': str, 'arn': str} dicts.
    """
    clusters = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs['nextToken'] = next_token
        response = ecs_client.list_clusters(**kwargs)
        for arn in response.get('clusterArns', []):
            clusters.append({'name': arn.split('/')[-1], 'arn': arn})
        next_token = response.get('nextToken')
        if not next_token:
            break
    # Sort by name (case-insensitive) so the picker is easy to scan.
    clusters.sort(key=lambda c: c['name'].lower())
    return clusters


def discover_ecs_attributes(ecs_client, cluster_arn: str) -> list:
    """Discover container-instance attributes present on an ECS cluster.

    Lists the cluster's container instances then describes them, collecting the
    distinct attribute key/value pairs from attributes[]. Returns an empty list
    when the cluster has no container instances (e.g., scaled to zero) so the UI
    can fall back to free-form entry.

    Args:
        ecs_client: A boto3 'ecs' client.
        cluster_arn: The ECS cluster ARN.

    Returns:
        List of {'key': str, 'value': str} dicts, de-duplicated, sorted by key.
    """
    # Collect container-instance ARNs (paginated).
    instance_arns = []
    next_token = None
    while True:
        kwargs = {'cluster': cluster_arn}
        if next_token:
            kwargs['nextToken'] = next_token
        response = ecs_client.list_container_instances(**kwargs)
        instance_arns.extend(response.get('containerInstanceArns', []))
        next_token = response.get('nextToken')
        if not next_token:
            break

    if not instance_arns:
        return []

    # Describe in batches of 100 (AWS limit) and collect distinct attributes.
    seen = set()
    attributes = []
    for i in range(0, len(instance_arns), 100):
        batch = instance_arns[i:i + 100]
        response = ecs_client.describe_container_instances(
            cluster=cluster_arn, containerInstances=batch
        )
        for instance in response.get('containerInstances', []):
            for attr in instance.get('attributes', []):
                key = attr.get('name')
                value = attr.get('value', '')
                if not key:
                    continue
                # Only VALUED attributes are usable as container-association
                # filters: the AWS ContainerAttribute model requires a non-empty
                # Value (pattern \\S+). Capability flags (e.g.
                # com.amazonaws.ecs.capability.*) are presence-only with no
                # value and can never be a valid filter, so we drop them here
                # rather than presenting unusable choices.
                if not value or not value.strip():
                    continue
                dedup_key = (key, value)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                attributes.append({'key': key, 'value': value})

    attributes.sort(key=lambda a: (a['key'], a['value']))
    return attributes


def list_eks_clusters(eks_client) -> list:
    """List EKS cluster names in the client's Region.

    eks:ListClusters returns names only (not ARNs); resolve_eks_cluster_arn()
    obtains the ARN for a chosen cluster. Handles nextToken pagination.

    Args:
        eks_client: A boto3 'eks' client.

    Returns:
        List of cluster name strings.
    """
    names = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs['nextToken'] = next_token
        response = eks_client.list_clusters(**kwargs)
        names.extend(response.get('clusters', []))
        next_token = response.get('nextToken')
        if not next_token:
            break
    # Sort by name (case-insensitive) so the picker is easy to scan.
    names.sort(key=str.lower)
    return names


def resolve_eks_cluster_arn(eks_client, name: str) -> str:
    """Resolve an EKS cluster name to its ARN via eks:DescribeCluster.

    Args:
        eks_client: A boto3 'eks' client.
        name: The EKS cluster name.

    Returns:
        The cluster ARN string.
    """
    response = eks_client.describe_cluster(name=name)
    return response['cluster']['arn']


# ===========================================================================
# AWS RAM: sharing / unsharing and shared-with detection
# ===========================================================================

# Name used for the resource share this tool creates/manages, so it can be
# located again for subsequent associate/disassociate operations.
TOOL_RESOURCE_SHARE_NAME = 'SuricataGenerator-ContainerAssociations'


def _find_tool_resource_share(ram_client) -> Optional[dict]:
    """Return the tool-managed resource share (owned by SELF), or None."""
    next_token = None
    while True:
        kwargs = {
            'resourceOwner': 'SELF',
            'name': TOOL_RESOURCE_SHARE_NAME,
        }
        if next_token:
            kwargs['nextToken'] = next_token
        response = ram_client.get_resource_shares(**kwargs)
        shares = response.get('resourceShares', [])
        # Prefer an ACTIVE share if several match the name.
        active = [s for s in shares if s.get('status') == 'ACTIVE']
        if active:
            return active[0]
        if shares:
            return shares[0]
        next_token = response.get('nextToken')
        if not next_token:
            return None


def create_or_associate_share(ram_client, assoc_arn: str, account_id: str) -> dict:
    """Share a container association with a single account via AWS RAM.

    Reuses the tool-managed resource share if it exists (associating the
    association ARN and the target account to it); otherwise creates a new
    resource share named TOOL_RESOURCE_SHARE_NAME with the association and
    principal.

    Args:
        ram_client: A boto3 'ram' client.
        assoc_arn: The container association ARN to share.
        account_id: The 12-digit consumer account ID.

    Returns:
        The AWS response dict from the create or associate call.
    """
    existing = _find_tool_resource_share(ram_client)
    if existing:
        return ram_client.associate_resource_share(
            resourceShareArn=existing['resourceShareArn'],
            resourceArns=[assoc_arn],
            principals=[account_id],
        )
    return ram_client.create_resource_share(
        name=TOOL_RESOURCE_SHARE_NAME,
        resourceArns=[assoc_arn],
        principals=[account_id],
        allowExternalPrincipals=True,
    )


def disassociate_share(ram_client, assoc_arn: str, account_id: str) -> None:
    """Remove a container association's share to an account (tool-managed share).

    Disassociates the association ARN and/or the principal from the tool-managed
    resource share. No-op when the tool-managed share does not exist.

    Args:
        ram_client: A boto3 'ram' client.
        assoc_arn: The container association ARN to unshare.
        account_id: The consumer account ID to remove.
    """
    existing = _find_tool_resource_share(ram_client)
    if not existing:
        return
    ram_client.disassociate_resource_share(
        resourceShareArn=existing['resourceShareArn'],
        resourceArns=[assoc_arn],
        principals=[account_id],
    )


def disassociate_resource_from_shares(ram_client, assoc_arn: str) -> bool:
    """Remove an association resource from the tool-managed RAM share entirely.

    Used when the association is being deleted: detaching the resource from the
    share (by resource ARN, for all principals) prevents an orphaned/leaked
    resource-share association lingering in RAM after the association is gone.

    Args:
        ram_client: A boto3 'ram' client.
        assoc_arn: The container association ARN to detach from the share.

    Returns:
        True if a disassociation call was made, False if there was nothing to do
        (e.g., no tool-managed share exists). Raises on an actual RAM API error
        so the caller can report it.
    """
    existing = _find_tool_resource_share(ram_client)
    if not existing:
        return False
    ram_client.disassociate_resource_share(
        resourceShareArn=existing['resourceShareArn'],
        resourceArns=[assoc_arn],
    )
    return True


def get_shared_with(ram_client, assoc_arns: list) -> dict:
    """Map each association ARN to the principal(s) it is shared with.

    Walks the caller's owned RAM resource-share associations (resource side for
    the association ARNs, principal side for the consumer principals) and groups
    principals by association ARN. Returns only ARNs that are actually shared.

    Args:
        ram_client: A boto3 'ram' client.
        assoc_arns: The association ARNs to report on.

    Returns:
        Dict {assoc_arn: [principal, ...]} for shared associations. ARNs that
        are not shared are omitted (caller renders "Not shared").
    """
    arn_set = set(assoc_arns or [])
    if not arn_set:
        return {}

    # Map resource association ARN -> resourceShareArn (for the associations we care about).
    share_to_arns = {}   # resourceShareArn -> set(assoc_arn)
    next_token = None
    while True:
        kwargs = {
            'associationType': 'RESOURCE',
        }
        if next_token:
            kwargs['nextToken'] = next_token
        response = ram_client.get_resource_share_associations(**kwargs)
        for assoc in response.get('resourceShareAssociations', []):
            resource_arn = assoc.get('associatedEntity')
            share_arn = assoc.get('resourceShareArn')
            if resource_arn in arn_set and assoc.get('status') != 'DISASSOCIATED':
                share_to_arns.setdefault(share_arn, set()).add(resource_arn)
        next_token = response.get('nextToken')
        if not next_token:
            break

    if not share_to_arns:
        return {}

    # For each relevant share, collect its principal associations.
    result = {}
    next_token = None
    while True:
        kwargs = {
            'associationType': 'PRINCIPAL',
        }
        if next_token:
            kwargs['nextToken'] = next_token
        response = ram_client.get_resource_share_associations(**kwargs)
        for assoc in response.get('resourceShareAssociations', []):
            share_arn = assoc.get('resourceShareArn')
            principal = assoc.get('associatedEntity')
            if share_arn in share_to_arns and assoc.get('status') != 'DISASSOCIATED':
                for resource_arn in share_to_arns[share_arn]:
                    result.setdefault(resource_arn, [])
                    if principal not in result[resource_arn]:
                        result[resource_arn].append(principal)
        next_token = response.get('nextToken')
        if not next_token:
            break

    return result


def supports_container_associations(nfw_client) -> bool:
    """Return True if the boto3 network-firewall client exposes the container-
    association operations.

    Container associations were added to the AWS SDK in the botocore 1.43.x
    series. An older-but-installed boto3 has the client but not these methods,
    so `HAS_BOTO3` being True is not sufficient. Callers use this to show a
    clear "update boto3" message instead of a raw AttributeError.

    Args:
        nfw_client: A boto3 'network-firewall' client.

    Returns:
        True when list_container_associations is available on the client.
    """
    return hasattr(nfw_client, 'list_container_associations')


# Minimum botocore version that introduced the container-association APIs
# (used only for user-facing guidance messages).
MIN_BOTOCORE_VERSION = "1.43.62"


def ram_read_available(ram_client) -> bool:
    """Return True if the caller can read RAM resource-share associations.

    A lightweight probe used to drive the all-or-nothing greying of the
    "Shared with" column and share controls. Returns False on any AccessDenied
    or other error rather than raising.

    Args:
        ram_client: A boto3 'ram' client.

    Returns:
        True when a resource-share associations read succeeds, else False.
    """
    try:
        # Note: get_resource_share_associations does NOT accept resourceOwner
        # (that parameter belongs to get_resource_shares / list_resources).
        ram_client.get_resource_share_associations(
            associationType='RESOURCE', maxResults=1
        )
        return True
    except Exception:
        return False


# ===========================================================================
# Pre-flight validation (pure; no AWS calls) — Requirement 7a
# ===========================================================================

import re as _re
from src.core.constants import looks_like_cluster_arn, arn_region, arn_account

# Association name: ^[a-zA-Z0-9-]+$, length 1..128 (verified AWS constraint).
_NAME_RE = _re.compile(r'^[a-zA-Z0-9-]+$')

# AWS account id: exactly 12 digits.
_ACCOUNT_RE = _re.compile(r'^\d{12}$')

NAME_MAX = 128
DESCRIPTION_MAX = 512
MAX_MONITORING_CONFIGS = 5
TAG_KEY_MAX = 128
TAG_VALUE_MAX = 256


def validate_association_name(name: str) -> Optional[str]:
    """Return an error string if the association name is invalid, else None.

    Enforces the AWS pattern ^[a-zA-Z0-9-]+$ and length 1..128 (R6.3).
    """
    if not name:
        return "Name is required."
    if len(name) > NAME_MAX:
        return f"Name must be at most {NAME_MAX} characters."
    if not _NAME_RE.match(name):
        return "Name may contain only letters, numbers, and hyphens (a-z A-Z 0-9 -)."
    return None


def validate_description(description: str) -> Optional[str]:
    """Return an error string if the description is too long, else None (R9.1)."""
    if description and len(description) > DESCRIPTION_MAX:
        return f"Description must be at most {DESCRIPTION_MAX} characters."
    return None


def validate_account_id(account_id: str) -> Optional[str]:
    """Return an error string if the account id is not 12 digits, else None (R9.3)."""
    if not account_id or not _ACCOUNT_RE.match(account_id.strip()):
        return "Enter a valid 12-digit AWS account ID."
    return None


def validate_tags(tags: dict) -> Optional[str]:
    """Return an error string if any tag violates AWS constraints, else None (R9.2).

    Constraints: key 1..128 chars, value 0..256 chars, no 'aws:' reserved
    prefix on keys. (Keys are already unique by virtue of being dict keys.)
    """
    for key, value in (tags or {}).items():
        if not key or len(key) < 1 or len(key) > TAG_KEY_MAX:
            return f"Tag key '{key}' must be 1-{TAG_KEY_MAX} characters."
        if key.lower().startswith('aws:'):
            return f"Tag key '{key}' may not use the reserved 'aws:' prefix."
        if value is not None and len(value) > TAG_VALUE_MAX:
            return f"Tag value for '{key}' must be at most {TAG_VALUE_MAX} characters."
    return None


def preflight_validate(state: dict, existing_names=None) -> dict:
    """Validate an add/edit state before Review; return blocking errors + warnings.

    Blocking errors (R6.3, R7a.1, R9): missing/invalid name (create only),
    zero monitoring configurations, a config without a cluster, an over-long
    description, invalid tags, and (when sharing is enabled) an invalid account
    id. Non-blocking warnings (R7.7, R7a.2, R7a.3, R7a.4): name collision,
    cluster ARN wrong type/region/account (manual entry), and duplicate cluster
    across configurations.

    Args:
        state: The add/edit state dict.
        existing_names: Iterable of association names already present in the
            account/Region (for the create-time collision warning). Optional.

    Returns:
        {'errors': [str, ...], 'warnings': [str, ...]}. Empty 'errors' means the
        state may proceed to Review.
    """
    errors = []
    warnings = []
    mode = state.get('mode', 'create')
    ctype = state.get('type', '')

    # Name (immutable on edit, so only validated on create).
    if mode == 'create':
        name_err = validate_association_name(state.get('name', ''))
        if name_err:
            errors.append(name_err)
        elif existing_names and state.get('name') in set(existing_names):
            warnings.append(
                f"An association named '{state['name']}' already exists in this "
                f"account/Region. Names must be unique; AWS will reject a duplicate.")

    # Description.
    desc_err = validate_description(state.get('description', ''))
    if desc_err:
        errors.append(desc_err)

    # Tags.
    tag_err = validate_tags(state.get('tags', {}))
    if tag_err:
        errors.append(tag_err)

    # Sharing.
    share = state.get('share') or {}
    if share.get('enabled'):
        acct_err = validate_account_id(share.get('account_id', ''))
        if acct_err:
            errors.append(acct_err)

    # Monitoring configurations.
    monitoring = state.get('monitoring') or []
    if len(monitoring) == 0:
        errors.append("Add at least one monitoring configuration (a cluster).")
    if len(monitoring) > MAX_MONITORING_CONFIGS:
        errors.append(f"An association may have at most {MAX_MONITORING_CONFIGS} "
                      f"monitoring configurations.")

    seen_configs = {}   # full config signature -> [config indices]
    target_region = state.get('region')
    target_account = None  # account is not always known client-side; only warn on ARN mismatch pairs
    for idx, cfg in enumerate(monitoring, start=1):
        cluster_arn = (cfg.get('cluster_arn') or '').strip()
        if not cluster_arn:
            errors.append(f"Configuration {idx} has no cluster selected.")
            continue
        # Track truly-identical configurations (same cluster AND same filters).
        # Two configs on the same cluster with DIFFERENT filters are the intended
        # AZ-OR pattern and are NOT redundant, so we key on the full signature.
        seen_configs.setdefault(_config_signature(cfg), []).append(idx)
        # Shape/type/region warnings for cluster ARNs (R7a.3, R7a.4).
        if not looks_like_cluster_arn(cluster_arn, ctype):
            warnings.append(
                f"Configuration {idx}: '{cluster_arn}' does not look like an "
                f"{ctype} cluster ARN.")
        else:
            c_region = arn_region(cluster_arn)
            if target_region and c_region and c_region != target_region:
                warnings.append(
                    f"Configuration {idx}: cluster Region '{c_region}' differs from "
                    f"the association Region '{target_region}'. All cluster ARNs must "
                    f"be in the same Region and account as the association.")

        # Every attribute filter must have a non-empty Key AND Value: the AWS
        # ContainerAttribute model requires both (pattern \\S+). Catch it here
        # rather than letting AWS reject the request.
        key_values = {}   # key -> set of values (for same-key AND detection)
        for f in cfg.get('filters', []):
            key = (f.get('key') or '').strip()
            value = (f.get('value') or '').strip()
            if key and not value:
                errors.append(
                    f"Configuration {idx}: attribute filter '{key}' needs a value "
                    f"(both key and value are required).")
            elif value and not key:
                errors.append(
                    f"Configuration {idx}: an attribute filter has a value but no key "
                    f"(both key and value are required).")
            elif key and value:
                key_values.setdefault(key, set()).add(value)

        # Same key with multiple values in ONE configuration = an impossible AND
        # (a container can't have two different values for one attribute), so it
        # matches nothing. Warn and point to the OR-across-configs pattern (R8.9).
        for key, values in key_values.items():
            if len(values) > 1:
                vals = ", ".join(sorted(values))
                warnings.append(
                    f"Configuration {idx} filters on '{key}' with multiple values "
                    f"({vals}) in the same configuration. Filters within a "
                    f"configuration are combined with AND, so a container can't match "
                    f"more than one value for the same key \u2014 this matches nothing. "
                    f"To match ANY of these values, put each in its own configuration "
                    f"(configurations are combined with OR).")

        # Fargate / no-instances signal (ECS only): the config has attribute
        # filters, but attribute discovery ran successfully and found nothing on
        # this cluster. AWS attribute filters only match EC2 launch-type container
        # instances; Fargate tasks have no container instance attributes and are
        # never filtered. With no registered instances, the filters match nothing
        # right now. Non-blocking (the cluster may gain EC2 instances later), so
        # this is a warning, not an error. Only fires when discovery succeeded and
        # was empty (see _no_discovered_attrs) so a manual ARN or a failed
        # discovery never triggers it.
        if (ctype == 'ECS' and key_values and cfg.get('_no_discovered_attrs')):
            warnings.append(
                f"Configuration {idx} has attribute filters, but this cluster has "
                f"no registered EC2 container instances right now, so the filters "
                f"won't match anything at the moment. Attribute filters only match "
                f"EC2 launch-type container instances \u2014 Fargate tasks have no "
                f"attributes and are never filtered. To collect IPs from Fargate "
                f"tasks, use a configuration with no attribute filters.")

    for sig, idxs in seen_configs.items():
        if len(idxs) > 1:
            cluster = sig.split(" || ")[0]
            cluster_name = cluster.split('/')[-1] if '/' in cluster else cluster
            warnings.append(
                f"Configurations {', '.join(str(i) for i in idxs)} are identical "
                f"(same cluster '{cluster_name}' and same filters); the duplicate is "
                f"redundant. Two configurations on the same cluster are only useful "
                f"when their filters differ (for example, a different AZ).")

    return {'errors': errors, 'warnings': warnings}


# ===========================================================================
# Review-screen formatting (pure; no AWS calls)
# ===========================================================================

def format_create_summary_lines(state: dict) -> list:
    """Return human-readable summary lines for a create Review (R10.2)."""
    lines = []
    lines.append(f"Region:  {state.get('region', '')}")
    lines.append(f"Type:    {state.get('type', '')}")
    lines.append(f"Name:    {state.get('name', '')}")
    monitoring = state.get('monitoring', [])
    if len(monitoring) > 1:
        lines.append("Configurations (a container matches if it matches ANY configuration \u2014 OR):")
    else:
        lines.append("Configurations:")
    for i, cfg in enumerate(monitoring, start=1):
        if i > 1:
            lines.append("   \u2014 OR \u2014")
        filters = cfg.get('filters', [])
        # Only call out AND when a configuration actually has 2+ filters.
        and_note = "  (must match ALL of the following \u2014 AND)" if len(filters) > 1 else ""
        lines.append(f"   Configuration {i}: {cfg.get('cluster_arn', '(no cluster)')}{and_note}")
        for f in filters:
            lines.append(f"       {f['key']} = {f['value']}")
        if not filters:
            lines.append("       (no attribute filters)")
    desc = (state.get('description') or '').strip()
    lines.append(f"Description: {desc if desc else '(none)'}")
    tags = state.get('tags') or {}
    if tags:
        lines.append("Tags: " + ", ".join(f"{k}={v}" for k, v in tags.items()))
    else:
        lines.append("Tags: (none)")
    share = state.get('share') or {}
    if share.get('enabled'):
        lines.append(f"Sharing: share with {share.get('account_id', '')}")
    else:
        lines.append("Sharing: not shared")
    return lines


def format_monitoring_lines(monitoring: list) -> list:
    """Render monitoring configurations as read-only display lines.

    Each configuration shows its cluster ARN and its filters (indented). Filters
    within a configuration are AND'd; a '--or--' separator is inserted between
    configurations to make the OR-across-configurations semantics explicit.

    Args:
        monitoring: list of {'cluster_arn', 'filters': [{'key','value'}]}.

    Returns:
        List of text lines.
    """
    lines = []
    for i, cfg in enumerate(monitoring or []):
        if i > 0:
            lines.append("    --or--")
        lines.append(cfg.get('cluster_arn', '(no cluster)'))
        filters = cfg.get('filters', [])
        if filters:
            for f in filters:
                lines.append(f"    {f.get('key')} = {f.get('value')}")
        else:
            lines.append("    (no attribute filters)")
    return lines


def _pretty_config_signature(sig: str) -> str:
    """Render a config signature ('arn || filters') as 'cluster (filters)'."""
    cluster, _, filters = sig.partition(" || ")
    name = cluster.split('/')[-1] if '/' in cluster else cluster
    return f"{name} ({filters})"


def format_diff_lines(diff: dict) -> list:
    """Return human-readable 'what will change' lines for an edit Review (R10.3).

    Returns ['(no changes)'] when the diff is empty.
    """
    if not diff:
        return ["(no changes)"]
    lines = []
    if 'description' in diff:
        old, new = diff['description']
        lines.append(f"Description:  \"{old}\" \u2192 \"{new}\"")
    for sig in diff.get('configs_added', []):
        lines.append(f"+ Configuration: {_pretty_config_signature(sig)}")
    for sig in diff.get('configs_removed', []):
        lines.append(f"\u2212 Configuration: {_pretty_config_signature(sig)}")
    for k, v in diff.get('tags_added', []):
        lines.append(f"+ Tag {k}={v}")
    for k in diff.get('tags_removed', []):
        lines.append(f"\u2212 Tag {k}")
    for k, old, new in diff.get('tags_changed', []):
        lines.append(f"~ Tag {k}: {old} \u2192 {new}")
    if 'share' in diff:
        old, new = diff['share']
        lines.append(f"Sharing:  {old} \u2192 {new}")
    return lines


def shared_cell_text(owned: bool, ram_available: bool, principals=None) -> str:
    """Text for the landing table's "Shared with" cell.

    The value depends on both ownership and where the sharing data comes from:

    - RAM perms unavailable -> blank (we can't report sharing at all).
    - Not owned (the association is owned by another account and shared INTO
      this one) -> "Shared from another account". RAM only reports shares THIS
      account owns, so `principals` is empty for a shared-in row; reporting
      "Not shared" there would be misleading, since it clearly IS shared.
    - Owned -> the principal account id(s) it is shared with, or "Not shared"
      when there are none.

    Args:
        owned: Whether the current account owns the association.
        ram_available: Whether RAM sharing data could be read.
        principals: Account ids the association is shared with (owner's view).

    Returns:
        The cell text.
    """
    if not ram_available:
        return ''
    if not owned:
        return 'Shared from another account'
    principals = principals or []
    if not principals:
        return 'Not shared'
    if len(principals) == 1:
        return principals[0]
    return f"{principals[0]}  +{len(principals) - 1} more"
