"""
AWS commercial Regions — single source of truth for Region selectors.

Several AWS-integrated features in this application present a Region dropdown
(rule group import/export, traffic analysis, and the Container Association
Manager). Historically the same commercial-Region list was duplicated in
each of those call sites. This module provides one canonical list so a new
Region only needs to be added in a single place.

The list covers AWS standard commercial Regions only; it intentionally
excludes GovCloud (us-gov-*) and China (cn-*) partitions, matching the
behavior of the existing Import/Export Region selectors.
"""

# All AWS standard commercial Regions (excludes GovCloud and China partitions).
# Ordered by geography for a predictable dropdown; keep in sync with new
# commercial Region launches.
AWS_COMMERCIAL_REGIONS = [
    # US Regions
    'us-east-1',      # US East (N. Virginia)
    'us-east-2',      # US East (Ohio)
    'us-west-1',      # US West (N. California)
    'us-west-2',      # US West (Oregon)
    # Canada Regions
    'ca-central-1',   # Canada (Central)
    'ca-west-1',      # Canada (Calgary)
    # Europe Regions
    'eu-west-1',      # Europe (Ireland)
    'eu-west-2',      # Europe (London)
    'eu-west-3',      # Europe (Paris)
    'eu-central-1',   # Europe (Frankfurt)
    'eu-central-2',   # Europe (Zurich)
    'eu-north-1',     # Europe (Stockholm)
    'eu-south-1',     # Europe (Milan)
    'eu-south-2',     # Europe (Spain)
    # Asia Pacific Regions
    'ap-south-1',     # Asia Pacific (Mumbai)
    'ap-south-2',     # Asia Pacific (Hyderabad)
    'ap-southeast-1', # Asia Pacific (Singapore)
    'ap-southeast-2', # Asia Pacific (Sydney)
    'ap-southeast-3', # Asia Pacific (Jakarta)
    'ap-southeast-4', # Asia Pacific (Melbourne)
    'ap-northeast-1', # Asia Pacific (Tokyo)
    'ap-northeast-2', # Asia Pacific (Seoul)
    'ap-northeast-3', # Asia Pacific (Osaka)
    'ap-east-1',      # Asia Pacific (Hong Kong)
    # South America Regions
    'sa-east-1',      # South America (São Paulo)
    # Middle East Regions
    'me-south-1',     # Middle East (Bahrain)
    'me-central-1',   # Middle East (UAE)
    # Africa Regions
    'af-south-1',     # Africa (Cape Town)
    # Israel Regions
    'il-central-1',   # Israel (Tel Aviv)
]
