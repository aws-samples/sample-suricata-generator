"""
Traffic Analyzer - CloudWatch Log Analysis for Network Firewall

Analyzes AWS Network Firewall logs from CloudWatch to provide:
1. Traffic visibility (Top Talkers with hostname/SNI)
2. VPC endpoint cost optimization recommendations
3. Internet vs AWS service vs VPC-to-VPC traffic breakdown

Author: Suricata Generator Team
Created: 2026-01-25
"""

import calendar
import ipaddress
import re
import threading
import time
import json
import os
from datetime import datetime, timedelta, date, timezone
from collections import defaultdict
from typing import Dict, List, Optional, Callable, Any

from src.aws.aws_service_detector import AWSServiceDetector


class TrafficAnalyzer:
    """Main class for traffic analysis and VPC endpoint recommendations"""
    
    # Maximum wall-clock time to wait for a single CloudWatch Logs Insights query
    # to reach a terminal state before giving up. This is a safety net against a
    # query that never returns a terminal status (e.g. stuck in Running); CloudWatch
    # normally returns a 'Timeout' status on its own, which is also handled. Kept
    # generous so a legitimately large server-side aggregation is not aborted early.
    MAX_QUERY_SECONDS = 900

    # Maximum number of flow-breakdown chunk queries run concurrently. CloudWatch
    # Logs Insights allows 30 concurrent queries per account/region by default, and
    # that quota is shared with anything else running in the account, so stay well
    # below it. Set to 1 to run strictly sequentially (the original behavior).
    MAX_PARALLEL_QUERIES = 8

    # Poll interval for a running query: starts short (small queries finish in a
    # second or two) and backs off to the cap to avoid hammering GetQueryResults.
    POLL_INITIAL_SECONDS = 0.5
    POLL_MAX_SECONDS = 2.0
    POLL_BACKOFF_FACTOR = 1.5

    # Retry budget for throttled / concurrency-limited CloudWatch Logs API calls.
    MAX_THROTTLE_RETRIES = 6
    _THROTTLE_ERROR_NAMES = ('ThrottlingException', 'LimitExceededException',
                             'TooManyRequestsException', 'RequestLimitExceeded',
                             'Throttling')

    # Chunk-size calibration. After the first chunk, the observed ratio of returned
    # groups to matched records is used to re-plan the remaining chunks only when
    # groups are clearly fewer than records (ratio below the threshold). Bursty
    # traffic that overshoots is still handled by the adaptive bisection.
    CALIBRATION_RATIO_THRESHOLD = 0.8
    CALIBRATED_GROUPS_PER_CHUNK = 7000
    CALIBRATION_MAX_REDUCTION = 4  # never plan fewer than 1/4 of the original chunks

    # Target netflow records per flow-breakdown chunk (under the 10K result cap).
    SAFE_CHUNK_ROWS = 9000

    # Record-density histogram used to plan chunks: finest bin width, and the most
    # bins one query may return (kept under the 10K result cap).
    HISTOGRAM_MIN_BIN_SECONDS = 300
    HISTOGRAM_MAX_BINS = 9000

    # Overall-progress steps shown in the progress dialog: (key, label, share of
    # the overall bar). Shares are rough expected proportions of the run time;
    # the flow breakdown dominates on large windows.
    ANALYSIS_STEPS = (
        ('totals', 'Querying traffic totals', 0.03),
        ('flows', 'Querying flow breakdown', 0.70),
        ('alerts', 'Querying alert logs', 0.12),
        ('correlate', 'Correlating flows and hostnames', 0.12),
        ('aggregate', 'Aggregating results', 0.03),
    )
    
    # CloudWatch Logs Insights query statuses that mean "done" (stop polling).
    # Includes Timeout/Unknown so a query in those states does not poll forever.
    _TERMINAL_QUERY_STATUSES = ('Complete', 'Failed', 'Cancelled', 'Timeout', 'Unknown')
    
    # AWS Network Firewall data processing costs by region (per GB).
    # Source: AWS Price List API (ServiceCode AWSNetworkFirewall, usagetype
    # '<region>-Traffic-GB-Processed'; the Transit Gateway attachment rate is the
    # same), validated 2026-11-16 (pricing effective 2026-09-01). Nearly all regions are $0.065/GB;
    # a few carry a premium. GB here is binary (1 GB = 1024^3 bytes), matching how
    # AWS meters Network Firewall data processing.
    FIREWALL_PRICING = {
        'af-south-1': 0.065,
        'ap-east-1': 0.065,
        'ap-east-2': 0.065,
        'ap-northeast-1': 0.065,
        'ap-northeast-2': 0.065,
        'ap-northeast-3': 0.065,
        'ap-south-1': 0.065,
        'ap-south-2': 0.065,
        'ap-southeast-1': 0.065,
        'ap-southeast-2': 0.065,
        'ap-southeast-3': 0.075,
        'ap-southeast-4': 0.065,
        'ap-southeast-5': 0.065,
        'ap-southeast-6': 0.065,
        'ap-southeast-7': 0.065,
        'ca-central-1': 0.065,
        'ca-west-1': 0.065,
        'eu-central-1': 0.065,
        'eu-central-2': 0.075,
        'eu-north-1': 0.065,
        'eu-south-1': 0.065,
        'eu-south-2': 0.065,
        'eu-west-1': 0.065,
        'eu-west-2': 0.065,
        'eu-west-3': 0.065,
        'il-central-1': 0.065,
        'me-central-1': 0.065,
        'me-south-1': 0.065,
        'mx-central-1': 0.065,
        'sa-east-1': 0.065,
        'us-east-1': 0.065,
        'us-east-2': 0.065,
        'us-gov-east-1': 0.078,
        'us-gov-west-1': 0.078,
        'us-west-1': 0.065,
        'us-west-2': 0.065,
    }
    
    # VPC Interface (PrivateLink) endpoint costs by region (per month).
    # Source: AWS Price List API (ServiceCode AmazonVPC, usagetype
    # '<region>-VpcEndpoint-Hours'), validated 2026-11-16 (pricing effective 2026-11-01).
    # Calculation: hourly_rate x 730 hours/month (rounded to cents).
    INTERFACE_ENDPOINT_PRICING = {
        'af-south-1': 9.56,      # $0.01309/hour
        'ap-east-1': 10.44,      # $0.0143/hour
        'ap-east-2': 9.20,       # $0.0126/hour
        'ap-northeast-1': 10.22, # $0.014/hour
        'ap-northeast-2': 9.49,  # $0.013/hour
        'ap-northeast-3': 10.22, # $0.014/hour
        'ap-south-1': 9.49,      # $0.013/hour
        'ap-south-2': 9.49,      # $0.013/hour
        'ap-southeast-1': 9.49,  # $0.013/hour
        'ap-southeast-2': 9.49,  # $0.013/hour
        'ap-southeast-3': 9.49,  # $0.013/hour
        'ap-southeast-4': 9.49,  # $0.013/hour
        'ap-southeast-5': 8.54,  # $0.0117/hour
        'ap-southeast-6': 9.96,  # $0.01365/hour
        'ap-southeast-7': 8.54,  # $0.0117/hour
        'ca-central-1': 8.03,    # $0.011/hour
        'ca-west-1': 8.03,       # $0.011/hour
        'eu-central-1': 8.76,    # $0.012/hour
        'eu-central-2': 9.64,    # $0.0132/hour
        'eu-north-1': 7.67,      # $0.0105/hour
        'eu-south-1': 8.43,      # $0.01155/hour
        'eu-south-2': 8.03,      # $0.011/hour
        'eu-west-1': 8.03,       # $0.011/hour
        'eu-west-2': 8.03,       # $0.011/hour
        'eu-west-3': 8.03,       # $0.011/hour
        'il-central-1': 8.43,    # $0.01155/hour
        'me-central-1': 8.83,    # $0.0121/hour
        'me-south-1': 8.83,      # $0.0121/hour
        'mx-central-1': 7.67,    # $0.0105/hour
        'sa-east-1': 15.33,      # $0.021/hour
        'us-east-1': 7.30,       # $0.01/hour
        'us-east-2': 7.30,       # $0.01/hour
        'us-gov-east-1': 9.12,   # $0.0125/hour
        'us-gov-west-1': 9.12,   # $0.0125/hour
        'us-west-1': 8.03,       # $0.011/hour
        'us-west-2': 7.30,       # $0.01/hour
    }
    
    # Interface endpoint data processing, first tier (up to 1 PB/month). Source:
    # AWS Price List API (ServiceCode AmazonVPC, usagetype
    # '<region>-VpcEndpoint-Bytes'), validated 2026-11-16: $0.01/GB in every
    # region in these tables.
    INTERFACE_ENDPOINT_DATA_COST_PER_GB = 0.01

    # CloudWatch Logs Insights query cost by region (per GB scanned).
    # Source: AWS Price List API (ServiceCode AmazonCloudWatch, operation
    # StartQuery, usagetype '<region>-DataScanned-Bytes', group "Queried Logs"),
    # validated 2026-11-16 (pricing effective 2026-11-01). This is the usage type
    # these queries are billed under (confirmed on a real bill); the separate
    # '<region>-Omni-DataScanned-Bytes' price is a different product. The
    # account-level monthly free tier (first 5 GB scanned) is not modeled.
    CLOUDWATCH_LOGS_INSIGHTS_PRICING = {
        'af-south-1': 0.0068,
        'ap-east-1': 0.008,
        'ap-east-2': 0.005,
        'ap-northeast-1': 0.0076,
        'ap-northeast-2': 0.0076,
        'ap-northeast-3': 0.0076,
        'ap-south-1': 0.0067,
        'ap-south-2': 0.0067,
        'ap-southeast-1': 0.007,
        'ap-southeast-2': 0.0067,
        'ap-southeast-3': 0.007,
        'ap-southeast-4': 0.0067,
        'ap-southeast-5': 0.005,
        'ap-southeast-6': 0.005,
        'ap-southeast-7': 0.005,
        'ca-central-1': 0.0055,
        'ca-west-1': 0.0055,
        'eu-central-1': 0.0063,
        'eu-central-2': 0.0069,
        'eu-north-1': 0.0054,
        'eu-south-1': 0.006,
        'eu-south-2': 0.0057,
        'eu-west-1': 0.0057,
        'eu-west-2': 0.0059,
        'eu-west-3': 0.0059,
        'il-central-1': 0.005,
        'me-central-1': 0.0063,
        'me-south-1': 0.0063,
        'mx-central-1': 0.005,
        'sa-east-1': 0.009,
        'us-east-1': 0.005,
        'us-east-2': 0.005,
        'us-gov-east-1': 0.00675,
        'us-gov-west-1': 0.00675,
        'us-west-1': 0.0067,
        'us-west-2': 0.005,
    }
    
    # AWS Network Firewall endpoint (hourly) costs by region
    # AWS Network Firewall standard PRIMARY endpoint hourly cost by region.
    # Source: AWS Price List API (ServiceCode AWSNetworkFirewall, usagetype
    # '<region>-Endpoint-Hour'), validated 2026-11-16 (pricing effective
    # 2026-09-01). Most regions are $0.395/hr; newer/edge regions carry a premium.
    # Note: this is the PRIMARY endpoint rate; secondary endpoints and Advanced
    # Inspection (TLS) endpoint hours use different rates and are not modeled here.
    ENDPOINT_HOURLY_PRICING = {
        'af-south-1': 0.395,
        'ap-east-1': 0.395,
        'ap-east-2': 0.66,
        'ap-northeast-1': 0.395,
        'ap-northeast-2': 0.395,
        'ap-northeast-3': 0.395,
        'ap-south-1': 0.395,
        'ap-south-2': 0.535,
        'ap-southeast-1': 0.395,
        'ap-southeast-2': 0.395,
        'ap-southeast-3': 0.485,
        'ap-southeast-4': 0.705,
        'ap-southeast-5': 0.66,
        'ap-southeast-6': 0.705,
        'ap-southeast-7': 0.66,
        'ca-central-1': 0.395,
        'ca-west-1': 0.705,
        'eu-central-1': 0.395,
        'eu-central-2': 1.075,
        'eu-north-1': 0.395,
        'eu-south-1': 0.395,
        'eu-south-2': 0.395,
        'eu-west-1': 0.395,
        'eu-west-2': 0.395,
        'eu-west-3': 0.395,
        'il-central-1': 0.565,
        'me-central-1': 0.415,
        'me-south-1': 0.395,
        'mx-central-1': 0.585,
        'sa-east-1': 0.395,
        'us-east-1': 0.395,
        'us-east-2': 0.395,
        'us-gov-east-1': 0.474,
        'us-gov-west-1': 0.474,
        'us-west-1': 0.395,
        'us-west-2': 0.395,
    }
    
    def __init__(self, log_group: str, region: str, days: Optional[int] = None, 
                 alert_log_group: Optional[str] = None,
                 start_date: Optional[date] = None,
                 end_date: Optional[date] = None,
                 aws_session=None):
        """Initialize traffic analyzer
        
        Args:
            log_group: CloudWatch log group name for flow logs
            region: AWS region
            days: Number of days to analyze (7-90) - DEPRECATED if start_date/end_date provided
            alert_log_group: Optional separate log group for alert logs. If not provided,
                           will attempt to auto-detect by replacing "Flow" with "Alert"
            start_date: Optional custom start date (overrides days parameter)
            end_date: Optional custom end date (overrides days parameter)
            aws_session: Optional AWSSessionManager instance for centralized credential management
        """
        self.log_group = log_group
        self.region = region
        self.cancel_requested = False

        # Number of CloudWatch Logs API calls retried because of throttling or the
        # concurrent-query limit (shown in the progress dialog). Incremented from
        # worker threads, hence the lock.
        self.throttle_retries = 0
        self._throttle_lock = threading.Lock()
        # Highest overall-progress percentage reported so far (never decreases).
        self._overall_percent = 0.0
        
        # Determine time range
        if start_date and end_date:
            # Custom date range mode.
            # The query window treats end_date as INCLUSIVE through the end of that
            # day (see _get_query_window: end is end_date @ 23:59:59). So a range of
            # start_date..end_date spans (delta + 1) calendar days, not delta. e.g.
            # 08-19..08-20 is TWO days (48h), not one. self.days must reflect that so
            # 'time_range_days' and the runtime-hours fallback stay consistent with
            # the window actually queried.
            self.start_date = start_date
            self.end_date = end_date
            self.days = (end_date - start_date).days + 1
            self.use_custom_dates = True
        else:
            # Legacy days mode (backward compatible)
            self.days = days or 30
            self.end_date = datetime.now().date()
            self.start_date = self.end_date - timedelta(days=self.days)
            self.use_custom_dates = False
        
        # Get region-specific pricing with fallback to us-east-1 rates.
        self.firewall_cost_per_gb = self.FIREWALL_PRICING.get(region, 0.065)
        self.interface_endpoint_monthly_cost = self.INTERFACE_ENDPOINT_PRICING.get(region, 7.30)
        self.endpoint_hourly_rate = self.ENDPOINT_HOURLY_PRICING.get(region, 0.395)
        self.cloudwatch_price_per_gb = self.CLOUDWATCH_LOGS_INSIGHTS_PRICING.get(region, 0.005)
        
        # Track whether ANY pricing table lacked this region, so results can be
        # flagged. When true, the figures use us-east-1 fallback rates and may not
        # reflect the region's real (often higher) pricing.
        self.pricing_fallback = (
            region not in self.FIREWALL_PRICING
            or region not in self.ENDPOINT_HOURLY_PRICING
            or region not in self.INTERFACE_ENDPOINT_PRICING
            or region not in self.CLOUDWATCH_LOGS_INSIGHTS_PRICING
        )
        
        # Calculate break-even thresholds for this region
        self.same_region_break_even = int(
            self.interface_endpoint_monthly_cost / self.firewall_cost_per_gb
        )
        self.cross_region_break_even = int(
            self.interface_endpoint_monthly_cost / 
            (self.firewall_cost_per_gb - self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
        )
        
        # Warn if using fallback pricing (unknown region)
        if self.pricing_fallback:
            print(f"⚠️  Warning: Region '{region}' not in the pricing tables. "
                  f"Using US-East-1 fallback rates (${self.firewall_cost_per_gb}/GB data, "
                  f"${self.endpoint_hourly_rate}/hr endpoint). Actual costs may vary.")
        
        # Auto-detect alert log group if not provided
        if alert_log_group:
            self.alert_log_group = alert_log_group
        else:
            # Try common naming patterns
            if 'Flow' in log_group:
                self.alert_log_group = log_group.replace('Flow', 'Alert')
            elif 'flow' in log_group:
                self.alert_log_group = log_group.replace('flow', 'alert')
            else:
                # Fall back to same log group (legacy behavior)
                self.alert_log_group = log_group
        
        # Initialize AWS clients
        if aws_session:
            self.logs_client = aws_session.get_client('logs', region_name=region)
        else:
            import boto3
            self.logs_client = boto3.client('logs', region_name=region)
        
        # Initialize AWS service detector (downloads IP ranges and builds trees)
        self.aws_service_detector = AWSServiceDetector()
    
    def cancel_analysis(self):
        """User requested cancellation"""
        self.cancel_requested = True
    
    def _get_query_window(self) -> tuple:
        """Return the (start_time, end_time) datetimes for all CloudWatch queries.

        Single source of truth for the analysis window so that the raw per-flow
        query, the authoritative totals aggregation, the record-count sizing, and
        the alert query all cover the EXACT same range. Any drift between them
        would make the totals and the breakdowns disagree.

        Custom-date mode: [start_date 00:00:00, end_date 23:59:59.999999] - end_date
        is inclusive through the end of that day (so start==end is a single full
        day, and 08-19..08-20 is two full days). Naive datetimes are interpreted in
        the host's local timezone by .timestamp(), matching the local dates shown in
        the date picker (log @timestamps themselves are UTC).

        Legacy days mode: a rolling window of the last `self.days` * 24 hours ending
        now.

        Returns:
            Tuple of (start_time: datetime, end_time: datetime)
        """
        if self.use_custom_dates:
            start_time = datetime.combine(self.start_date, datetime.min.time())
            end_time = datetime.combine(self.end_date, datetime.max.time())
        else:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=self.days)
        return (start_time, end_time)
    
    def query_flow_totals(self, progress_callback: Optional[Callable] = None) -> tuple:
        """Query authoritative traffic totals using server-side aggregation.

        CRITICAL: This is the source of truth for volumetric figures (total bytes
        and per-AZ bytes). It uses a CloudWatch Logs Insights `stats sum() by ...`
        query, so the 10,000-row result limit applies to the number of returned
        *aggregate* rows (one per
        Availability Zone) rather than the number of underlying netflow records,
        so the totals cannot be truncated by high traffic volume.

        The sum is taken over every netflow record in range. Because Suricata
        emits one netflow record per direction (to-server always, to-client when
        response packets are seen) and each carries that direction's byte count,
        summing all records yields the correct bidirectional processed-byte total
        for the firewall - the same quantity the per-flow path computes by grouping
        on flow_id, but without the row-limit truncation.

        This query also returns the total netflow RECORD count, which
        query_flow_grouped() uses to size its time-chunking in a single pass.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            Tuple of (total_bytes, az_bytes, bytes_scanned, total_records) where:
              - total_bytes (int): authoritative total netflow bytes in range
              - az_bytes (Dict[str, int]): bytes per availability_zone
              - bytes_scanned (int): bytes scanned by this query (for query cost)
              - total_records (int): number of netflow records in range (for chunk sizing)
            Returns (None, None, None, None) if cancelled.
        """
        if self.cancel_requested:
            return (None, None, None, None)

        # Use the shared window helper so this aggregation covers the EXACT same
        # range as the raw per-flow and alert queries.
        start_time, end_time = self._get_query_window()

        # Aggregate bytes AND record count server-side, grouped by AZ (low
        # cardinality => never hits the 10K row limit). Grouping by AZ also gives us
        # the per-AZ distribution needed for endpoint cost attribution.
        query = """
        fields availability_zone, event.netflow.bytes
        | filter event.event_type = "netflow"
        | stats sum(event.netflow.bytes) as total_bytes, count(*) as rec_count by availability_zone
        """

        if progress_callback:
            progress_callback({
                'stage': 'Querying traffic totals',
                'status': 'Aggregating processed bytes (authoritative total)...'
            })

        try:
            response = self._call_logs_api(self.logs_client.start_query,
                logGroupName=self.log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
        except Exception as e:
            error_str = str(e)
            if "ResourceNotFoundException" in error_str or "ResourceNotFound" in error_str:
                raise Exception(f"FLOW log group not found: '{self.log_group}'. Please verify the name and region.")
            elif "MalformedQueryException" in error_str and ("creation time" in error_str or "before" in error_str.lower()):
                # Query range predates log group creation - no data for this range.
                return (0, {}, 0, 0)
            else:
                raise Exception(f"Failed to start flow totals query on '{self.log_group}': {error_str}")

        query_id = response['queryId']

        start_query_time = time.time()
        while True:
            if self.cancel_requested:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except:
                    pass
                return (None, None, None, None)

            result = self._call_logs_api(self.logs_client.get_query_results, queryId=query_id)
            status = result['status']

            if status in self._TERMINAL_QUERY_STATUSES:
                break

            # Wall-clock safety net: fail loudly instead of hanging if the query
            # never reaches a terminal state.
            elapsed = time.time() - start_query_time
            if elapsed > self.MAX_QUERY_SECONDS:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except:
                    pass
                raise Exception(f"Flow totals query timed out after {int(elapsed)}s "
                                f"waiting for CloudWatch Logs Insights (status '{status}').")

            if progress_callback:
                progress_callback({
                    'stage': 'Querying traffic totals',
                    'status': f'Aggregation running... ({int(elapsed)}s elapsed)'
                })

            time.sleep(2)

        if status != 'Complete':
            raise Exception(f"Flow totals query {status.lower()}: {result.get('statistics', {})}")

        records = result.get('results', [])
        statistics = result.get('statistics', {})
        bytes_scanned = statistics.get('bytesScanned', 0)

        az_bytes = {}
        total_bytes = 0
        total_records = 0
        for row in records:
            az = self._get_field_value(row, 'availability_zone')
            bytes_str = self._get_field_value(row, 'total_bytes')
            count_str = self._get_field_value(row, 'rec_count')
            try:
                # stats sum() may return a numeric string (e.g. "12345" or "1.2E7")
                row_bytes = int(float(bytes_str)) if bytes_str else 0
            except (ValueError, TypeError):
                row_bytes = 0
            try:
                row_count = int(float(count_str)) if count_str else 0
            except (ValueError, TypeError):
                row_count = 0
            total_bytes += row_bytes
            total_records += row_count
            # availability_zone may be absent on some records; bucket under '' so
            # the grand total still reflects those bytes even if unattributed.
            az_bytes[az if az else ''] = az_bytes.get(az if az else '', 0) + row_bytes

        if progress_callback:
            progress_callback({
                'stage': 'Querying traffic totals',
                'status': f'Authoritative total: {total_bytes / (1024**3):.2f} GB '
                          f'across {len(az_bytes)} AZ(s), {total_records:,} records'
            })

        return (total_bytes, az_bytes, bytes_scanned, total_records)

    # Fields returned by the grouped per-flow aggregation, in query order.
    _GROUPED_QUERY = """
        fields event.flow_id, event.src_ip, event.dest_ip, event.src_port, event.dest_port,
               event.proto, event.app_proto, availability_zone, event.netflow.bytes, @timestamp
        | filter event.event_type = "netflow"
        | stats sum(event.netflow.bytes) as bytes, count(*) as recs,
                min(@timestamp) as first_ts, max(@timestamp) as last_ts
          by event.flow_id, event.src_ip, event.dest_ip, event.src_port, event.dest_port,
             event.proto, event.app_proto, availability_zone
        """

    def query_flow_grouped(self, expected_records: Optional[int] = None,
                           progress_callback: Optional[Callable] = None) -> tuple:
        """Retrieve per-flow byte totals via server-side aggregation (truncation-proof).

        Replaces the old raw per-flow row retrieval. Instead of pulling individual
        netflow rows (capped at 10,000/query and thus a *sample* on busy firewalls),
        this sums bytes server-side grouped by the flow's identifying dimensions:

            stats sum(bytes), count(*), min/max(@timestamp)
              by flow_id, src_ip, dest_ip, src_port, dest_port, proto, app_proto, az

        Each returned row is one directional leg of a flow (the two Suricata
        directional netflow records collapse into two rows sharing a flow_id, with
        swapped src/dest). correlate_logs re-joins them by flow_id and applies the
        same direction/port collapse as before, so the downstream breakdowns are
        byte-accurate at ANY volume while keeping full hostname/service enrichment.

        The 10,000-row limit now applies to the number of returned GROUPS. Group
        cardinality (distinct flow legs) is far lower than raw record count but can
        still be large, so we reuse the count-seeded time chunking and adaptive
        bisection; groups are merged across chunks by their full key. Only if a
        <=60s window still exceeds the group cap is the result flagged partial (the
        authoritative totals from query_flow_totals remain exact regardless).

        Args:
            expected_records: Total netflow record count (from query_flow_totals),
                used to size chunking. Groups are fewer than records, so this is a
                conservative (safe) upper bound for chunk sizing.
            progress_callback: Optional progress callback.

        Returns:
            Tuple of (grouped_rows, bytes_scanned, truncated) where grouped_rows is a
            list of dicts with keys: flow_id, src_ip, dest_ip, src_port, dest_port,
            proto, app_proto, az, bytes, recs, first_ts, last_ts.
            Returns (None, None, None) if cancelled.
        """
        if self.cancel_requested:
            return (None, None, None)

        start_time, end_time = self._get_query_window()

        # Keep each chunk's returned GROUP count under the 10K cap. Groups are a
        # fraction of raw records, so sizing by record count is conservative.
        SAFE_CHUNK_ROWS = self.SAFE_CHUNK_ROWS

        if not expected_records or expected_records <= SAFE_CHUNK_ROWS:
            rows, scanned, truncated = self._query_grouped_range_adaptive(
                start_time, end_time, progress_callback
            )
            if self.cancel_requested:
                return (None, None, None)
            return (rows, scanned, truncated)

        # Plan the chunks from where the records actually are (a per-time-bin
        # record count). This skips empty stretches and sizes busy periods small,
        # so fewer queries are needed and fewer chunks overflow and get bisected.
        # The plan always covers the whole window, so accuracy does not depend on
        # it; if the histogram is unavailable or disagrees with the record count,
        # fall back to evenly sized time chunks.
        if progress_callback:
            progress_callback({
                'stage': 'Querying flow breakdown',
                'status': 'Measuring where records are in the time window...',
            })
        histogram = self._query_record_histogram(start_time, end_time, progress_callback)
        if self.cancel_requested:
            return (None, None, None)

        histogram_scanned = 0
        bounds = None
        if histogram is not None:
            bins, bin_seconds, histogram_scanned = histogram
            hist_total = sum(c for _, c in bins)
            if hist_total > 0 and abs(hist_total - expected_records) <= 0.1 * expected_records:
                bounds = self._bounds_from_histogram(bins, bin_seconds, start_time,
                                                     end_time, SAFE_CHUNK_ROWS)
            else:
                histogram = None
        if bounds is None:
            num_chunks = max(1, -(-expected_records // SAFE_CHUNK_ROWS))  # ceil division
            bounds = self._plan_chunks(start_time, end_time, num_chunks)
        return self._query_chunked(
            bounds, histogram, expected_records, end_time,
            lambda s, e, cb: self._query_grouped_range_adaptive(s, e, cb),
            self._merge_flow_rows, self._FLOW_CHUNK_LABELS,
            histogram_scanned, progress_callback)

    # Progress labels for the flow-breakdown chunk phase (unchanged wording).
    _FLOW_CHUNK_LABELS = {
        'stage': 'Querying flow breakdown',
        'chunk_stage': 'Querying flow breakdown (chunked)',
        'phase': 'flow_chunks',
        'chunk_label': 'Flow logs',
        'start_status': 'Aggregating per-flow bytes in {n} chunks...',
        'done_status': 'Aggregated {rows:,} flow legs from {n} chunks',
        'truncated_note': ' (breakdown sampled; totals unaffected)',
    }

    @staticmethod
    def _merge_flow_rows(results: list) -> list:
        """Merge per-chunk flow-leg groups by their full identifying key.

        bytes/recs are additive; timestamps take the min/max across chunks. A
        flow_id is time-local so this cannot mis-merge distinct flows.
        """
        merged = {}
        for chunk_rows, _, _ in results:
            for r in chunk_rows:
                key = (r['flow_id'], r['src_ip'], r['dest_ip'], r['src_port'],
                       r['dest_port'], r['proto'], r['app_proto'], r['az'])
                if key in merged:
                    m = merged[key]
                    m['bytes'] += r['bytes']
                    m['recs'] += r['recs']
                    if r['first_ts'] and (not m['first_ts'] or r['first_ts'] < m['first_ts']):
                        m['first_ts'] = r['first_ts']
                    if r['last_ts'] and (not m['last_ts'] or r['last_ts'] > m['last_ts']):
                        m['last_ts'] = r['last_ts']
                else:
                    merged[key] = dict(r)
        return list(merged.values())

    def _query_chunked(self, bounds: list, histogram, expected_records: int,
                       end_time: datetime, run_range: Callable, merge_rows: Callable,
                       labels: Dict[str, str], extra_scanned: int,
                       progress_callback: Optional[Callable]) -> tuple:
        """Run a grouped query over planned chunks and merge the results.

        Shared by the flow breakdown and the alert hostname query. Chunk 0 runs
        first and is used to recalibrate the remaining chunk sizes; the rest run
        in parallel (MAX_PARALLEL_QUERIES). Results are merged in chunk order, so
        the output does not depend on the order in which queries finish.

        Args:
            bounds: Planned (start, end) chunk ranges covering the window.
            histogram: (bins, bin_seconds, scanned) used for the plan, or None if
                the plan is the even split.
            expected_records: Record count used for the even-split recalibration.
            end_time: Window end.
            run_range: (start, end, progress_callback) -> (rows, scanned, truncated).
            merge_rows: list of per-chunk results -> merged rows.
            labels: Progress wording (see _FLOW_CHUNK_LABELS).
            extra_scanned: Bytes scanned by planning queries (billed too).
            progress_callback: Optional progress callback.

        Returns:
            (rows, bytes_scanned, truncated), or (None, None, None) if cancelled.
        """
        num_chunks = len(bounds)

        def emit(current, total, status):
            if progress_callback:
                progress_callback({
                    'stage': labels['chunk_stage'],
                    'status': status,
                    'phase': labels['phase'],
                    'chunk_label': labels['chunk_label'],
                    'chunk_current': current,
                    'chunk_total': total,
                })

        if progress_callback:
            progress_callback({
                'stage': labels['stage'],
                'status': labels['start_status'].format(n=num_chunks),
                'phase': labels['phase'],
                'chunk_label': labels['chunk_label'],
                'chunk_current': 0,
                'chunk_total': num_chunks,
            })

        # results[i] = (rows, bytes_scanned, truncated) for chunk i.
        results = [None] * len(bounds)

        # Chunk 0 runs alone first. Besides being a normal chunk, it measures how
        # many groups the data really produces per matched record, which lets the
        # remaining chunks be sized more accurately (see _recalibrate_chunks).
        emit(0, len(bounds), f'Chunk 1/{len(bounds)}...')
        first = run_range(bounds[0][0], bounds[0][1], progress_callback)
        if self.cancel_requested:
            return (None, None, None)
        results[0] = first

        if histogram is not None:
            bins, bin_seconds, _ = histogram
            new_bounds = self._recalibrate_from_histogram(first[0], bins, bin_seconds,
                                                          bounds, end_time)
        else:
            new_bounds = self._recalibrate_chunks(first[0], expected_records, bounds, end_time)
        if new_bounds is not None:
            bounds = new_bounds
            results = [first] + [None] * (len(bounds) - 1)
        total_chunks = len(bounds)
        emit(1, total_chunks, f'Chunk 1/{total_chunks} complete...')

        remaining = list(range(1, total_chunks))
        if remaining:
            workers = min(max(1, int(self.MAX_PARALLEL_QUERIES)), len(remaining))
            if workers <= 1:
                completed = 1
                for idx in remaining:
                    if self.cancel_requested:
                        return (None, None, None)
                    emit(completed, total_chunks, f'Chunk {idx + 1}/{total_chunks}...')
                    results[idx] = run_range(bounds[idx][0], bounds[idx][1], progress_callback)
                    if self.cancel_requested:
                        return (None, None, None)
                    completed += 1
            else:
                if not self._run_chunks_parallel(bounds, remaining, results, workers,
                                                 total_chunks, emit, run_range):
                    return (None, None, None)

        total_bytes_scanned = extra_scanned + sum(r[1] for r in results)
        truncated = any(r[2] for r in results)
        rows = merge_rows(results)
        if progress_callback:
            status_msg = labels['done_status'].format(rows=len(rows), n=total_chunks)
            if truncated:
                status_msg += labels['truncated_note']
            progress_callback({
                'stage': labels['stage'],
                'status': status_msg,
                'phase': labels['phase'],
                'chunk_label': labels['chunk_label'],
                'chunk_current': total_chunks,
                'chunk_total': total_chunks,
            })
        return (rows, total_bytes_scanned, truncated)

    @staticmethod
    def _plan_chunks(start_time: datetime, end_time: datetime, num_chunks: int) -> list:
        """Split [start_time, end_time] into num_chunks disjoint (start, end) ranges.

        Every chunk after the first starts 1 second after its nominal boundary so a
        record on a boundary second is not counted in two chunks; the last chunk
        ends exactly at end_time.
        """
        chunk_duration = (end_time - start_time) / num_chunks
        bounds = []
        for chunk_num in range(num_chunks):
            raw_start = start_time + (chunk_duration * chunk_num)
            chunk_start = raw_start if chunk_num == 0 else raw_start + timedelta(seconds=1)
            chunk_end = (end_time if chunk_num == num_chunks - 1
                         else start_time + (chunk_duration * (chunk_num + 1)))
            bounds.append((chunk_start, chunk_end))
        return bounds

    def _histogram_bin_seconds(self, start_time: datetime, end_time: datetime) -> int:
        """Bin width (whole minutes, in seconds) for the record histogram.

        As fine as HISTOGRAM_MIN_BIN_SECONDS, but coarse enough that the window
        produces at most HISTOGRAM_MAX_BINS rows (under the 10K result cap).
        """
        span = max(1, int(end_time.timestamp()) - int(start_time.timestamp()) + 1)
        needed = -(-span // self.HISTOGRAM_MAX_BINS)
        seconds = max(self.HISTOGRAM_MIN_BIN_SECONDS, needed)
        return int(-(-seconds // 60) * 60)

    def _query_record_histogram(self, start_time: datetime, end_time: datetime,
                                progress_callback: Optional[Callable] = None):
        """Count netflow records per time bin across the window.

        Returns (bins, bin_seconds, bytes_scanned), where bins is a sorted list of
        (bin_start_epoch_seconds, record_count). Returns None if the query fails,
        is cancelled, or returns nothing usable; callers then fall back to evenly
        sized chunks, so a failure here never affects the results.
        """
        return self._query_histogram(self.log_group, 'filter event.event_type = "netflow"\n',
                                     start_time, end_time, progress_callback,
                                     'Querying flow breakdown')

    def _query_alert_histogram(self, start_time: datetime, end_time: datetime,
                               progress_callback: Optional[Callable] = None):
        """Count hostname-bearing alert records per time bin (see _query_histogram)."""
        return self._query_histogram(self.alert_log_group, self._ALERT_FILTER,
                                     start_time, end_time, progress_callback,
                                     'Querying alert logs')

    def _query_histogram(self, log_group: str, filter_text: str, start_time: datetime,
                         end_time: datetime, progress_callback: Optional[Callable],
                         stage: str):
        """Count the records matching filter_text per time bin in log_group.

        Returns (bins, bin_seconds, bytes_scanned) or None on any failure.
        """
        bin_seconds = self._histogram_bin_seconds(start_time, end_time)
        query = filter_text + f'| stats count(*) as recs by bin({bin_seconds // 60}m)'
        try:
            response = self._call_logs_api(
                self.logs_client.start_query,
                logGroupName=log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
            query_id = response['queryId']
            started = time.time()
            poll_delay = self.POLL_INITIAL_SECONDS
            while True:
                if self.cancel_requested:
                    try:
                        self.logs_client.stop_query(queryId=query_id)
                    except Exception:
                        pass
                    return None
                result = self._call_logs_api(self.logs_client.get_query_results,
                                             queryId=query_id)
                status = result.get('status')
                if status in self._TERMINAL_QUERY_STATUSES:
                    break
                elapsed = time.time() - started
                if elapsed > self.MAX_QUERY_SECONDS:
                    try:
                        self.logs_client.stop_query(queryId=query_id)
                    except Exception:
                        pass
                    return None
                if progress_callback:
                    progress_callback({
                        'stage': stage,
                        'status': f'Measuring record density... ({int(elapsed)}s elapsed)'
                    })
                time.sleep(poll_delay)
                poll_delay = min(self.POLL_MAX_SECONDS, poll_delay * self.POLL_BACKOFF_FACTOR)
            if status != 'Complete':
                return None

            bins = {}
            for row in result.get('results', []):
                count = None
                stamp = None
                for cell in row:
                    name = cell.get('field', '')
                    if name == 'recs':
                        count = cell.get('value')
                    elif name.startswith('bin('):
                        stamp = cell.get('value')
                ts = self._parse_cw_timestamp(stamp)
                if ts is None or count is None:
                    continue
                epoch = calendar.timegm(ts.timetuple())
                bins[epoch] = bins.get(epoch, 0) + int(float(count))
            if not bins:
                return None
            bytes_scanned = result.get('statistics', {}).get('bytesScanned', 0)
            return (sorted(bins.items()), bin_seconds, bytes_scanned)
        except Exception:
            return None

    @staticmethod
    def _plan_epochs_from_histogram(bins: list, bin_seconds: int, first: int,
                                    last: int, target: float) -> list:
        """Partition the inclusive epoch-second range [first, last] into chunks.

        Each chunk is planned to hold about `target` records according to the
        histogram, assuming records are spread evenly within a bin. Chunks are
        contiguous and disjoint (each starts one second after the previous ends),
        cover the whole range including empty stretches, and are at least one
        second long.

        Returns a list of (start_epoch, end_epoch) inclusive pairs.
        """
        cuts = []
        acc = 0.0
        for bin_start, count in bins:
            lo = max(first, bin_start)
            hi = min(last, bin_start + bin_seconds - 1)
            if lo > hi or count <= 0:
                continue
            rate = count / float(bin_seconds)  # records per second in this bin
            pos = lo
            while pos <= hi and acc + rate * (hi - pos + 1) > target:
                fit = int((target - acc) / rate)  # whole seconds that still fit
                cut = pos + max(fit, 1) - 1
                if cut >= last:
                    break
                cuts.append(cut)
                acc = 0.0
                pos = cut + 1
            if pos <= hi:
                acc += rate * (hi - pos + 1)
        starts = [first] + [c + 1 for c in cuts]
        ends = cuts + [last]
        return list(zip(starts, ends))

    def _bounds_from_histogram(self, bins: list, bin_seconds: int, start_time: datetime,
                               end_time: datetime, target: float) -> list:
        """Chunk (start, end) datetimes for the window, planned from the histogram.

        The first chunk starts exactly at start_time and the last ends exactly at
        end_time; interior boundaries are whole seconds.
        """
        first = int(start_time.timestamp())
        last = int(end_time.timestamp())
        pairs = self._plan_epochs_from_histogram(bins, bin_seconds, first, last, target)
        bounds = []
        for i, (s, e) in enumerate(pairs):
            chunk_start = start_time if i == 0 else datetime.fromtimestamp(s)
            chunk_end = end_time if i == len(pairs) - 1 else datetime.fromtimestamp(e)
            bounds.append((chunk_start, chunk_end))
        return bounds

    def _recalibrate_from_histogram(self, first_rows: list, bins: list, bin_seconds: int,
                                    bounds: list, end_time: datetime) -> Optional[list]:
        """Re-plan the chunks after the first one when groups are fewer than records.

        Same idea as _recalibrate_chunks, for a histogram-based plan: the observed
        groups-per-record ratio of the first chunk raises the per-chunk record
        target (capped at CALIBRATION_MAX_REDUCTION times the safe size). Any chunk
        that still hits the cap is bisected, so accuracy does not depend on this.
        Returns the new full bounds list or None to keep the plan.
        """
        try:
            first_recs = sum(int(r.get('recs') or 0) for r in first_rows)
            if not first_rows or first_recs <= 0 or len(bounds) <= 2:
                return None
            ratio = len(first_rows) / float(first_recs)
            if ratio >= self.CALIBRATION_RATIO_THRESHOLD:
                return None
            target = min(self.CALIBRATED_GROUPS_PER_CHUNK / ratio,
                         float(self.SAFE_CHUNK_ROWS * self.CALIBRATION_MAX_REDUCTION))
            sub_start = datetime.fromtimestamp(int(bounds[0][1].timestamp()) + 1)
            if sub_start >= end_time:
                return None
            rest = self._bounds_from_histogram(bins, bin_seconds, sub_start, end_time, target)
            if len(rest) >= len(bounds) - 1:
                return None
            return [bounds[0]] + rest
        except Exception:
            return None  # calibration is an optimization only; keep the safe plan

    def _recalibrate_chunks(self, first_rows: list, expected_records: int,
                            bounds: list, end_time: datetime) -> Optional[list]:
        """Re-plan the chunks after the first one using the observed group density.

        The initial plan sizes chunks by netflow RECORD count, but the 10K cap
        applies to returned GROUPS, which are fewer. From the first chunk, the ratio
        groups/records is len(rows) / sum(recs). When that ratio is clearly below 1
        the remaining window can be covered by fewer, larger chunks.

        Returns the new full bounds list (first chunk kept as-is) or None to keep the
        original plan. The result never has fewer than 1/CALIBRATION_MAX_REDUCTION of
        the original remaining chunks, and any chunk that still hits the cap is
        bisected by _query_grouped_range_adaptive, so accuracy never depends on this
        estimate being right.
        """
        try:
            first_recs = sum(int(r.get('recs') or 0) for r in first_rows)
            if not first_rows or first_recs <= 0 or len(bounds) <= 2:
                return None
            ratio = len(first_rows) / float(first_recs)
            if ratio >= self.CALIBRATION_RATIO_THRESHOLD:
                return None

            remaining_records = max(0, expected_records - first_recs)
            est_groups = remaining_records * ratio
            needed = max(1, -(-int(est_groups) // self.CALIBRATED_GROUPS_PER_CHUNK))
            orig_remaining = len(bounds) - 1
            min_chunks = max(1, -(-orig_remaining // self.CALIBRATION_MAX_REDUCTION))
            new_remaining = max(needed, min_chunks)
            if new_remaining >= orig_remaining:
                return None

            sub_start = bounds[0][1] + timedelta(seconds=1)
            if sub_start >= end_time:
                return None
            return [bounds[0]] + self._plan_chunks(sub_start, end_time, new_remaining)
        except Exception:
            return None  # calibration is an optimization only; keep the safe plan

    def _run_chunks_parallel(self, bounds: list, indexes: list, results: list,
                             workers: int, total_chunks: int, emit,
                             run_range: Optional[Callable] = None) -> bool:
        """Run the chunk queries for `indexes` concurrently and fill `results`.

        Worker threads only issue CloudWatch queries; they never call the progress
        callback. This (calling) thread waits for them and reports progress itself,
        so UI code that is not thread-safe is only touched from here.

        Returns False if the analysis was cancelled. Raises the first worker error
        (after stopping the other workers).
        """
        from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

        executor = ThreadPoolExecutor(max_workers=workers)
        future_index = {}
        try:
            for idx in indexes:
                fut = executor.submit(run_range or self._query_grouped_range_adaptive,
                                      bounds[idx][0], bounds[idx][1], None)
                future_index[fut] = idx
            pending = set(future_index)
            completed = 1  # chunk 0 is already done
            while pending:
                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for fut in done:
                    results[future_index[fut]] = fut.result()  # re-raises worker errors
                    completed += 1
                emit(completed, total_chunks,
                     f'{completed}/{total_chunks} chunks complete '
                     f'({min(workers, len(pending))} running)...')
                if self.cancel_requested:
                    self._stop_workers(executor, pending)
                    return False
            executor.shutdown(wait=True)
            return True
        except BaseException:
            self._stop_workers(executor, [f for f in future_index if not f.done()])
            raise

    def _stop_workers(self, executor, pending) -> None:
        """Cancel queued chunk tasks and wait for running ones to stop.

        Running workers poll `cancel_requested` and stop their CloudWatch query, so
        it is raised for the duration of the shutdown and then restored.
        """
        previous = self.cancel_requested
        self.cancel_requested = True
        try:
            for fut in pending:
                fut.cancel()
            executor.shutdown(wait=True)
        finally:
            self.cancel_requested = previous

    def _call_logs_api(self, func, **kwargs):
        """Call a CloudWatch Logs API with retry/backoff on throttling.

        Concurrent chunk queries can hit throttling or the concurrent-query quota
        (LimitExceededException). Those are retried with exponential backoff; any
        other error is raised immediately and unchanged.
        """
        delay = 1.0
        for attempt in range(self.MAX_THROTTLE_RETRIES):
            try:
                return func(**kwargs)
            except Exception as e:
                code = ''
                try:
                    code = e.response.get('Error', {}).get('Code', '')
                except Exception:
                    pass
                text = f'{code} {e}'
                throttled = any(name in text for name in self._THROTTLE_ERROR_NAMES)
                if (not throttled or self.cancel_requested
                        or attempt >= self.MAX_THROTTLE_RETRIES - 1):
                    raise
                with self._throttle_lock:
                    self.throttle_retries += 1
                time.sleep(delay)
                delay = min(delay * 2, 30.0)

    def _query_grouped_range_adaptive(self, start_time: datetime, end_time: datetime,
                                      progress_callback: Optional[Callable] = None) -> tuple:
        """Flow breakdown for one range, bisected if it hits the group cap."""
        return self._query_range_adaptive(self._execute_grouped_query,
                                          start_time, end_time, progress_callback)

    def _query_alert_range_adaptive(self, start_time: datetime, end_time: datetime,
                                    progress_callback: Optional[Callable] = None) -> tuple:
        """Alert hostnames for one range, bisected if it hits the group cap."""
        return self._query_range_adaptive(self._execute_alert_grouped_query,
                                          start_time, end_time, progress_callback)

    def _query_range_adaptive(self, execute: Callable, start_time: datetime,
                              end_time: datetime,
                              progress_callback: Optional[Callable] = None) -> tuple:
        """Run a grouped query for a range; bisect if it hits the group cap.

        If the returned group count hits the 10,000-row cap the range is halved
        (down to a 60s floor) so no groups are lost; only a <=60s window still at
        the cap is flagged truncated.

        Args:
            execute: (start, end, progress_callback) -> (rows, scanned, hit_cap).

        Returns:
            Tuple of (grouped_rows, bytes_scanned, truncated)
        """
        MIN_CHUNK_SECONDS = 60

        if self.cancel_requested:
            return ([], 0, False)

        rows, bytes_scanned, hit_limit = execute(start_time, end_time, progress_callback)
        if self.cancel_requested:
            return ([], 0, False)

        if not hit_limit:
            return (rows, bytes_scanned, False)

        if (end_time - start_time).total_seconds() <= MIN_CHUNK_SECONDS:
            print("\u26a0\ufe0f  Warning: a <=60s window still hit the 10K group limit; "
                  "results for this period are a sample. "
                  "Authoritative totals are unaffected.")
            return (rows, bytes_scanned, True)

        mid = start_time + (end_time - start_time) / 2
        left_rows, left_bytes, left_trunc = self._query_range_adaptive(
            execute, start_time, mid, progress_callback
        )
        if self.cancel_requested:
            return ([], 0, False)
        right_rows, right_bytes, right_trunc = self._query_range_adaptive(
            execute, mid + timedelta(seconds=1), end_time, progress_callback
        )
        return (left_rows + right_rows,
                left_bytes + right_bytes,
                left_trunc or right_trunc)

    def _execute_grouped_query(self, start_time: datetime, end_time: datetime,
                               progress_callback: Optional[Callable] = None) -> tuple:
        """Execute one grouped aggregation query and parse rows.

        Returns:
            Tuple of (grouped_rows, bytes_scanned, hit_group_cap)
        """
        try:
            response = self._call_logs_api(
                self.logs_client.start_query,
                logGroupName=self.log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=self._GROUPED_QUERY
            )
        except Exception as e:
            error_str = str(e)
            if "ResourceNotFoundException" in error_str or "ResourceNotFound" in error_str:
                raise Exception(f"FLOW log group not found: '{self.log_group}'. Please verify the name and region.")
            elif "MalformedQueryException" in error_str and ("creation time" in error_str or "before" in error_str.lower()):
                # Range predates log group creation - no data for this chunk.
                return ([], 0, False)
            else:
                raise Exception(f"Failed to start flow breakdown query on '{self.log_group}': {error_str}")

        query_id = response['queryId']
        start_query_time = time.time()
        poll_delay = self.POLL_INITIAL_SECONDS
        while True:
            if self.cancel_requested:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except:
                    pass
                return ([], 0, False)

            result = self._call_logs_api(self.logs_client.get_query_results, queryId=query_id)
            status = result['status']
            if status in self._TERMINAL_QUERY_STATUSES:
                break

            elapsed = time.time() - start_query_time
            if elapsed > self.MAX_QUERY_SECONDS:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except:
                    pass
                raise Exception(f"Flow breakdown query timed out after {int(elapsed)}s "
                                f"waiting for CloudWatch Logs Insights (status '{status}').")
            if progress_callback:
                progress_callback({
                    'stage': 'Querying flow breakdown',
                    'status': f'Aggregation running... ({int(elapsed)}s elapsed)'
                })
            time.sleep(poll_delay)
            poll_delay = min(self.POLL_MAX_SECONDS, poll_delay * self.POLL_BACKOFF_FACTOR)

        if status != 'Complete':
            raise Exception(f"Flow breakdown query {status.lower()}: {result.get('statistics', {})}")

        records = result.get('results', [])
        statistics = result.get('statistics', {})
        bytes_scanned = statistics.get('bytesScanned', 0)
        records_matched = statistics.get('recordsMatched', 0)
        # For a stats query, len(records) is the number of returned GROUPS; hitting
        # 10K means we must subdivide to avoid dropping groups.
        hit_limit = (len(records) >= 10000 and records_matched > 10000)

        rows = []
        for row in records:
            bytes_str = self._get_field_value(row, 'bytes')
            recs_str = self._get_field_value(row, 'recs')
            try:
                b = int(float(bytes_str)) if bytes_str else 0
            except (ValueError, TypeError):
                b = 0
            try:
                recs = int(float(recs_str)) if recs_str else 0
            except (ValueError, TypeError):
                recs = 0
            rows.append({
                'flow_id': self._get_field_value(row, 'event.flow_id'),
                'src_ip': self._get_field_value(row, 'event.src_ip'),
                'dest_ip': self._get_field_value(row, 'event.dest_ip'),
                'src_port': self._get_field_value(row, 'event.src_port'),
                'dest_port': self._get_field_value(row, 'event.dest_port'),
                'proto': self._get_field_value(row, 'event.proto'),
                'app_proto': self._get_field_value(row, 'event.app_proto'),
                'az': self._get_field_value(row, 'availability_zone'),
                'bytes': b,
                'recs': recs,
                'first_ts': self._get_field_value(row, 'first_ts'),
                'last_ts': self._get_field_value(row, 'last_ts'),
            })
        return (rows, bytes_scanned, hit_limit)

    # Alerts that carry a hostname (HTTP Host header or TLS SNI).
    _ALERT_FILTER = ('filter event.event_type = "alert"\n'
                     '| filter (isPresent(event.http.hostname) or isPresent(event.tls.sni))\n')

    # One row per flow: its hostname/SNI, alert count and first/last alert time.
    # sortsLast() returns a value whenever any of the flow's alerts has the field.
    _ALERT_GROUPED_QUERY = (_ALERT_FILTER +
                            '| stats sortsLast(event.http.hostname) as http_host,'
                            ' sortsLast(event.tls.sni) as sni, count(*) as recs,'
                            ' min(@timestamp) as first_ts, max(@timestamp) as last_ts'
                            ' by event.flow_id')

    _ALERT_CHUNK_LABELS = {
        'stage': 'Querying alert logs',
        'chunk_stage': 'Querying alert logs (chunked)',
        'phase': 'alert_chunks',
        'chunk_label': 'Alert logs',
        'start_status': 'Collecting hostnames in {n} chunks...',
        'done_status': 'Collected hostnames for {rows:,} flows from {n} chunks',
        'truncated_note': ' (some hostnames sampled)',
    }

    def query_alert_logs(self, progress_callback: Optional[Callable] = None) -> tuple:
        """Collect the hostname (HTTP host or TLS SNI) of every flow that has one.

        Hostnames come from alert events. A single Logs Insights query returns at
        most 10,000 rows, so instead of fetching raw alerts this groups them per
        flow_id on the server and splits the window into chunks (planned from a
        per-time-bin count of matching alerts), exactly like the flow breakdown.
        Chunks that still hit the cap are bisected, so every flow is covered.

        Also tracks the earliest/latest alert timestamps for the endpoint cost
        calculation.

        Returns:
            Tuple of (alert_logs, earliest_alert_ts, latest_alert_ts, bytes_scanned)
            where alert_logs is a list of {'flow_id', 'http_host', 'sni'} dicts
            (one per flow), or (None, None, None, None) if cancelled.
        """
        if self.cancel_requested:
            return (None, None, None, None)

        # Shared window helper: identical range to the flow / totals queries.
        start_time, end_time = self._get_query_window()

        if progress_callback:
            progress_callback({
                'stage': 'Querying alert logs',
                'status': 'Measuring where alerts are in the time window...'
            })
        histogram = self._query_alert_histogram(start_time, end_time, progress_callback)
        if self.cancel_requested:
            return (None, None, None, None)

        hist_scanned = 0
        expected = None
        if histogram is not None:
            bins, bin_seconds, hist_scanned = histogram
            expected = sum(c for _, c in bins)

        if expected is not None and expected > self.SAFE_CHUNK_ROWS:
            bounds = self._bounds_from_histogram(bins, bin_seconds, start_time, end_time,
                                                 self.SAFE_CHUNK_ROWS)
            rows, scanned, truncated = self._query_chunked(
                bounds, histogram, expected, end_time,
                lambda s, e, cb: self._query_alert_range_adaptive(s, e, cb),
                self._merge_alert_rows, self._ALERT_CHUNK_LABELS,
                hist_scanned, progress_callback)
        else:
            # Few alerts (or no density data): one query, bisected if needed.
            rows, scanned, truncated = self._query_alert_range_adaptive(
                start_time, end_time, progress_callback)
            if rows is not None:
                rows = self._merge_alert_rows([(rows, scanned, truncated)])
                scanned += hist_scanned
        if self.cancel_requested or rows is None:
            return (None, None, None, None)

        earliest_alert_ts = None
        latest_alert_ts = None
        alert_logs = []
        for r in rows:
            # Normalized to NAIVE UTC by the shared parser so these compare with
            # the flow-leg timestamps in analyze() (mixing naive and tz-aware
            # datetimes raises).
            first = self._parse_cw_timestamp(r.get('first_ts'))
            last = self._parse_cw_timestamp(r.get('last_ts'))
            if first and (earliest_alert_ts is None or first < earliest_alert_ts):
                earliest_alert_ts = first
            if last and (latest_alert_ts is None or last > latest_alert_ts):
                latest_alert_ts = last
            alert_logs.append({'flow_id': r['flow_id'], 'http_host': r.get('http_host'),
                               'sni': r.get('sni')})

        if progress_callback:
            progress_callback({
                'stage': 'Querying alert logs',
                'status': f'Found hostnames for {len(alert_logs):,} flows'
            })
        return (alert_logs, earliest_alert_ts, latest_alert_ts, scanned)

    @staticmethod
    def _merge_alert_rows(results: list) -> list:
        """Merge per-chunk alert groups by flow_id.

        A flow's alerts can fall in more than one chunk. Counts add up, first/last
        timestamps take the min/max, and a hostname/SNI found in any chunk is kept
        (if two chunks disagree, the one from the later alerts wins).
        """
        merged = {}
        for chunk_rows, _, _ in results:
            for r in chunk_rows:
                fid = r.get('flow_id')
                if not fid:
                    continue
                m = merged.get(fid)
                if m is None:
                    merged[fid] = dict(r)
                    continue
                later = bool(r.get('last_ts')) and (not m.get('last_ts')
                                                    or r['last_ts'] > m['last_ts'])
                for field in ('http_host', 'sni'):
                    if r.get(field) and (not m.get(field) or later):
                        m[field] = r[field]
                m['recs'] = m.get('recs', 0) + r.get('recs', 0)
                if r.get('first_ts') and (not m.get('first_ts') or r['first_ts'] < m['first_ts']):
                    m['first_ts'] = r['first_ts']
                if later:
                    m['last_ts'] = r['last_ts']
        return list(merged.values())

    def _execute_alert_grouped_query(self, start_time: datetime, end_time: datetime,
                                     progress_callback: Optional[Callable] = None) -> tuple:
        """Execute one grouped alert query and parse rows.

        Returns:
            Tuple of (rows, bytes_scanned, hit_group_cap), where rows are dicts with
            flow_id, http_host, sni, recs, first_ts, last_ts.
        """
        try:
            response = self._call_logs_api(
                self.logs_client.start_query,
                logGroupName=self.alert_log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=self._ALERT_GROUPED_QUERY
            )
        except Exception as e:
            error_str = str(e)
            if "ResourceNotFoundException" in error_str or "ResourceNotFound" in error_str:
                raise Exception(f"ALERT log group not found: '{self.alert_log_group}'. Please verify the name and region.")
            elif "MalformedQueryException" in error_str and ("creation time" in error_str or "before" in error_str.lower()):
                return ([], 0, False)  # range predates log group creation
            else:
                raise Exception(f"Failed to start alert log query on '{self.alert_log_group}': {error_str}")

        query_id = response['queryId']
        start_query_time = time.time()
        poll_delay = self.POLL_INITIAL_SECONDS
        while True:
            if self.cancel_requested:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except Exception:
                    pass
                return ([], 0, False)

            result = self._call_logs_api(self.logs_client.get_query_results, queryId=query_id)
            status = result['status']
            if status in self._TERMINAL_QUERY_STATUSES:
                break

            # Wall-clock safety net: fail loudly instead of hanging.
            elapsed = time.time() - start_query_time
            if elapsed > self.MAX_QUERY_SECONDS:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except Exception:
                    pass
                raise Exception(f"Alert log query timed out after {int(elapsed)}s "
                                f"waiting for CloudWatch Logs Insights (status '{status}').")
            if progress_callback:
                progress_callback({
                    'stage': 'Querying alert logs',
                    'status': f'Query running... ({int(elapsed)}s elapsed)'
                })
            time.sleep(poll_delay)
            poll_delay = min(self.POLL_MAX_SECONDS, poll_delay * self.POLL_BACKOFF_FACTOR)

        if status != 'Complete':
            raise Exception(f"Alert log query {status.lower()}: {result.get('statistics', {})}")

        records = result.get('results', [])
        statistics = result.get('statistics', {})
        bytes_scanned = statistics.get('bytesScanned', 0)
        records_matched = statistics.get('recordsMatched', 0)
        hit_limit = (len(records) >= 10000 and records_matched > 10000)

        rows = []
        for row in records:
            recs_str = self._get_field_value(row, 'recs')
            try:
                recs = int(float(recs_str)) if recs_str else 1
            except (ValueError, TypeError):
                recs = 1
            ts = self._get_field_value(row, '@timestamp')  # present on raw rows only
            rows.append({
                'flow_id': self._get_field_value(row, 'event.flow_id'),
                'http_host': (self._get_field_value(row, 'http_host')
                              or self._get_field_value(row, 'event.http.hostname')),
                'sni': (self._get_field_value(row, 'sni')
                        or self._get_field_value(row, 'event.tls.sni')),
                'recs': recs,
                'first_ts': self._get_field_value(row, 'first_ts') or ts,
                'last_ts': self._get_field_value(row, 'last_ts') or ts,
            })
        return (rows, bytes_scanned, hit_limit)

    def _get_field_value(self, log_entry: List[Dict], field_name: str) -> Optional[str]:
        """Extract field value from CloudWatch Logs query result
        
        Args:
            log_entry: CloudWatch log entry (list of field dicts)
            field_name: Field name to extract
            
        Returns:
            Field value or None if not found
        """
        for field in log_entry:
            if field.get('field') == field_name:
                return field.get('value')
        return None
    
    @staticmethod
    def _parse_cw_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
        """Parse a CloudWatch Logs timestamp string into a datetime, or None.

        Handles both the raw @timestamp ISO form ('2026-07-01T05:00:00.000Z') and
        the form returned by min()/max(@timestamp) in a stats query, which uses a
        space separator ('2026-07-01 05:00:00.000'). Returns None on any failure so
        callers can simply skip unparseable values.
        """
        if not ts_str:
            return None
        s = ts_str.strip().replace('Z', '+00:00')
        # min/max(@timestamp) returns 'YYYY-MM-DD HH:MM:SS.sss' (space, no 'T').
        if 'T' not in s and ' ' in s:
            s = s.replace(' ', 'T', 1)
        try:
            dt = datetime.fromisoformat(s)
        except (ValueError, TypeError):
            return None
        # Normalize to NAIVE UTC. CloudWatch returns @timestamp as naive UTC, so
        # every timestamp in the analysis (flow legs, alert logs, metadata) is kept
        # naive and mutually comparable. Mixing naive and tz-aware datetimes raises
        # "can't compare offset-naive and offset-aware datetimes", so if a source
        # value happens to carry an offset we convert it to UTC and drop tzinfo.
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    
    def correlate_logs(self, grouped_rows: List[Dict], alert_logs: List[Dict],
                      progress_callback: Optional[Callable] = None) -> tuple:
        """Correlate the grouped per-flow aggregation with alert logs by flow_id.

        Input is the output of query_flow_grouped(): each row is one directional
        leg of a flow (dict with flow_id, src_ip, dest_ip, src_port, dest_port,
        proto, app_proto, az, bytes, recs, first_ts, last_ts), where 'bytes' is
        already the server-side sum for that leg. The two directional legs of a
        flow share a flow_id (with src/dest swapped), so we re-join by flow_id and
        collapse them into one canonical flow exactly as the previous raw-record
        path did: sum bytes across legs (bidirectional total), pick the canonical
        src/dest/port via the outbound/return-traffic heuristic, then enrich with
        hostname (alert join) and AWS service (hostname or dest-IP) info.

        This collapse is order-independent: whether the outbound or return leg is
        seen first, the canonical dest_port resolves to the same service port.

        Args:
            grouped_rows: List of aggregated flow-leg dicts from query_flow_grouped.
            alert_logs: List of alert log entries.
            progress_callback: Optional callback for progress updates.

        Returns:
            Tuple of (enriched_flows, unique_azs, az_traffic, earliest_timestamp, latest_timestamp) or (None, None, None, None, None) if cancelled
        """
        if self.cancel_requested:
            return (None, None, None, None, None)
        
        if progress_callback:
            progress_callback({
                'stage': 'Correlating logs',
                'status': f'Processing {len(alert_logs):,} alert records...'
            })
        
        # Build alert lookup by flow_id
        alert_lookup = {}
        for alert in alert_logs:
            if isinstance(alert, dict):
                # One row per flow from query_alert_logs.
                flow_id = alert.get('flow_id')
                hostname = alert.get('http_host')
                tls_sni = alert.get('sni')
            else:
                # Raw Logs Insights row (list of field/value cells).
                flow_id = self._get_field_value(alert, 'event.flow_id')
                hostname = self._get_field_value(alert, 'event.http.hostname')
                tls_sni = self._get_field_value(alert, 'event.tls.sni')
            
            if flow_id:
                # Prefer HTTP hostname over TLS SNI
                alert_lookup[flow_id] = {
                    'hostname': hostname or tls_sni or ''
                }
        
        if progress_callback:
            progress_callback({
                'stage': 'Correlating logs',
                'status': f'Processing {len(grouped_rows):,} flow legs...'
            })
        
        # Re-join the directional legs by flow_id and sum bytes bidirectionally.
        # Each grouped row's 'bytes' is already the server-side sum for that leg;
        # summing across a flow_id's legs yields the correct bidirectional total.
        flow_totals = {}
        
        # Track unique AZs and timestamps for endpoint cost calculation
        # Also track bytes per AZ for traffic distribution analysis
        unique_azs = set()
        az_traffic = {}  # Map AZ -> total bytes processed
        earliest_timestamp = None
        latest_timestamp = None
        
        for i, row in enumerate(grouped_rows):
            if self.cancel_requested:
                return (None, None, None, None, None)
            
            flow_id = row.get('flow_id')
            src_ip = row.get('src_ip')
            dest_ip = row.get('dest_ip')
            src_port = row.get('src_port')
            dest_port = row.get('dest_port')
            proto = row.get('proto')
            app_proto = row.get('app_proto')
            az = row.get('az')
            
            if not flow_id:
                continue
            
            bytes_val = row.get('bytes') or 0  # already summed for this leg
            
            # Track AZ for endpoint cost calculation and traffic distribution
            if az:
                unique_azs.add(az)
                if az not in az_traffic:
                    az_traffic[az] = 0
                az_traffic[az] += bytes_val
            
            # Track overall timestamp range from this leg's min/max timestamps.
            first_ts = self._parse_cw_timestamp(row.get('first_ts'))
            last_ts = self._parse_cw_timestamp(row.get('last_ts'))
            if first_ts:
                if earliest_timestamp is None or first_ts < earliest_timestamp:
                    earliest_timestamp = first_ts
            if last_ts:
                if latest_timestamp is None or last_ts > latest_timestamp:
                    latest_timestamp = last_ts
            
            # Initialize flow entry if first time seeing this flow_id
            if flow_id not in flow_totals:
                flow_totals[flow_id] = {
                    'bytes': 0,
                    'src_ip': None,
                    'dest_ip': None,
                    'dest_port': None,
                    'proto': None,
                    'app_proto': None,
                    'timestamp': None
                }
            
            # Sum bytes from both directional legs
            flow_totals[flow_id]['bytes'] += bytes_val
            
            # Per-flow timestamp: earliest leg start seen for this flow.
            if first_ts and (flow_totals[flow_id]['timestamp'] is None
                             or first_ts < flow_totals[flow_id]['timestamp']):
                flow_totals[flow_id]['timestamp'] = first_ts
            
            # Determine initiating source and destination.
            # CRITICAL: Only capture port/protocol from OUTBOUND traffic (private -> public);
            # return traffic (public -> private) has ephemeral ports we must not use as the port.
            src_is_private = self.aws_service_detector.is_rfc1918_private(src_ip) if src_ip else False
            dest_is_private = self.aws_service_detector.is_rfc1918_private(dest_ip) if dest_ip else False
            
            # If we don't have IPs yet, capture them from the first leg seen
            if flow_totals[flow_id]['src_ip'] is None:
                if src_is_private and not dest_is_private:
                    # OUTBOUND: private source, public dest (captures real dest port: 443, 80, etc.)
                    flow_totals[flow_id]['src_ip'] = src_ip
                    flow_totals[flow_id]['dest_ip'] = dest_ip
                    flow_totals[flow_id]['dest_port'] = dest_port
                    flow_totals[flow_id]['proto'] = proto
                    flow_totals[flow_id]['app_proto'] = app_proto
                elif not src_is_private and dest_is_private:
                    # RETURN TRAFFIC: public source, private dest.
                    # In return traffic, the source port IS the real service port
                    # (e.g. public:443 -> private:54321 => port 443).
                    flow_totals[flow_id]['src_ip'] = dest_ip  # VPC IP
                    flow_totals[flow_id]['dest_ip'] = src_ip  # Internet IP
                    flow_totals[flow_id]['dest_port'] = src_port  # src_port from return = service port
                    flow_totals[flow_id]['proto'] = proto
                    flow_totals[flow_id]['app_proto'] = app_proto
                elif src_ip and dest_ip:
                    # Both private or both public - capture as-is
                    flow_totals[flow_id]['src_ip'] = src_ip
                    flow_totals[flow_id]['dest_ip'] = dest_ip
                    flow_totals[flow_id]['dest_port'] = dest_port
                    flow_totals[flow_id]['proto'] = proto
                    flow_totals[flow_id]['app_proto'] = app_proto
            elif flow_totals[flow_id]['dest_port'] is None:
                # We have IPs but missing port - try to get it from an outbound leg
                if src_is_private and not dest_is_private:
                    flow_totals[flow_id]['dest_port'] = dest_port
                    if flow_totals[flow_id]['app_proto'] is None:
                        flow_totals[flow_id]['app_proto'] = app_proto
            
            # Progress update every 10,000 legs
            if i > 0 and i % 10000 == 0 and progress_callback:
                percent = (i / len(grouped_rows)) * 100
                progress_callback({
                    'stage': 'Correlating logs',
                    'processed': i,
                    'total': len(grouped_rows),
                    'percent': percent,
                    'status': f'Grouping flow legs by flow_id... ({i:,}/{len(grouped_rows):,})'
                })
        
        if progress_callback:
            progress_callback({
                'stage': 'Correlating logs',
                'status': 'Enriching with hostnames and AWS service info...'
            })
        
        # Enrich flows with alert data and AWS service identification
        enriched_flows = []
        flow_items = list(flow_totals.items())
        
        for i, (flow_id, flow_data) in enumerate(flow_items):
            if self.cancel_requested:
                return (None, None, None, None, None)
            
            # Add hostname from alerts if available
            hostname = alert_lookup.get(flow_id, {}).get('hostname', '')
            if not hostname:
                hostname = "(No hostname)"
            
            # Identify AWS service - prioritize hostname detection over IP detection
            dest_ip = flow_data['dest_ip']
            src_ip = flow_data['src_ip']
            
            service_info = None
            
            # CRITICAL: Try hostname-based detection FIRST when available
            # Hostname is more accurate than IP-based detection for AWS services
            if hostname and hostname != "(No hostname)":
                parsed = self._service_from_hostname(hostname)
                if parsed:
                    service_name, region_part = parsed
                    if region_part is None:
                        # Regionless hostname (e.g. bucket.s3.amazonaws.com): take
                        # the region from the destination IP's published range.
                        ip_info = (self.aws_service_detector.identify_aws_service(dest_ip)
                                   if dest_ip else None)
                        region_part = (ip_info['region'] if ip_info and ip_info.get('is_aws')
                                       else 'N/A')
                    service_info = {'service': service_name, 'region': region_part, 'is_aws': True}
            
            # Fall back to IP-based detection if hostname didn't provide info
            if service_info is None:
                if dest_ip:
                    service_info = self.aws_service_detector.identify_aws_service(dest_ip)
                else:
                    service_info = {'service': 'Unknown', 'region': 'N/A', 'is_aws': False}
            
            enriched_flows.append({
                'flow_id': flow_id,
                'src_ip': src_ip or 'Unknown',
                'dest_ip': dest_ip or 'Unknown',
                'dest_port': flow_data['dest_port'] or 'Unknown',
                'proto': flow_data['proto'] or 'Unknown',
                'bytes': flow_data['bytes'],
                'hostname': hostname,
                'aws_service': service_info['service'],
                'aws_region': service_info['region'],
                'is_aws': service_info['is_aws'],
                'app_proto': flow_data['app_proto'] or 'Unknown',
                'timestamp': flow_data.get('timestamp')
            })
            
            # Progress update every 10,000 flows
            if i > 0 and i % 10000 == 0 and progress_callback:
                percent = (i / len(flow_items)) * 100
                progress_callback({
                    'stage': 'Identifying AWS services',
                    'processed': i,
                    'total': len(flow_items),
                    'percent': percent,
                    'status': f'Processing flows... ({i:,}/{len(flow_items):,})'
                })
        
        # Return flows along with AZ traffic distribution and timestamp data
        return (enriched_flows, unique_azs, az_traffic, earliest_timestamp, latest_timestamp)
    
    def classify_traffic_type(self, src_ip: str, dest_ip: str, is_aws: bool) -> str:
        """Classify traffic into one of three types
        
        Args:
            src_ip: Source IP address
            dest_ip: Destination IP address
            is_aws: Whether destination is AWS service
            
        Returns:
            str: 'internet', 'aws_service', or 'vpc_to_vpc'
        """
        src_is_private = self.aws_service_detector.is_rfc1918_private(src_ip)
        dest_is_private = self.aws_service_detector.is_rfc1918_private(dest_ip)
        
        if src_is_private and dest_is_private:
            # Both private → VPC-to-VPC (Tab 3)
            return 'vpc_to_vpc'
        elif is_aws:
            # Destination is AWS service → AWS Service Traffic (Tab 2)
            return 'aws_service'
        else:
            # Everything else → Internet Traffic (Tab 1)
            return 'internet'
    
    def aggregate_by_hostname(self, enriched_flows: List[Dict]) -> Dict[str, Dict]:
        """Aggregate Internet traffic by hostname (or dest IP if no hostname) for Tab 1
        
        Args:
            enriched_flows: List of enriched flow dictionaries
            
        Returns:
            Dict mapping destination (hostname or IP:port) to aggregated statistics
        """
        # BUGFIX: Build a lookup table mapping dest_ip -> known hostname
        # This allows flows without hostnames to inherit the hostname from other flows to same IP
        ip_to_hostname = {}
        for flow in enriched_flows:
            hostname = flow['hostname']
            dest_ip = flow['dest_ip']
            
            # Only store if we have a valid hostname (not placeholder)
            if hostname and hostname != "(No hostname)" and dest_ip:
                # If multiple hostnames exist for same IP (e.g., CDN), prefer non-IP hostnames
                if dest_ip not in ip_to_hostname:
                    ip_to_hostname[dest_ip] = hostname
                # Keep the existing hostname unless new one is "better" (not an IP address)
                # This prevents IP-based names from overriding real hostnames
        
        # Use regular dict with manual initialization to ensure set is properly maintained
        hostname_totals = {}
        
        for flow in enriched_flows:
            traffic_type = self.classify_traffic_type(
                flow['src_ip'],
                flow['dest_ip'],
                flow['is_aws']
            )
            
            # Only include internet traffic (non-AWS, non-VPC-to-VPC)
            if traffic_type == 'internet':
                hostname = flow['hostname']
                src_ip = flow['src_ip']
                dest_ip = flow['dest_ip']
                dest_port = flow['dest_port']
                
                # BUGFIX: If no hostname, check if we know the hostname from other flows to same IP
                if hostname == "(No hostname)" and dest_ip in ip_to_hostname:
                    # Use the known hostname from the lookup table
                    hostname = ip_to_hostname[dest_ip]
                    aggregation_key = hostname
                elif hostname == "(No hostname)":
                    # Still no hostname - aggregate by dest IP and port combination
                    aggregation_key = f"{dest_ip}:{dest_port}"
                else:
                    # Use hostname as key
                    aggregation_key = hostname
                
                # Initialize entry if first time seeing this destination
                if aggregation_key not in hostname_totals:
                    hostname_totals[aggregation_key] = {
                        'bytes': 0,
                        'flow_count': 0,
                        'dest_port': dest_port,
                        'proto': None,
                        'source_ips': set(),
                        'dest_ip': dest_ip if hostname == "(No hostname)" else None,
                        'is_ip_based': (hostname == "(No hostname)")
                    }
                
                # Accumulate statistics
                hostname_totals[aggregation_key]['bytes'] += flow['bytes']
                hostname_totals[aggregation_key]['flow_count'] += 1
                hostname_totals[aggregation_key]['source_ips'].add(src_ip)
                
                # Set protocol from first flow
                if hostname_totals[aggregation_key]['proto'] is None:
                    hostname_totals[aggregation_key]['proto'] = flow['proto']
        
        # Convert sets to counts for serialization
        result = {}
        for destination, data in hostname_totals.items():
            result[destination] = {
                'bytes': data['bytes'],
                'flow_count': data['flow_count'],
                'unique_sources': len(data['source_ips']),
                'dest_port': data['dest_port'],
                'proto': data['proto'],
                'dest_ip': data.get('dest_ip'),
                'is_ip_based': data.get('is_ip_based', False)
            }
        
        return result
    
    # An AWS Region label inside a hostname, e.g. us-east-2, eu-west-1, us-gov-west-1.
    _REGION_LABEL = re.compile(r'^(?:us|eu|ap|sa|ca|me|af|il|mx|cn)(?:-gov|-iso[a-z]*)?-[a-z]+-\d+$')

    # Services reached over AWS addresses that no VPC endpoint can serve.
    # 'AMAZON' is an address AWS publishes only under its catch-all code, so the
    # actual service (and therefore any endpoint) cannot be determined.
    NO_VPC_ENDPOINT_SERVICES = frozenset({
        'CLOUDFRONT', 'CLOUDFRONT_ORIGIN_FACING', 'GLOBALACCELERATOR', 'AMAZON',
    })

    @classmethod
    def _service_from_hostname(cls, hostname: str) -> Optional[tuple]:
        """Work out (service, region) from an AWS hostname, or None.

        Region is None when the hostname carries no Region (e.g.
        bucket.s3.amazonaws.com); the caller then takes it from the IP.

        Handles the common AWS endpoint shapes:
          logs.us-east-2.amazonaws.com                 -> LOGS, us-east-2
          api.ecr.us-east-2.amazonaws.com              -> ECR_API, us-east-2
          <account>.dkr.ecr.us-east-2.amazonaws.com    -> ECR_DKR, us-east-2
          bucket.s3.dualstack.us-east-2.amazonaws.com  -> S3, us-east-2
          kms-fips.us-east-1.amazonaws.com             -> KMS, us-east-1
          bucket.s3-us-west-2.amazonaws.com (legacy)   -> S3, us-west-2
          d111111abcdef8.cloudfront.net                -> CLOUDFRONT, GLOBAL
        The service is the label just before the Region (ignoring 'dualstack'
        and 'fips'). ECR's API and image-layer (dkr) hostnames are separate
        services because each needs its own interface endpoint.
        """
        h = (hostname or '').strip().lower().rstrip('.')
        if h.endswith('.cloudfront.net'):
            return ('CLOUDFRONT', 'GLOBAL')
        if not h.endswith('.amazonaws.com'):
            return None
        labels = h[:-len('.amazonaws.com')].split('.')

        region_idx = None
        for i in range(len(labels) - 1, -1, -1):
            if cls._REGION_LABEL.match(labels[i]):
                region_idx = i
                break

        if region_idx is None:
            # Legacy S3 forms: s3-<region>, s3-external-1, or regionless s3.
            for label in reversed(labels):
                if label.startswith('s3-'):
                    rest = label[3:]
                    if cls._REGION_LABEL.match(rest):
                        return ('S3', rest)
                    if rest.startswith('external-'):
                        return ('S3', 'us-east-1')
            if labels and (labels[-1] == 's3' or labels[-1].startswith('s3-')):
                return ('S3', None)
            return None

        region = labels[region_idx]
        before = [lb for lb in labels[:region_idx] if lb not in ('dualstack', 'fips')]
        if not before:
            return None
        service = before[-1]
        if service.endswith('-fips'):
            service = service[:-len('-fips')]
        if service == 's3' or service.startswith('s3-'):
            return ('S3', region)
        if service == 'ecr':
            if len(before) >= 2 and before[-2] == 'dkr':
                return ('ECR_DKR', region)
            return ('ECR_API', region)
        return (service.upper().replace('-', '_'), region)

    @staticmethod
    def internet_hostname_coverage(hostname_aggregation: Dict[str, Dict]) -> Optional[float]:
        """Percent of Internet-tab traffic (bytes) shown under a hostname.

        Computed from the Internet tab's own rows: bytes in hostname rows divided
        by all Internet bytes (hostname rows plus IP:port rows). It therefore
        matches what the tab displays, including hostnames inferred for flows to
        an IP that was seen with that hostname. Returns None when there is no
        Internet traffic.
        """
        total = sum(v.get('bytes', 0) for v in hostname_aggregation.values())
        if total <= 0:
            return None
        named = sum(v.get('bytes', 0) for v in hostname_aggregation.values()
                    if not v.get('is_ip_based'))
        return named / total * 100.0

    @staticmethod
    def _is_private_for_drilldown(ip) -> bool:
        """Private-address test used by the drill-down filters.

        Uses ipaddress' is_private (the same test the drill-down dialogs have
        always used), which is broader than RFC1918 (it also covers loopback,
        link-local, etc.). Unparseable values count as not private.
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    @classmethod
    def build_source_breakdowns(cls, flows: List[Dict], internet_keys,
                                internal_dests) -> Dict[str, Any]:
        """Per-source-IP totals behind every drill-down row, for all three tabs.

        The drill-down dialogs show, for one row, each source IP's bytes and flow
        count. This computes those tables up front from the enriched flows, so the
        individual flows do not need to be kept or saved. The selection rules are
        exactly the ones the drill-downs have always applied:

          Internet tab, hostname row H: non-AWS flows whose hostname is H, plus
            non-AWS flows with no hostname whose dest IP is one of the dest IPs
            seen with H; destination must not be private.
          Internet tab, IP:port row: non-AWS flows with no hostname to that dest IP
            and port; destination must not be private.
          AWS Service tab, (service, region) row: all flows with that service and
            region.
          Internal tab, (dest IP, dest port) row: all flows to that dest IP and port.

        Args:
            flows: Enriched flow dicts (src_ip, dest_ip, dest_port, hostname,
                is_aws, aws_service, aws_region, bytes).
            internet_keys: Internet-tab row keys (hostname_aggregation keys).
            internal_dests: Iterable of (dest_ip, dest_port) Internal-tab rows.

        Returns:
            {'internet': {key: sources},
             'aws_service': {service: {region: sources}},
             'internal': {dest_ip: {dest_port: sources}}}
            where sources is {src_ip: {'bytes': int, 'flow_count': int}} and all
            keys are strings (so the structure survives a JSON round trip).
        """
        no_host = "(No hostname)"

        def add(table, flow):
            src = str(flow['src_ip'])
            entry = table.get(src)
            if entry is None:
                entry = table[src] = {'bytes': 0, 'flow_count': 0}
            entry['bytes'] += flow['bytes']
            entry['flow_count'] += 1

        # One pass to index the flows each tab's rules need.
        by_hostname = defaultdict(list)    # non-AWS flows by hostname
        no_host_by_ip = defaultdict(list)  # non-AWS flows with no hostname, by dest IP
        aws_service = {}
        internal_wanted = set((str(ip), str(port)) for ip, port in internal_dests)
        internal = {}
        for f in flows:
            if not f['is_aws']:
                by_hostname[f['hostname']].append(f)
                if f['hostname'] == no_host:
                    no_host_by_ip[f['dest_ip']].append(f)
            svc = aws_service.setdefault(str(f['aws_service']), {})
            add(svc.setdefault(str(f['aws_region']), {}), f)
            dest = (str(f['dest_ip']), str(f['dest_port']))
            if dest in internal_wanted:
                add(internal.setdefault(dest[0], {}).setdefault(dest[1], {}), f)

        internet = {}
        for key in internet_keys:
            sources = {}
            if ':' in key and not key.startswith('http'):
                ip, port = key.rsplit(':', 1)
                port = port.strip()
                for f in no_host_by_ip.get(ip, ()):
                    if (str(f['dest_port']) == port
                            and not cls._is_private_for_drilldown(f['dest_ip'])):
                        add(sources, f)
            else:
                named = by_hostname.get(key, [])
                ips = set(f['dest_ip'] for f in named)
                selected = list(named)
                if key != no_host:  # avoid counting the same no-hostname flow twice
                    for ip in ips:
                        selected.extend(no_host_by_ip.get(ip, ()))
                for f in selected:
                    if not cls._is_private_for_drilldown(f['dest_ip']):
                        add(sources, f)
            if sources:
                internet[key] = sources

        return {'internet': internet, 'aws_service': aws_service, 'internal': internal}

    def aggregate_by_service(self, enriched_flows: List[Dict]) -> Dict[str, Dict[str, int]]:
        """Aggregate AWS service traffic by service and region for Tab 2
        
        Args:
            enriched_flows: List of enriched flow dictionaries
            
        Returns:
            Dict mapping service -> region -> bytes
        """
        service_totals = defaultdict(lambda: defaultdict(int))
        
        for flow in enriched_flows:
            traffic_type = self.classify_traffic_type(
                flow['src_ip'],
                flow['dest_ip'],
                flow['is_aws']
            )
            
            # Only include AWS service traffic
            if traffic_type == 'aws_service':
                service = flow['aws_service']
                region = flow['aws_region']
                bytes_val = flow['bytes']
                service_totals[service][region] += bytes_val
        
        return dict(service_totals)
    
    def aggregate_vpc_to_vpc(self, enriched_flows: List[Dict]) -> List[Dict]:
        """Aggregate VPC-to-VPC traffic by directional pairs for Tab 3
        
        Uses (src_ip, dest_ip, dest_port) as aggregation key to avoid
        circular logic with bidirectional traffic.
        
        Args:
            enriched_flows: List of enriched flow dictionaries
            
        Returns:
            List of VPC-to-VPC connection dictionaries
        """
        vpc_pairs = {}
        
        for flow in enriched_flows:
            traffic_type = self.classify_traffic_type(
                flow['src_ip'],
                flow['dest_ip'],
                flow['is_aws']
            )
            
            # Only include VPC-to-VPC traffic
            if traffic_type == 'vpc_to_vpc':
                # Create directional key
                key = (flow['src_ip'], flow['dest_ip'], flow['dest_port'])
                
                if key not in vpc_pairs:
                    vpc_pairs[key] = {
                        'src_ip': flow['src_ip'],
                        'dest_ip': flow['dest_ip'],
                        'dest_port': flow['dest_port'],
                        'proto': flow['proto'],
                        'total_bytes': 0,
                        'flow_count': 0
                    }
                
                vpc_pairs[key]['total_bytes'] += flow['bytes']
                vpc_pairs[key]['flow_count'] += 1
        
        # Sort by traffic volume (descending)
        sorted_pairs = sorted(vpc_pairs.values(), 
                            key=lambda x: x['total_bytes'], 
                            reverse=True)
        
        return sorted_pairs
    
    def calculate_vpc_endpoint_recommendations(self, service_totals: Dict,
                                                window_hours: float = 730.0) -> List[Dict]:
        """Calculate VPC endpoint recommendations with cost-benefit analysis.

        CRITICAL: Interface endpoints are deployed in the FIREWALL's region (where the client is),
        not the destination service region. Therefore, endpoint cost is ALWAYS based on
        firewall region pricing, regardless of which region the service is in.

        SCOPING (must stay consistent with the UI columns):
          - traffic_gb / current_cost / endpoint_cost are WINDOW-scoped: the traffic
            seen and the data-processing cost for the analyzed window, plus the cost
            of running the equivalent endpoint for that same window.
          - monthly_savings is a PROJECTION: it answers "if this window's traffic
            repeated for a full month, what would deploying the endpoint save?" It is
            computed by projecting the window data-processing cost to a month
            (x 730/window_hours) and subtracting the endpoint's MONTHLY cost. This
            like-for-like (monthly vs monthly) comparison is what makes the number
            coherent - the previous code subtracted a monthly endpoint price from a
            window data cost, which under-reported savings by the window/month ratio.
          - DEPLOY/CONSIDER/SKIP thresholds compare the MONTHLY-projected volume
            against the (monthly) break-even, so they are scope-consistent too.

        Args:
            service_totals: Dict mapping service -> region -> bytes (window totals)
            window_hours: Length of the analyzed window in hours, used to project
                window figures to a month (730 hours). Defaults to 730 (=> no
                projection) for safety if a caller omits it.

        Returns:
            List of recommendation dictionaries sorted by projected monthly savings.
        """
        recommendations = []

        # Window -> month projection factor for volume/data cost, and the inverse
        # (month -> window) factor for expressing a monthly endpoint price over the
        # analyzed window.
        month_factor = (730.0 / window_hours) if window_hours else 1.0
        endpoint_window_factor = (window_hours / 730.0) if window_hours else 1.0

        for service, regions in service_totals.items():
            for region, total_bytes in regions.items():
                traffic_gb = total_bytes / (1024**3)  # window GB
                current_cost = traffic_gb * self.firewall_cost_per_gb  # window data cost

                # Monthly-projected volume / data cost (assumes window is representative).
                projected_monthly_gb = traffic_gb * month_factor
                projected_monthly_current = current_cost * month_factor

                is_same_region = (region == self.region)

                # Services that support cross-region interface endpoints (as of 2026)
                # Source: https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-cross-region-privatelink-support.html
                CROSS_REGION_SUPPORTED_SERVICES = {
                    'S3', 'LAMBDA', 'ECS', 'KINESIS_FIREHOSE', 
                    'IAM', 'ECR', 'ECR_API', 'ECR_DKR', 'KMS', 'KINESISANALYTICS', 'ROUTE53'
                }

                # Each branch sets:
                #   endpoint_type       - label
                #   endpoint_cost       - WINDOW-scoped cost of the equivalent endpoint
                #   monthly_savings     - PROJECTED monthly savings (monthly vs monthly)
                #   recommendation      - DEPLOY / CONSIDER / SKIP...
                # NOTE: ALL interface endpoints use firewall region pricing.
                if service in self.NO_VPC_ENDPOINT_SERVICES:
                    # e.g. CloudFront: AWS-owned, but no VPC endpoint can serve it,
                    # so there is nothing to deploy and no saving to project.
                    endpoint_type = 'N/A (no VPC endpoint)'
                    endpoint_cost = current_cost
                    monthly_savings = 0.0
                    recommendation = 'SKIP - No VPC endpoint available'
                elif service in ['S3', 'DYNAMODB']:
                    if is_same_region:
                        # Gateway endpoint (FREE) - always worth deploying.
                        endpoint_type = 'Gateway'
                        endpoint_cost = 0.0
                        monthly_savings = projected_monthly_current - 0.0
                        recommendation = 'DEPLOY'
                    else:
                        # Cross-region: Only recommend interface endpoint if supported.
                        if service in CROSS_REGION_SUPPORTED_SERVICES:
                            endpoint_type = 'Interface (cross-region)'
                            # Window-scoped endpoint cost: base fee prorated to the
                            # window + window data processing on the endpoint.
                            endpoint_cost = (self.interface_endpoint_monthly_cost * endpoint_window_factor
                                             + traffic_gb * self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
                            monthly_endpoint = (self.interface_endpoint_monthly_cost
                                                + projected_monthly_gb * self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
                            monthly_savings = projected_monthly_current - monthly_endpoint

                            # Thresholds compare MONTHLY-projected volume to break-even.
                            if projected_monthly_gb > self.cross_region_break_even:
                                recommendation = 'DEPLOY'
                            elif projected_monthly_gb > 20:
                                # S3 CRR (~$0.02/GB) may be a better alternative here.
                                recommendation = 'SKIP - Consider CRR instead'
                            else:
                                recommendation = 'SKIP'
                        else:
                            # Service doesn't support cross-region endpoints.
                            endpoint_type = 'N/A'
                            endpoint_cost = current_cost
                            monthly_savings = 0.0
                            recommendation = 'SKIP - Cross-region not supported'
                else:
                    # Interface endpoint (deployed in firewall region)
                    endpoint_type = 'Interface'

                    if is_same_region:
                        endpoint_cost = self.interface_endpoint_monthly_cost * endpoint_window_factor
                        monthly_endpoint = self.interface_endpoint_monthly_cost
                        monthly_savings = projected_monthly_current - monthly_endpoint

                        break_even_gb = self.same_region_break_even
                        if projected_monthly_gb > break_even_gb:
                            recommendation = 'DEPLOY'
                        elif projected_monthly_gb > (break_even_gb * 0.75):
                            recommendation = 'CONSIDER'
                        else:
                            recommendation = 'SKIP'
                    else:
                        # Cross-region for non-S3/DynamoDB services
                        if service in CROSS_REGION_SUPPORTED_SERVICES:
                            endpoint_cost = (self.interface_endpoint_monthly_cost * endpoint_window_factor
                                             + traffic_gb * self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
                            monthly_endpoint = (self.interface_endpoint_monthly_cost
                                                + projected_monthly_gb * self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
                            monthly_savings = projected_monthly_current - monthly_endpoint

                            break_even_gb = self.cross_region_break_even
                            if projected_monthly_gb > break_even_gb:
                                recommendation = 'DEPLOY'
                            elif projected_monthly_gb > (break_even_gb * 0.75):
                                recommendation = 'CONSIDER'
                            else:
                                recommendation = 'SKIP'
                        else:
                            # Service doesn't support cross-region endpoints.
                            endpoint_cost = current_cost
                            monthly_savings = 0.0
                            recommendation = 'SKIP - Cross-region not supported'

                recommendations.append({
                    'service': service,
                    'region': region,
                    'is_same_region': is_same_region,
                    'endpoint_type': endpoint_type,
                    'traffic_gb': round(traffic_gb, 2),
                    'current_cost': round(current_cost, 2),
                    'endpoint_cost': round(endpoint_cost, 2),
                    'monthly_savings': round(monthly_savings, 2),
                    'annual_savings': round(monthly_savings * 12, 0),
                    'recommendation': recommendation
                })

        # Sort by projected monthly savings (descending)
        recommendations.sort(key=lambda x: x['monthly_savings'], reverse=True)

        return recommendations
    
    def _step_fraction(self, step_key: str, update: Dict) -> float:
        """How far through its own step a progress update is (0.0 to 1.0)."""
        if update.get('chunk_total'):
            return min(1.0, max(0.0, update.get('chunk_current', 0) / float(update['chunk_total'])))
        if 'percent' in update:
            pct = min(100.0, max(0.0, float(update['percent'])))
            if step_key == 'correlate':
                # Correlation reports two passes that each run 0-100%: grouping
                # flow legs, then identifying AWS services. Each is half the step.
                if update.get('stage') == 'Identifying AWS services':
                    return 0.5 + pct / 200.0
                return pct / 200.0
            return pct / 100.0
        return 0.0

    def _step_callback(self, progress_callback: Optional[Callable],
                       step_key: str) -> Optional[Callable]:
        """Wrap progress_callback so each update also carries overall progress.

        Adds: step (1-based), step_total, step_name, overall_percent (0-100, never
        decreasing across the run) and throttle_retries. The original keys are
        passed through unchanged. Returns None when there is no callback.
        """
        if progress_callback is None:
            return None
        keys = [s[0] for s in self.ANALYSIS_STEPS]
        index = keys.index(step_key)
        name = self.ANALYSIS_STEPS[index][1]
        weight = self.ANALYSIS_STEPS[index][2]
        base = sum(s[2] for s in self.ANALYSIS_STEPS[:index])
        total_weight = sum(s[2] for s in self.ANALYSIS_STEPS)

        def callback(update: Dict):
            enriched = dict(update)
            overall = (base + weight * self._step_fraction(step_key, update)) / total_weight * 100.0
            self._overall_percent = max(self._overall_percent, min(100.0, overall))
            enriched['step'] = index + 1
            enriched['step_total'] = len(self.ANALYSIS_STEPS)
            enriched['step_name'] = name
            enriched['overall_percent'] = self._overall_percent
            enriched['throttle_retries'] = self.throttle_retries
            progress_callback(enriched)

        return callback

    def analyze(self, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Main analysis method
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dict containing analysis results:
            - source_breakdowns: Per-source-IP totals behind each drill-down row
              (see build_source_breakdowns)
            - hostname_aggregation: Dict of internet traffic by hostname
            - service_totals: Dict of AWS service traffic by service/region
            - vpc_to_vpc_connections: List of VPC-to-VPC connections
            - vpc_endpoint_recommendations: List of VPC endpoint recommendations
            - metadata: Analysis metadata (timestamp, region, days, etc.)
        """
        try:
            # Each step reports through its own wrapper, which adds the overall
            # step number and an overall percentage (see _step_callback) so the
            # progress dialog can show where the whole run is.
            self._overall_percent = 0.0
            totals_cb = self._step_callback(progress_callback, 'totals')
            flows_cb = self._step_callback(progress_callback, 'flows')
            alerts_cb = self._step_callback(progress_callback, 'alerts')
            correlate_cb = self._step_callback(progress_callback, 'correlate')
            aggregate_cb = self._step_callback(progress_callback, 'aggregate')

            # Step 1: Query AUTHORITATIVE traffic totals via server-side aggregation.
            # This runs FIRST because it is the source of truth for total/per-AZ
            # bytes (not subject to the 10K-row limit) AND it returns the total
            # netflow record count, which we use to size the raw per-flow query's
            # chunking correctly in a single pass.
            if totals_cb:
                totals_cb({
                    'stage': 'Querying traffic totals',
                    'status': 'Starting...'
                })
            
            totals_result = self.query_flow_totals(totals_cb)
            
            if self.cancel_requested or totals_result == (None, None, None, None):
                return None
            
            authoritative_total_bytes, authoritative_az_bytes, totals_bytes_scanned, total_records = totals_result
            
            # Step 2: Query per-flow byte totals via server-side aggregation (for
            # top-talkers, drill-down, and the per-hostname/service/VPC breakdowns).
            # Unlike the old raw-row retrieval, this sums bytes server-side grouped
            # by flow leg, so the breakdowns are byte-accurate at any volume. Seeded
            # with the record count to size chunking (groups are fewer than records,
            # so this is a conservative bound).
            if flows_cb:
                flows_cb({
                    'stage': 'Querying flow breakdown',
                    'status': 'Starting...'
                })
            
            flow_result = self.query_flow_grouped(expected_records=total_records,
                                                  progress_callback=flows_cb)
            
            if self.cancel_requested or flow_result == (None, None, None):
                return None
            
            # grouped_rows are per-flow-leg aggregates. flow_truncated indicates the
            # rare case where even a <=60s window exceeded the 10K GROUP cap (the
            # breakdown becomes a sample); authoritative totals remain exact.
            grouped_rows, flow_bytes_scanned, flow_truncated = flow_result
            
            # Step 3: Query alert logs
            if alerts_cb:
                alerts_cb({
                    'stage': 'Querying alert logs',
                    'status': 'Starting...'
                })
            
            alert_result = self.query_alert_logs(alerts_cb)
            
            if self.cancel_requested or alert_result == (None, None, None, None):
                return None
            
            # Unpack alert results (alert_logs, earliest_alert_ts, latest_alert_ts, bytes_scanned)
            alert_logs, earliest_alert_ts, latest_alert_ts, alert_bytes_scanned = alert_result
            
            # Step 4: Correlate logs
            if correlate_cb:
                correlate_cb({
                    'stage': 'Correlating logs',
                    'status': 'Starting correlation...'
                })
            
            result_tuple = self.correlate_logs(grouped_rows, alert_logs, correlate_cb)
            
            if self.cancel_requested or result_tuple == (None, None, None, None, None):
                return None
            
            # Unpack correlation results (gets flow timestamps, AZs, and AZ traffic distribution)
            enriched_flows, unique_azs, az_traffic, earliest_flow_ts, latest_flow_ts = result_tuple
            
            # CRITICAL: Combine timestamps from BOTH log sources for most accurate timespan
            # Use earliest timestamp from either source and latest from either source
            earliest_timestamp = None
            latest_timestamp = None
            
            # Consider flow log timestamps
            if earliest_flow_ts:
                earliest_timestamp = earliest_flow_ts
            if latest_flow_ts:
                latest_timestamp = latest_flow_ts
            
            # Consider alert log timestamps (may be more recent or older)
            if earliest_alert_ts:
                if earliest_timestamp is None or earliest_alert_ts < earliest_timestamp:
                    earliest_timestamp = earliest_alert_ts
            
            if latest_alert_ts:
                if latest_timestamp is None or latest_alert_ts > latest_timestamp:
                    latest_timestamp = latest_alert_ts
            
            # Step 5: Aggregate by hostname (Tab 1)
            if aggregate_cb:
                aggregate_cb({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing internet traffic...',
                    'percent': 0
                })
            
            hostname_aggregation = self.aggregate_by_hostname(enriched_flows)
            
            # Step 6: Aggregate by service (Tab 2)
            if aggregate_cb:
                aggregate_cb({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing AWS service traffic...',
                    'percent': 40
                })
            
            service_totals = self.aggregate_by_service(enriched_flows)
            
            # Step 7: Aggregate VPC-to-VPC (Tab 3)
            if aggregate_cb:
                aggregate_cb({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing VPC-to-VPC traffic...',
                    'percent': 70
                })
            
            vpc_to_vpc_connections = self.aggregate_vpc_to_vpc(enriched_flows)
            
            # Per-source-IP tables behind each drill-down row (all three tabs).
            # These replace keeping/saving every individual flow.
            if aggregate_cb:
                aggregate_cb({
                    'stage': 'Aggregating traffic',
                    'status': 'Building source IP breakdowns...',
                    'percent': 80
                })
            
            source_breakdowns = self.build_source_breakdowns(
                enriched_flows,
                hostname_aggregation.keys(),
                [(c['dest_ip'], c['dest_port']) for c in vpc_to_vpc_connections]
            )
            
            # Window length in hours - the single scope basis for both the fixed
            # (endpoint) cost and the window->month projection used by the
            # recommendations. Derived from the shared query window so it matches
            # exactly what was queried.
            window_start, window_end = self._get_query_window()
            window_hours = (window_end - window_start).total_seconds() / 3600
            if window_hours <= 0:
                window_hours = self.days * 24  # defensive fallback
            
            # Step 8: Calculate VPC endpoint recommendations
            if aggregate_cb:
                aggregate_cb({
                    'stage': 'Calculating recommendations',
                    'status': 'Analyzing VPC endpoint opportunities...',
                    'percent': 90
                })
            
            vpc_endpoint_recommendations = self.calculate_vpc_endpoint_recommendations(
                service_totals, window_hours=window_hours
            )
            
            # Calculate total traffic and costs
            #
            # AUTHORITATIVE TOTALS: total_bytes comes from the server-side
            # aggregation query (query_flow_totals), NOT from summing the raw
            # per-flow sample. The raw sample is capped at 10,000 rows per query
            # period, so summing it under-reports whenever traffic is high enough
            # to hit that cap. The aggregation sums every netflow record in range
            # and cannot be truncated by row count.
            #
            # raw_sample_bytes is retained for diagnostics / coverage math and to
            # fall back on if the aggregation somehow returned nothing.
            raw_sample_bytes = sum(flow['bytes'] for flow in enriched_flows)
            
            if authoritative_total_bytes and authoritative_total_bytes > 0:
                total_bytes = authoritative_total_bytes
            else:
                # Aggregation returned no data (e.g. empty range, or a log format
                # without availability_zone). Fall back to the raw sample sum so we
                # never report zero when we do have per-flow rows.
                total_bytes = raw_sample_bytes
            
            total_gb = total_bytes / (1024**3)
            total_cost = total_gb * self.firewall_cost_per_gb
            
            # Calculate hostname coverage statistics.
            # NOTE: hostname enrichment can only be computed over the per-flow
            # sample we actually retrieved. bytes_coverage_pct is expressed against
            # the AUTHORITATIVE total so it honestly reflects that, when the sample
            # is truncated, hostnames cover only part of the real traffic.
            flows_with_hostname = sum(1 for f in enriched_flows if f['hostname'] != "(No hostname)")
            hostname_coverage_pct = (flows_with_hostname / len(enriched_flows) * 100) if enriched_flows else 0
            
            bytes_with_hostname = sum(f['bytes'] for f in enriched_flows if f['hostname'] != "(No hostname)")
            bytes_coverage_pct = (bytes_with_hostname / total_bytes * 100) if total_bytes > 0 else 0
            
            # Calculate CloudWatch Logs Insights query cost at the region's rate
            # (the log groups are queried in the firewall's region; see
            # CLOUDWATCH_LOGS_INSIGHTS_PRICING). Includes the grouped per-flow
            # aggregation, the authoritative totals, the alert queries and the
            # chunk-planning (density) queries.
            total_bytes_scanned = flow_bytes_scanned + totals_bytes_scanned + alert_bytes_scanned
            cloudwatch_gb_scanned = total_bytes_scanned / (1024**3)
            cloudwatch_query_cost = cloudwatch_gb_scanned * self.cloudwatch_price_per_gb
            
            # Calculate firewall endpoint costs.
            #
            # AZ attribution uses the authoritative per-AZ byte distribution from
            # query_flow_totals (authoritative_az_bytes). unique_azs is the union
            # of AZs seen in either source, so an endpoint that only appears in the
            # aggregation (e.g. because its per-flow rows were truncated away) is
            # still counted. The '' bucket (records with no availability_zone) is
            # excluded from per-endpoint attribution but its bytes remain in the
            # grand total.
            endpoint_hourly_rate = self.ENDPOINT_HOURLY_PRICING.get(self.region, 0.395)
            
            az_traffic_authoritative = {
                az: b for az, b in authoritative_az_bytes.items() if az
            } if authoritative_az_bytes else {}
            
            # Fall back to the sample-derived az_traffic only if the aggregation
            # produced no AZ attribution at all.
            if not az_traffic_authoritative:
                az_traffic_authoritative = {az: b for az, b in az_traffic.items() if az}
            
            all_azs = set(a for a in unique_azs if a) | set(az_traffic_authoritative.keys())
            num_endpoints = len(all_azs)
            
            # Endpoint (fixed) cost is billed per provisioned hour regardless of
            # traffic. Normally we bill for the FULL selected window: if an endpoint
            # processed any traffic during the window it is assumed to have been
            # provisioned for the whole window. This intentionally avoids
            # under-counting endpoints that were idle at the window edges.
            #
            # SPECIAL CASE - log coverage gap: if the logs we found cover materially
            # less than the selected window (observed span misses either edge of the
            # window by more than COVERAGE_GAP_THRESHOLD_HOURS), we cannot trust the
            # window as the provisioning duration. The missing time may be logs that
            # aged out of CloudWatch retention, OR a firewall that simply did not
            # exist for the whole window (e.g. deployed mid-window). We cannot tell
            # these apart from the data, so we bill the fixed cost on the OBSERVED
            # span instead of the full window - a defensible lower bound. The
            # endpoint COUNT is unchanged (still the AZs actually observed), so an
            # endpoint that saw no traffic in the observed span is not counted.
            COVERAGE_GAP_THRESHOLD_HOURS = 6.0

            coverage_gap = False
            observed_span_hours = None
            if earliest_timestamp is not None and latest_timestamp is not None:
                observed_span_hours = (latest_timestamp - earliest_timestamp).total_seconds() / 3600
                start_shortfall = (earliest_timestamp - window_start).total_seconds() / 3600
                end_shortfall = (window_end - latest_timestamp).total_seconds() / 3600
                # A positive shortfall means observed data starts later than / ends
                # earlier than the requested window edge.
                if (start_shortfall > COVERAGE_GAP_THRESHOLD_HOURS
                        or end_shortfall > COVERAGE_GAP_THRESHOLD_HOURS):
                    coverage_gap = True

            if coverage_gap and observed_span_hours and observed_span_hours > 0:
                # Bill the fixed cost on the observed span (lower bound).
                runtime_hours = observed_span_hours
                runtime_basis = 'observed_span'
            else:
                # Normal path: bill the full selected window (unchanged behaviour).
                # This also covers the degenerate gap case (span <= 0), where falling
                # back to the window is safer than producing a zero endpoint cost.
                coverage_gap = False
                runtime_hours = window_hours
                runtime_basis = 'window'
            
            # Calculate per-endpoint costs with traffic volume
            endpoint_costs = []
            sorted_azs = sorted(all_azs)
            for az in sorted_azs:
                cost = endpoint_hourly_rate * runtime_hours
                az_bytes = az_traffic_authoritative.get(az, 0)
                az_gb = az_bytes / (1024**3)
                az_pct = (az_bytes / total_bytes * 100) if total_bytes > 0 else 0
                
                endpoint_costs.append({
                    'availability_zone': az,
                    'hours': round(runtime_hours, 2),
                    'hourly_rate': endpoint_hourly_rate,
                    'total_cost': round(cost, 2),
                    'traffic_gb': round(az_gb, 2),
                    'traffic_pct': round(az_pct, 1)
                })
            
            total_endpoint_cost = sum(e['total_cost'] for e in endpoint_costs)
            
            # Return comprehensive results
            return {
                'source_breakdowns': source_breakdowns,
                'hostname_aggregation': hostname_aggregation,
                'service_totals': service_totals,
                'vpc_to_vpc_connections': vpc_to_vpc_connections,
                'vpc_endpoint_recommendations': vpc_endpoint_recommendations,
                'metadata': {
                    'timestamp': datetime.now(),
                    'log_group': self.log_group,
                    'alert_log_group': self.alert_log_group,
                    'region': self.region,
                    'time_range_days': self.days,
                    'total_flows': len(enriched_flows),
                    'total_bytes': total_bytes,
                    'total_gb': round(total_gb, 2),
                    'total_cost': round(total_cost, 2),
                    'flow_logs_retrieved': len(grouped_rows),
                    'alert_logs_retrieved': len(alert_logs),
                    'flows_with_hostname': flows_with_hostname,
                    'hostname_coverage_pct': round(hostname_coverage_pct, 1),
                    'bytes_with_hostname': bytes_with_hostname,
                    'bytes_coverage_pct': round(bytes_coverage_pct, 1),
                    'endpoint_costs': endpoint_costs,
                    'total_endpoint_cost': round(total_endpoint_cost, 2),
                    'num_endpoints': num_endpoints,
                    'endpoint_hourly_rate': endpoint_hourly_rate,
                    'runtime_hours': round(runtime_hours, 2),
                    # Whether the endpoint-hour cost was billed on the full selected
                    # window ('window') or, in the log-coverage-gap special case, on
                    # the shorter observed data span ('observed_span').
                    'runtime_basis': runtime_basis,
                    # True when the observed log span is materially shorter than the
                    # selected window (logs likely aged out of retention, or the
                    # firewall did not exist for the whole window). The UI uses this
                    # to warn that totals reflect only the observed span.
                    'coverage_gap': bool(coverage_gap),
                    'observed_span_hours': (round(observed_span_hours, 2)
                                            if observed_span_hours else None),
                    'earliest_timestamp': earliest_timestamp,
                    'latest_timestamp': latest_timestamp,
                    'start_date': self.start_date.strftime('%Y-%m-%d') if self.use_custom_dates else None,
                    'end_date': self.end_date.strftime('%Y-%m-%d') if self.use_custom_dates else None,
                    'use_custom_dates': self.use_custom_dates,
                    'cloudwatch_gb_scanned': round(cloudwatch_gb_scanned, 3),
                    'cloudwatch_query_cost': round(cloudwatch_query_cost, 2),
                    'cloudwatch_price_per_gb': self.cloudwatch_price_per_gb,
                    # --- Data completeness / accuracy diagnostics ---
                    # total_bytes/total_gb/total_cost above are authoritative
                    # (server-side aggregation). The fields below expose whether the
                    # per-flow SAMPLE used for breakdowns/top-talkers was truncated
                    # by the 10K-row limit, so the UI can flag partial breakdowns.
                    'flow_bytes_truncated': bool(flow_truncated),
                    'is_partial': bool(flow_truncated),
                    # True when the region was missing from the pricing tables and
                    # us-east-1 fallback rates were used (costs may be inaccurate).
                    'pricing_fallback': bool(self.pricing_fallback),
                    'authoritative_total_bytes': int(authoritative_total_bytes or 0),
                    'raw_sample_bytes': int(raw_sample_bytes),
                    # Fraction (0-1) of authoritative bytes represented by the
                    # per-flow sample. 1.0 when not truncated; <1.0 indicates the
                    # category/service/hostname breakdowns cover only part of traffic.
                    'sample_bytes_fraction': (
                        round(min(1.0, raw_sample_bytes / total_bytes), 4)
                        if total_bytes > 0 else 1.0
                    )
                }
            }
            
        except Exception as e:
            # Re-raise with context
            raise Exception(f"Analysis failed: {str(e)}")
    
    # Version of the 'traffic_analysis' section written by save_results. Files
    # without the field are the original format (per-flow 'top_talkers').
    TRAFFIC_FORMAT_VERSION = 2

    # Above this size, save_results reads only the part of the existing file it
    # keeps (everything before the traffic section) instead of parsing it all.
    _PARTIAL_READ_MIN_BYTES = 50 * 1024 * 1024

    @staticmethod
    def _read_existing_stats_for_save(stats_file_path: str) -> Dict[str, Any]:
        """Read the parts of an existing .stats file that a save must preserve.

        save_results keeps only the rule-usage data (and the version markers) from
        the existing file; the traffic section is replaced. Older files can be
        several GB because their traffic section held every flow, so for large
        files this parses only the text BEFORE the top-level traffic section.

        The cut point is found by a line that is exactly two spaces of indent
        followed by the "traffic_analysis" key. With the indent=2 layout that
        save_results writes, only top-level keys sit at that indent (a string
        value cannot contain a raw newline), so the match is unambiguous. If
        anything about the partial read fails, the whole file is parsed instead.
        Returns {} if the file cannot be read at all (save then starts fresh).
        """
        try:
            if os.path.getsize(stats_file_path) >= TrafficAnalyzer._PARTIAL_READ_MIN_BYTES:
                marker = b'\n  "traffic_analysis": '
                head = b''
                with open(stats_file_path, 'rb') as f:
                    while True:
                        chunk = f.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        # Re-scan a small overlap so a marker split across reads is found.
                        scan_from = max(0, len(head) - len(marker))
                        head += chunk
                        cut = head.find(marker, scan_from)
                        if cut < 0 and len(head) > 256 * 1024 * 1024:
                            break  # no traffic section near the start; read it all
                        if cut >= 0:
                            text = head[:cut].decode('utf-8').rstrip().rstrip(',') + '\n}'
                            data = json.loads(text)
                            if isinstance(data, dict):
                                return data
                            break
        except Exception:
            pass  # fall back to a full read
        try:
            with open(stats_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}  # If file is corrupt, start fresh

    @staticmethod
    def save_results(results: Dict[str, Any], stats_file_path: str):
        """Save traffic analysis results to .stats file
        
        This method saves results in the unified v2.0 format that supports both
        rule usage analysis and traffic analysis data.
        
        Args:
            results: Analysis results dictionary from analyze()
            stats_file_path: Path to .stats file (e.g., 'user_files/myrules.stats')
        """
        # Load existing stats file if it exists (may contain rule usage data)
        existing_data = {}
        if os.path.exists(stats_file_path):
            existing_data = TrafficAnalyzer._read_existing_stats_for_save(stats_file_path)
        
        # Upgrade v1.0 format to v2.0 if needed
        if existing_data.get('version') == '1.0':
            # Wrap v1.0 rule usage data
            rule_usage_data = {k: v for k, v in existing_data.items() if k != 'version'}
            existing_data = {
                'version': '2.0',
                'file_type': 'unified_stats',
                'rule_usage_analysis': rule_usage_data
            }
        
        # Prepare traffic analysis data for saving
        metadata = results['metadata']
        
        # Convert datetime objects to ISO strings for JSON serialization
        timestamp_str = metadata['timestamp'].isoformat()
        earliest_ts_str = metadata['earliest_timestamp'].isoformat() if metadata.get('earliest_timestamp') else None
        latest_ts_str = metadata['latest_timestamp'].isoformat() if metadata.get('latest_timestamp') else None
        
        traffic_data = {
            # Format of this section. 2 = per-source drill-down tables
            # ('source_breakdowns') instead of every individual flow ('top_talkers').
            'traffic_format_version': TrafficAnalyzer.TRAFFIC_FORMAT_VERSION,
            'timestamp': timestamp_str,
            'log_group': metadata['log_group'],
            'alert_log_group': metadata['alert_log_group'],
            'region': metadata['region'],
            'time_range_days': metadata['time_range_days'],
            'start_date': metadata.get('start_date'),
            'end_date': metadata.get('end_date'),
            'use_custom_dates': metadata.get('use_custom_dates', False),
            
            # Metadata summary
            'metadata': {
                'total_flows': metadata['total_flows'],
                'total_bytes': metadata['total_bytes'],
                'total_gb': metadata['total_gb'],
                'total_cost': metadata['total_cost'],
                'hostname_coverage_pct': metadata['hostname_coverage_pct'],
                'cloudwatch_query_cost': metadata['cloudwatch_query_cost'],
                'cloudwatch_gb_scanned': metadata.get('cloudwatch_gb_scanned', 0),
                'cloudwatch_price_per_gb': metadata.get('cloudwatch_price_per_gb', 0.005),
                'num_endpoints': metadata['num_endpoints'],
                'runtime_hours': metadata['runtime_hours'],
                'runtime_basis': metadata.get('runtime_basis', 'window'),
                'coverage_gap': metadata.get('coverage_gap', False),
                'observed_span_hours': metadata.get('observed_span_hours'),
                'earliest_timestamp': earliest_ts_str,
                'latest_timestamp': latest_ts_str,
                'endpoint_costs': metadata['endpoint_costs'],
                # Data completeness diagnostics (preserved so cached/loaded views
                # can still show the partial-data notice). Defaulted with .get so
                # older cache files remain loadable.
                'flow_bytes_truncated': metadata.get('flow_bytes_truncated', False),
                'is_partial': metadata.get('is_partial', False),
                'pricing_fallback': metadata.get('pricing_fallback', False),
                'authoritative_total_bytes': metadata.get('authoritative_total_bytes', 0),
                'raw_sample_bytes': metadata.get('raw_sample_bytes', 0),
                'sample_bytes_fraction': metadata.get('sample_bytes_fraction', 1.0)
            },
            
            # Aggregated data (sufficient for UI display)
            'hostname_aggregation': results['hostname_aggregation'],
            'service_totals': results['service_totals'],
            'vpc_to_vpc_connections': results['vpc_to_vpc_connections'],
            'vpc_endpoint_recommendations': results['vpc_endpoint_recommendations'],
            
            # Per-source-IP tables for the drill-down dialogs (all three tabs).
            # Replaces the old per-flow 'top_talkers' list, which made large
            # analyses multi-GB files.
            'source_breakdowns': results['source_breakdowns']
        }
        
        # Build unified v2.0 structure
        unified_data = {
            'version': '2.0',
            'file_type': 'unified_stats'
        }
        
        # Preserve existing rule usage data if present
        if 'rule_usage_analysis' in existing_data:
            unified_data['rule_usage_analysis'] = existing_data['rule_usage_analysis']
        
        # Add new traffic analysis data
        unified_data['traffic_analysis'] = traffic_data
        
        # Save to file
        with open(stats_file_path, 'w', encoding='utf-8') as f:
            json.dump(unified_data, f, indent=2)
    
    @staticmethod
    def load_results(stats_file_path: str) -> Optional[Dict[str, Any]]:
        """Load traffic analysis results from .stats file
        
        Args:
            stats_file_path: Path to .stats file
            
        Returns:
            Analysis results dictionary compatible with show_results_window(),
            or None if no traffic data in file
        """
        if not os.path.exists(stats_file_path):
            return None
        
        try:
            with open(stats_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check if file contains traffic analysis data
            traffic_data = data.get('traffic_analysis')
            if not traffic_data:
                return None
            
            # Parse back datetime objects
            metadata = traffic_data['metadata']
            timestamp = datetime.fromisoformat(traffic_data['timestamp'])
            earliest_ts = datetime.fromisoformat(metadata['earliest_timestamp']) if metadata.get('earliest_timestamp') else None
            latest_ts = datetime.fromisoformat(metadata['latest_timestamp']) if metadata.get('latest_timestamp') else None
            
            # Drill-down tables. Current files store them directly; older files
            # stored every flow ('top_talkers'), so build the same tables from
            # those flows (the flows themselves are not kept). The next save then
            # writes the current format.
            source_breakdowns = traffic_data.get('source_breakdowns')
            if source_breakdowns is None:
                source_breakdowns = TrafficAnalyzer.build_source_breakdowns(
                    traffic_data.get('top_talkers', []),
                    traffic_data['hostname_aggregation'].keys(),
                    [(c['dest_ip'], c['dest_port'])
                     for c in traffic_data['vpc_to_vpc_connections']]
                )
            
            # Reconstruct results dictionary compatible with UI
            results = {
                'source_breakdowns': source_breakdowns,
                'hostname_aggregation': traffic_data['hostname_aggregation'],
                'service_totals': traffic_data['service_totals'],
                'vpc_to_vpc_connections': traffic_data['vpc_to_vpc_connections'],
                'vpc_endpoint_recommendations': traffic_data['vpc_endpoint_recommendations'],
                'metadata': {
                    'timestamp': timestamp,
                    'log_group': traffic_data['log_group'],
                    'alert_log_group': traffic_data['alert_log_group'],
                    'region': traffic_data['region'],
                    'time_range_days': traffic_data['time_range_days'],
                    'start_date': traffic_data.get('start_date'),
                    'end_date': traffic_data.get('end_date'),
                    'use_custom_dates': traffic_data.get('use_custom_dates', False),
                    'total_flows': metadata['total_flows'],
                    'total_bytes': metadata['total_bytes'],
                    'total_gb': metadata['total_gb'],
                    'total_cost': metadata['total_cost'],
                    'hostname_coverage_pct': metadata['hostname_coverage_pct'],
                    'cloudwatch_query_cost': metadata['cloudwatch_query_cost'],
                    'num_endpoints': metadata['num_endpoints'],
                    'runtime_hours': metadata['runtime_hours'],
                    # Coverage-gap diagnostics; default to the normal (full-window)
                    # basis so older cache files without these keys load cleanly.
                    'runtime_basis': metadata.get('runtime_basis', 'window'),
                    'coverage_gap': metadata.get('coverage_gap', False),
                    'observed_span_hours': metadata.get('observed_span_hours'),
                    'earliest_timestamp': earliest_ts,
                    'latest_timestamp': latest_ts,
                    'endpoint_costs': metadata['endpoint_costs'],
                    'total_endpoint_cost': sum(e['total_cost'] for e in metadata['endpoint_costs']),
                    'endpoint_hourly_rate': metadata['endpoint_costs'][0]['hourly_rate'] if metadata['endpoint_costs'] else 0.395,
                    'flow_logs_retrieved': 0,  # Not saved
                    'alert_logs_retrieved': 0,  # Not saved
                    'flows_with_hostname': 0,  # Not saved
                    'bytes_with_hostname': 0,  # Not saved
                    'bytes_coverage_pct': 0,  # Not saved
                    # Saved since the per-region query rate was added; older files
                    # have neither (their cost was computed at $0.005/GB).
                    'cloudwatch_gb_scanned': metadata.get('cloudwatch_gb_scanned', 0),
                    'cloudwatch_price_per_gb': metadata.get('cloudwatch_price_per_gb', 0.005),
                    # Data completeness diagnostics (defaulted for older cache files
                    # written before these fields existed).
                    'flow_bytes_truncated': metadata.get('flow_bytes_truncated', False),
                    'is_partial': metadata.get('is_partial', False),
                    'pricing_fallback': metadata.get('pricing_fallback', False),
                    'authoritative_total_bytes': metadata.get('authoritative_total_bytes', 0),
                    'raw_sample_bytes': metadata.get('raw_sample_bytes', 0),
                    'sample_bytes_fraction': metadata.get('sample_bytes_fraction', 1.0)
                }
            }
            
            return results
            
        except Exception as e:
            print(f"Error loading traffic analysis from {stats_file_path}: {str(e)}")
            return None
    
    @staticmethod
    def has_cached_results(stats_file_path: str) -> bool:
        """Check if .stats file contains cached traffic analysis results
        
        Args:
            stats_file_path: Path to .stats file
            
        Returns:
            True if file exists and contains traffic analysis data
        """
        if not os.path.exists(stats_file_path):
            return False
        
        try:
            with open(stats_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return 'traffic_analysis' in data
        except:
            return False
