"""
Traffic Analyzer - CloudWatch Log Analysis for Network Firewall

Analyzes AWS Network Firewall logs from CloudWatch to provide:
1. Traffic visibility (Top Talkers with hostname/SNI)
2. VPC endpoint cost optimization recommendations
3. Internet vs AWS service vs VPC-to-VPC traffic breakdown

Author: Suricata Generator Team
Created: 2026-01-25
"""

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
    
    # CloudWatch Logs Insights query statuses that mean "done" (stop polling).
    # Includes Timeout/Unknown so a query in those states does not poll forever.
    _TERMINAL_QUERY_STATUSES = ('Complete', 'Failed', 'Cancelled', 'Timeout', 'Unknown')
    
    # AWS Network Firewall data processing costs by region (per GB).
    # Source: AWS Price List API (ServiceCode AWSNetworkFirewall), validated
    # 2026-08-21 (pricing effective 2026-02-01). Nearly all regions are $0.065/GB;
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
    # '<region>-VpcEndpoint-Hours'), validated 2026-08-21.
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
    
    # Interface endpoint data processing (first tier ~$0.01/GB in most regions)
    INTERFACE_ENDPOINT_DATA_COST_PER_GB = 0.01
    
    # AWS Network Firewall endpoint (hourly) costs by region
    # AWS Network Firewall standard PRIMARY endpoint hourly cost by region.
    # Source: AWS Price List API (ServiceCode AWSNetworkFirewall, usagetype
    # '<region>-Endpoint-Hour'), validated 2026-08-21 (pricing effective
    # 2026-02-01). Most regions are $0.395/hr; newer/edge regions carry a premium.
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
        
        # Track whether ANY pricing table lacked this region, so results can be
        # flagged. When true, the figures use us-east-1 fallback rates and may not
        # reflect the region's real (often higher) pricing.
        self.pricing_fallback = (
            region not in self.FIREWALL_PRICING
            or region not in self.ENDPOINT_HOURLY_PRICING
            or region not in self.INTERFACE_ENDPOINT_PRICING
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
            response = self.logs_client.start_query(
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

            result = self.logs_client.get_query_results(queryId=query_id)
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
        SAFE_CHUNK_ROWS = 9000

        if not expected_records or expected_records <= SAFE_CHUNK_ROWS:
            rows, scanned, truncated = self._query_grouped_range_adaptive(
                start_time, end_time, progress_callback
            )
            if self.cancel_requested:
                return (None, None, None)
            return (rows, scanned, truncated)

        num_chunks = max(1, -(-expected_records // SAFE_CHUNK_ROWS))  # ceil division
        total_duration = end_time - start_time
        chunk_duration = total_duration / num_chunks

        if progress_callback:
            progress_callback({
                'stage': 'Querying flow breakdown',
                'status': f'Aggregating per-flow bytes in {num_chunks} chunks...',
                'phase': 'flow_chunks',
                'chunk_current': 0,
                'chunk_total': num_chunks,
            })

        # Merge groups across chunks by their full identifying key. bytes/recs are
        # additive; timestamps take the min/max across chunks. A flow_id is
        # time-local so this cannot mis-merge distinct flows.
        merged = {}
        total_bytes_scanned = 0
        truncated = False

        for chunk_num in range(num_chunks):
            if self.cancel_requested:
                return (None, None, None)

            raw_start = start_time + (chunk_duration * chunk_num)
            chunk_start = raw_start if chunk_num == 0 else raw_start + timedelta(seconds=1)
            chunk_end = (end_time if chunk_num == num_chunks - 1
                         else start_time + (chunk_duration * (chunk_num + 1)))

            if progress_callback:
                progress_callback({
                    'stage': 'Querying flow breakdown (chunked)',
                    'status': f'Chunk {chunk_num + 1}/{num_chunks}...',
                    'phase': 'flow_chunks',
                    'chunk_current': chunk_num + 1,
                    'chunk_total': num_chunks,
                })

            chunk_rows, chunk_bytes, chunk_trunc = self._query_grouped_range_adaptive(
                chunk_start, chunk_end, progress_callback
            )
            if self.cancel_requested:
                return (None, None, None)

            total_bytes_scanned += chunk_bytes
            if chunk_trunc:
                truncated = True
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

        rows = list(merged.values())
        if progress_callback:
            status_msg = f'Aggregated {len(rows):,} flow legs from {num_chunks} chunks'
            if truncated:
                status_msg += ' (breakdown sampled; totals unaffected)'
            progress_callback({
                'stage': 'Querying flow breakdown',
                'status': status_msg,
                'phase': 'flow_chunks',
                'chunk_current': num_chunks,
                'chunk_total': num_chunks,
            })
        return (rows, total_bytes_scanned, truncated)

    def _query_grouped_range_adaptive(self, start_time: datetime, end_time: datetime,
                                      progress_callback: Optional[Callable] = None) -> tuple:
        """Run the grouped aggregation for a range; bisect if it hits the group cap.

        If the returned
        group count hits the 10,000-row cap the range is halved (down to a 60s
        floor) so no groups are lost; only a <=60s window still at the cap is
        flagged truncated.

        Returns:
            Tuple of (grouped_rows, bytes_scanned, truncated)
        """
        MIN_CHUNK_SECONDS = 60

        if self.cancel_requested:
            return ([], 0, False)

        rows, bytes_scanned, hit_limit = self._execute_grouped_query(
            start_time, end_time, progress_callback
        )
        if self.cancel_requested:
            return ([], 0, False)

        if not hit_limit:
            return (rows, bytes_scanned, False)

        if (end_time - start_time).total_seconds() <= MIN_CHUNK_SECONDS:
            print("⚠️  Warning: a <=60s window still hit the 10K group limit; "
                  "per-flow breakdowns for this period are a sample. "
                  "Authoritative totals are unaffected.")
            return (rows, bytes_scanned, True)

        mid = start_time + (end_time - start_time) / 2
        left_rows, left_bytes, left_trunc = self._query_grouped_range_adaptive(
            start_time, mid, progress_callback
        )
        if self.cancel_requested:
            return ([], 0, False)
        right_rows, right_bytes, right_trunc = self._query_grouped_range_adaptive(
            mid + timedelta(seconds=1), end_time, progress_callback
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
            response = self.logs_client.start_query(
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
        while True:
            if self.cancel_requested:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except:
                    pass
                return ([], 0, False)

            result = self.logs_client.get_query_results(queryId=query_id)
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
            time.sleep(2)

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

    def query_alert_logs(self, progress_callback: Optional[Callable] = None) -> tuple:
        """Query CloudWatch Logs for alert data (hostnames from HTTP and TLS)
        
        Also tracks timestamps for accurate endpoint cost calculation.
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (alert_logs, earliest_alert_ts, latest_alert_ts, bytes_scanned) or (None, None, None, None) if cancelled
        """
        if self.cancel_requested:
            return (None, None, None, None)
        
        # Shared window helper: identical range to the flow / totals queries.
        start_time, end_time = self._get_query_window()
        
        # Query for alert events with hostname/SNI
        query = """
        fields @timestamp, event.flow_id, event.http.hostname, event.tls.sni
        | filter event.event_type = "alert"
        | filter (isPresent(event.http.hostname) or isPresent(event.tls.sni))
        """
        
        if progress_callback:
            progress_callback({
                'stage': 'Querying alert logs',
                'status': 'Starting CloudWatch query...'
            })
        
        # Start query (using alert log group, which may be different from flow log group)
        try:
            response = self.logs_client.start_query(
                logGroupName=self.alert_log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
        except Exception as e:
            error_str = str(e)
            if "ResourceNotFoundException" in error_str or "ResourceNotFound" in error_str:
                raise Exception(f"ALERT log group not found: '{self.alert_log_group}'. Please verify the name and region.")
            else:
                raise Exception(f"Failed to start alert log query on '{self.alert_log_group}': {error_str}")
        
        query_id = response['queryId']
        
        # Wait for query completion
        start_query_time = time.time()
        while True:
            if self.cancel_requested:
                try:
                    self.logs_client.stop_query(queryId=query_id)
                except:
                    pass
                return (None, None, None, None)
            
            result = self.logs_client.get_query_results(queryId=query_id)
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
                raise Exception(f"Alert log query timed out after {int(elapsed)}s "
                                f"waiting for CloudWatch Logs Insights (status '{status}').")
            
            # Progress update
            if progress_callback:
                progress_callback({
                    'stage': 'Querying alert logs',
                    'status': f'Query running... ({int(elapsed)}s elapsed)'
                })
            
            time.sleep(2)
        
        if status == 'Complete':
            records = result.get('results', [])
            # Capture bytes scanned for cost calculation
            statistics = result.get('statistics', {})
            bytes_scanned = statistics.get('bytesScanned', 0)
            
            if progress_callback:
                progress_callback({
                    'stage': 'Querying alert logs',
                    'status': f'Retrieved {len(records):,} alert records'
                })
            
            # Track timestamps from alert logs too
            earliest_alert_ts = None
            latest_alert_ts = None
            
            for alert in records:
                timestamp_str = self._get_field_value(alert, '@timestamp')
                if timestamp_str:
                    # Route through the shared parser so alert timestamps are
                    # normalized to NAIVE UTC, matching the flow-leg and metadata
                    # timestamps. Parsing inline with fromisoformat() on a 'Z' form
                    # yields a tz-aware datetime, which later raises "can't compare
                    # offset-naive and offset-aware datetimes" when combined with
                    # the naive flow timestamps in analyze().
                    ts = self._parse_cw_timestamp(timestamp_str)
                    if ts:
                        if earliest_alert_ts is None or ts < earliest_alert_ts:
                            earliest_alert_ts = ts
                        if latest_alert_ts is None or ts > latest_alert_ts:
                            latest_alert_ts = ts
            
            return (records, earliest_alert_ts, latest_alert_ts, bytes_scanned)
        else:
            raise Exception(f"Alert log query {status.lower()}: {result.get('statistics', {})}")
    
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
            if hostname and hostname != "(No hostname)" and '.amazonaws.com' in hostname:
                # Parse service from hostname format: service.region.amazonaws.com
                if '.s3.' in hostname or hostname.endswith('.s3.amazonaws.com'):
                    # S3 specific patterns
                    service_info = {'service': 'S3', 'is_aws': True, 'region': 'N/A'}
                    # Try to extract region from hostname
                    if '.s3.' in hostname:
                        parts = hostname.split('.s3.')
                        if len(parts) > 1:
                            region_part = parts[1].split('.amazonaws.com')[0]
                            if region_part and '-' in region_part and region_part != 'amazonaws':
                                service_info['region'] = region_part
                elif 'cloudfront.net' in hostname:
                    service_info = {'service': 'CLOUDFRONT', 'region': 'GLOBAL', 'is_aws': True}
                else:
                    # Generic AWS service hostname: service.region.amazonaws.com
                    parts = hostname.split('.amazonaws.com')[0].split('.')
                    if len(parts) >= 2:
                        # Extract service name (first part) and region (second-to-last part)
                        service_name = parts[0].upper().replace('-', '_')
                        # Get region from hostname (typically second-to-last part)
                        region_part = parts[-1] if len(parts) >= 2 else 'N/A'
                        if region_part and '-' in region_part:
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
                    'IAM', 'ECR', 'KMS', 'KINESISANALYTICS', 'ROUTE53'
                }

                # Each branch sets:
                #   endpoint_type       - label
                #   endpoint_cost       - WINDOW-scoped cost of the equivalent endpoint
                #   monthly_savings     - PROJECTED monthly savings (monthly vs monthly)
                #   recommendation      - DEPLOY / CONSIDER / SKIP...
                # NOTE: ALL interface endpoints use firewall region pricing.
                if service in ['S3', 'DYNAMODB']:
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
    
    def analyze(self, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Main analysis method
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dict containing analysis results:
            - top_talkers: List of enriched flows
            - hostname_aggregation: Dict of internet traffic by hostname
            - service_totals: Dict of AWS service traffic by service/region
            - vpc_to_vpc_connections: List of VPC-to-VPC connections
            - vpc_endpoint_recommendations: List of VPC endpoint recommendations
            - metadata: Analysis metadata (timestamp, region, days, etc.)
        """
        try:
            # Step 1: Query AUTHORITATIVE traffic totals via server-side aggregation.
            # This runs FIRST because it is the source of truth for total/per-AZ
            # bytes (not subject to the 10K-row limit) AND it returns the total
            # netflow record count, which we use to size the raw per-flow query's
            # chunking correctly in a single pass.
            if progress_callback:
                progress_callback({
                    'stage': 'Querying traffic totals',
                    'status': 'Starting...'
                })
            
            totals_result = self.query_flow_totals(progress_callback)
            
            if self.cancel_requested or totals_result == (None, None, None, None):
                return None
            
            authoritative_total_bytes, authoritative_az_bytes, totals_bytes_scanned, total_records = totals_result
            
            # Step 2: Query per-flow byte totals via server-side aggregation (for
            # top-talkers, drill-down, and the per-hostname/service/VPC breakdowns).
            # Unlike the old raw-row retrieval, this sums bytes server-side grouped
            # by flow leg, so the breakdowns are byte-accurate at any volume. Seeded
            # with the record count to size chunking (groups are fewer than records,
            # so this is a conservative bound).
            if progress_callback:
                progress_callback({
                    'stage': 'Querying flow breakdown',
                    'status': 'Starting...'
                })
            
            flow_result = self.query_flow_grouped(expected_records=total_records,
                                                  progress_callback=progress_callback)
            
            if self.cancel_requested or flow_result == (None, None, None):
                return None
            
            # grouped_rows are per-flow-leg aggregates. flow_truncated indicates the
            # rare case where even a <=60s window exceeded the 10K GROUP cap (the
            # breakdown becomes a sample); authoritative totals remain exact.
            grouped_rows, flow_bytes_scanned, flow_truncated = flow_result
            
            # Step 3: Query alert logs
            if progress_callback:
                progress_callback({
                    'stage': 'Querying alert logs',
                    'status': 'Starting...'
                })
            
            alert_result = self.query_alert_logs(progress_callback)
            
            if self.cancel_requested or alert_result == (None, None, None, None):
                return None
            
            # Unpack alert results (alert_logs, earliest_alert_ts, latest_alert_ts, bytes_scanned)
            alert_logs, earliest_alert_ts, latest_alert_ts, alert_bytes_scanned = alert_result
            
            # Step 4: Correlate logs
            if progress_callback:
                progress_callback({
                    'stage': 'Correlating logs',
                    'status': 'Starting correlation...'
                })
            
            result_tuple = self.correlate_logs(grouped_rows, alert_logs, progress_callback)
            
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
            if progress_callback:
                progress_callback({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing internet traffic...'
                })
            
            hostname_aggregation = self.aggregate_by_hostname(enriched_flows)
            
            # Step 6: Aggregate by service (Tab 2)
            if progress_callback:
                progress_callback({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing AWS service traffic...'
                })
            
            service_totals = self.aggregate_by_service(enriched_flows)
            
            # Step 7: Aggregate VPC-to-VPC (Tab 3)
            if progress_callback:
                progress_callback({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing VPC-to-VPC traffic...'
                })
            
            vpc_to_vpc_connections = self.aggregate_vpc_to_vpc(enriched_flows)
            
            # Window length in hours - the single scope basis for both the fixed
            # (endpoint) cost and the window->month projection used by the
            # recommendations. Derived from the shared query window so it matches
            # exactly what was queried.
            window_start, window_end = self._get_query_window()
            window_hours = (window_end - window_start).total_seconds() / 3600
            if window_hours <= 0:
                window_hours = self.days * 24  # defensive fallback
            
            # Step 8: Calculate VPC endpoint recommendations
            if progress_callback:
                progress_callback({
                    'stage': 'Calculating recommendations',
                    'status': 'Analyzing VPC endpoint opportunities...'
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
            
            # Calculate CloudWatch Logs Insights query cost
            # Pricing: $0.005 per GB scanned (consistent across all regions).
            # Includes the grouped per-flow aggregation query, the authoritative
            # totals aggregation query, and the alert query.
            total_bytes_scanned = flow_bytes_scanned + totals_bytes_scanned + alert_bytes_scanned
            cloudwatch_gb_scanned = total_bytes_scanned / (1024**3)
            cloudwatch_query_cost = cloudwatch_gb_scanned * 0.005
            
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
                'top_talkers': enriched_flows,
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
            try:
                with open(stats_file_path, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            except:
                pass  # If file is corrupt, start fresh
        
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
        
        # Convert timestamps in top_talkers to ISO strings
        top_talkers_serializable = []
        for flow in results['top_talkers']:
            flow_copy = flow.copy()
            if flow_copy.get('timestamp'):
                flow_copy['timestamp'] = flow_copy['timestamp'].isoformat()
            top_talkers_serializable.append(flow_copy)
        
        traffic_data = {
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
            
            # Save top_talkers for drill-down functionality (with timestamps converted)
            # Note: This increases file size but enables full UI features
            'top_talkers': top_talkers_serializable
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
            
            # Parse timestamps back to datetime objects in top_talkers
            top_talkers_with_ts = []
            for flow in traffic_data.get('top_talkers', []):
                flow_copy = flow.copy()
                if flow_copy.get('timestamp'):
                    try:
                        flow_copy['timestamp'] = datetime.fromisoformat(flow_copy['timestamp'])
                    except:
                        flow_copy['timestamp'] = None
                top_talkers_with_ts.append(flow_copy)
            
            # Reconstruct results dictionary compatible with UI
            results = {
                'top_talkers': top_talkers_with_ts,
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
                    'cloudwatch_gb_scanned': 0,  # Can't recalculate from saved data
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
