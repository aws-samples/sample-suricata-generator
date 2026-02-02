"""
Traffic Analyzer - CloudWatch Log Analysis for Network Firewall

Analyzes AWS Network Firewall logs from CloudWatch to provide:
1. Traffic visibility (Top Talkers with hostname/SNI)
2. VPC endpoint cost optimization recommendations
3. Internet vs AWS service vs VPC-to-VPC traffic breakdown

Author: Suricata Generator Team
Created: 2026-01-25
"""

import boto3
import time
import json
import os
from datetime import datetime, timedelta, date
from collections import defaultdict
from typing import Dict, List, Optional, Callable, Any

from aws_service_detector import AWSServiceDetector


class TrafficAnalyzer:
    """Main class for traffic analysis and VPC endpoint recommendations"""
    
    # AWS Network Firewall data processing costs by region (per GB)
    # Source: AWS Network Firewall Pricing (2026)
    FIREWALL_PRICING = {
        'us-east-1': 0.065,
        'us-east-2': 0.065,
        'us-west-1': 0.078,
        'us-west-2': 0.065,
        'ca-central-1': 0.072,
        'eu-west-1': 0.075,
        'eu-west-2': 0.075,
        'eu-west-3': 0.075,
        'eu-central-1': 0.075,
        'eu-north-1': 0.075,
        'ap-south-1': 0.090,
        'ap-northeast-1': 0.090,
        'ap-northeast-2': 0.090,
        'ap-northeast-3': 0.090,
        'ap-southeast-1': 0.090,
        'ap-southeast-2': 0.090,
        'ap-southeast-3': 0.090,
        'sa-east-1': 0.104,
        'me-south-1': 0.078,
        'af-south-1': 0.091,
    }
    
    # VPC Interface Endpoint costs by region (per month)
    # Source: AWS PrivateLink Pricing (2026)
    # Calculation: hourly_rate × 730 hours/month
    INTERFACE_ENDPOINT_PRICING = {
        'us-east-1': 7.30,      # $0.01/hour
        'us-east-2': 7.30,      # $0.01/hour
        'us-west-1': 8.03,      # $0.011/hour
        'us-west-2': 7.30,      # $0.01/hour
        'ca-central-1': 7.30,   # $0.01/hour
        'eu-west-1': 8.03,      # $0.011/hour
        'eu-west-2': 8.03,      # $0.011/hour
        'eu-west-3': 8.03,      # $0.011/hour
        'eu-central-1': 8.03,   # $0.011/hour
        'eu-north-1': 8.03,     # $0.011/hour
        'ap-south-1': 10.22,    # $0.014/hour
        'ap-northeast-1': 10.22, # $0.014/hour
        'ap-northeast-2': 10.22, # $0.014/hour
        'ap-northeast-3': 10.22, # $0.014/hour
        'ap-southeast-1': 10.22, # $0.014/hour
        'ap-southeast-2': 10.22, # $0.014/hour
        'ap-southeast-3': 10.22, # $0.014/hour
        'sa-east-1': 11.68,     # $0.016/hour
        'me-south-1': 8.76,     # $0.012/hour
        'af-south-1': 10.95,    # $0.015/hour
    }
    
    # Interface endpoint data processing (cross-region) - same across all regions
    INTERFACE_ENDPOINT_DATA_COST_PER_GB = 0.01
    
    # AWS Network Firewall endpoint (hourly) costs by region
    # Source: AWS Network Firewall Pricing (2026)
    ENDPOINT_HOURLY_PRICING = {
        'us-east-1': 0.395,
        'us-east-2': 0.395,
        'us-west-1': 0.473,
        'us-west-2': 0.395,
        'ca-central-1': 0.433,
        'eu-west-1': 0.443,
        'eu-west-2': 0.443,
        'eu-west-3': 0.443,
        'eu-central-1': 0.443,
        'eu-north-1': 0.443,
        'ap-south-1': 0.540,
        'ap-northeast-1': 0.540,
        'ap-northeast-2': 0.540,
        'ap-northeast-3': 0.540,
        'ap-southeast-1': 0.540,
        'ap-southeast-2': 0.540,
        'ap-southeast-3': 0.540,
        'sa-east-1': 0.623,
        'me-south-1': 0.469,
        'af-south-1': 0.547,
    }
    
    def __init__(self, log_group: str, region: str, days: Optional[int] = None, 
                 alert_log_group: Optional[str] = None,
                 start_date: Optional[date] = None,
                 end_date: Optional[date] = None):
        """Initialize traffic analyzer
        
        Args:
            log_group: CloudWatch log group name for flow logs
            region: AWS region
            days: Number of days to analyze (7-90) - DEPRECATED if start_date/end_date provided
            alert_log_group: Optional separate log group for alert logs. If not provided,
                           will attempt to auto-detect by replacing "Flow" with "Alert"
            start_date: Optional custom start date (overrides days parameter)
            end_date: Optional custom end date (overrides days parameter)
        """
        self.log_group = log_group
        self.region = region
        self.cancel_requested = False
        
        # Determine time range
        if start_date and end_date:
            # Custom date range mode
            self.start_date = start_date
            self.end_date = end_date
            self.days = (end_date - start_date).days
            self.use_custom_dates = True
        else:
            # Legacy days mode (backward compatible)
            self.days = days or 30
            self.end_date = datetime.now().date()
            self.start_date = self.end_date - timedelta(days=self.days)
            self.use_custom_dates = False
        
        # Get region-specific pricing with fallback to us-east-1
        self.firewall_cost_per_gb = self.FIREWALL_PRICING.get(region, 0.065)
        self.interface_endpoint_monthly_cost = self.INTERFACE_ENDPOINT_PRICING.get(region, 7.30)
        
        # Calculate break-even thresholds for this region
        self.same_region_break_even = int(
            self.interface_endpoint_monthly_cost / self.firewall_cost_per_gb
        )
        self.cross_region_break_even = int(
            self.interface_endpoint_monthly_cost / 
            (self.firewall_cost_per_gb - self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
        )
        
        # Warn if using fallback pricing (unknown region)
        if region not in self.FIREWALL_PRICING:
            print(f"⚠️  Warning: Region '{region}' not in pricing table. "
                  f"Using US-East-1 pricing (${self.firewall_cost_per_gb}/GB). "
                  f"Actual costs may vary.")
        
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
        self.logs_client = boto3.client('logs', region_name=region)
        
        # Initialize AWS service detector (downloads IP ranges and builds trees)
        self.aws_service_detector = AWSServiceDetector()
    
    def cancel_analysis(self):
        """User requested cancellation"""
        self.cancel_requested = True
    
    def query_flow_logs(self, progress_callback: Optional[Callable] = None) -> tuple:
        """Query CloudWatch Logs for flow data (netflow events with bytes)
        
        Automatically handles pagination when queries exceed 10K record limit by
        breaking the time range into smaller chunks.
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (flow_logs, bytes_scanned) or (None, None) if cancelled
        """
        if self.cancel_requested:
            return (None, None)
        
        # Use custom dates if provided, otherwise calculate from days
        if self.use_custom_dates:
            # Convert date to datetime with time components
            start_time = datetime.combine(self.start_date, datetime.min.time())
            end_time = datetime.combine(self.end_date, datetime.max.time())
        else:
            # Legacy behavior
            end_time = datetime.now()
            start_time = end_time - timedelta(days=self.days)
        
        # Implement automatic pagination for large queries
        # Strategy: Start with full range, if we hit 10K limit OR if query fails due to
        # time range issues (log group created after start date), chunk into smaller periods
        all_records = []
        total_bytes_scanned = 0
        needs_chunking = False
        
        # Try initial query
        records = []
        bytes_scanned = 0
        
        try:
            records, bytes_scanned, hit_limit = self._execute_flow_query(start_time, end_time, progress_callback)
            
            if self.cancel_requested:
                return (None, None)
            
            if not hit_limit:
                # Query succeeded without hitting limit - we're done
                return (records, bytes_scanned)
            
            # Hit the 10K limit - need to chunk
            needs_chunking = True
        except Exception as e:
            error_msg = str(e)
            # Check if error is due to time range issues (log group created after query start)
            if "MalformedQueryException" in error_msg and ("creation time" in error_msg or "before" in error_msg.lower()):
                # Log group is newer than query start time - need to chunk to find valid range
                needs_chunking = True
                if progress_callback:
                    progress_callback({
                        'stage': 'Querying flow logs',
                        'status': 'Log group created after query start - automatically chunking to find data...'
                    })
            else:
                # Different error - re-raise it
                raise
        
        # Need to chunk the time range (either hit limit or log group too new)
        if progress_callback:
            progress_callback({
                'stage': 'Querying flow logs',
                'status': 'Query exceeded 10K limit - automatically chunking into smaller periods...'
            })
        
        # Calculate chunk size (start with daily chunks)
        total_duration = end_time - start_time
        num_chunks = max(2, int(total_duration.total_seconds() / (24 * 3600)))  # At least daily chunks
        chunk_duration = total_duration / num_chunks
        
        all_records = []
        total_bytes_scanned = 0
        
        for chunk_num in range(num_chunks):
            if self.cancel_requested:
                return (None, None)
            
            chunk_start = start_time + (chunk_duration * chunk_num)
            chunk_end = start_time + (chunk_duration * (chunk_num + 1))
            
            if progress_callback:
                progress_callback({
                    'stage': 'Querying flow logs (chunked)',
                    'status': f'Chunk {chunk_num + 1}/{num_chunks}: {chunk_start.date()} to {chunk_end.date()}...'
                })
            
            # Execute query for this chunk
            chunk_records, chunk_bytes, chunk_hit_limit = self._execute_flow_query(
                chunk_start, chunk_end, progress_callback
            )
            
            if self.cancel_requested:
                return (None, None)
            
            # If this chunk STILL hit the 10K limit, recursively subdivide it
            if chunk_hit_limit:
                if progress_callback:
                    progress_callback({
                        'stage': 'Querying flow logs (recursive chunking)',
                        'status': f'Chunk {chunk_num + 1} exceeded 10K - subdividing into hourly periods...'
                    })
                
                # Recursively query this chunk with hourly subdivision
                chunk_records, chunk_bytes = self._query_with_hourly_chunks(
                    chunk_start, chunk_end, progress_callback
                )
                
                if self.cancel_requested:
                    return (None, None)
            
            all_records.extend(chunk_records)
            total_bytes_scanned += chunk_bytes
        
        if progress_callback:
            progress_callback({
                'stage': 'Querying flow logs',
                'status': f'Retrieved {len(all_records):,} total flow records from {num_chunks} chunks'
            })
        
        return (all_records, total_bytes_scanned)
    
    def _query_with_hourly_chunks(self, start_time: datetime, end_time: datetime,
                                  progress_callback: Optional[Callable] = None) -> tuple:
        """Query with hourly chunks for high-traffic periods
        
        Used when a daily chunk exceeds 10K records. Breaks the day into 24 hourly chunks.
        
        Args:
            start_time: Chunk start time
            end_time: Chunk end time  
            progress_callback: Optional progress callback
            
        Returns:
            Tuple of (all_records, total_bytes_scanned)
        """
        # Break into hourly chunks
        duration = end_time - start_time
        num_hours = max(1, int(duration.total_seconds() / 3600))
        hour_duration = duration / num_hours
        
        all_records = []
        total_bytes = 0
        
        for hour_num in range(num_hours):
            if self.cancel_requested:
                return ([], 0)
            
            hour_start = start_time + (hour_duration * hour_num)
            hour_end = start_time + (hour_duration * (hour_num + 1))
            
            if progress_callback:
                progress_callback({
                    'stage': 'Querying flow logs (hourly)',
                    'status': f'Hour {hour_num + 1}/{num_hours}: {hour_start.strftime("%H:%M")} to {hour_end.strftime("%H:%M")}...'
                })
            
            hour_records, hour_bytes, hour_hit_limit = self._execute_flow_query(
                hour_start, hour_end, progress_callback
            )
            
            if self.cancel_requested:
                return ([], 0)
            
            all_records.extend(hour_records)
            total_bytes += hour_bytes
            
            # If even an hour hits 10K, log warning but continue
            # (This would be extremely high traffic - ~240K records/day)
            if hour_hit_limit:
                print(f"⚠️  Warning: Single hour still hit 10K limit. "
                      f"This is extremely high traffic volume. Results may be slightly incomplete.")
        
        return (all_records, total_bytes)
    
    def _execute_flow_query(self, start_time: datetime, end_time: datetime,
                           progress_callback: Optional[Callable] = None) -> tuple:
        """Execute a single flow log query
        
        Args:
            start_time: Query start time
            end_time: Query end time
            progress_callback: Optional progress callback
            
        Returns:
            Tuple of (records, bytes_scanned, hit_10k_limit)
        """
        query = """
        fields @timestamp, availability_zone, event.src_ip, event.dest_ip, event.src_port, event.dest_port, 
               event.proto, event.flow_id, event.netflow.bytes, event.app_proto
        | filter event.event_type = "netflow"
        """
        
        # Start query
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
                # Query time range is before log group was created - return empty results for this chunk
                # This is normal during chunked queries when firewall is new
                return ([], 0, False)
            else:
                raise Exception(f"Failed to start flow log query on '{self.log_group}': {error_str}")
        
        query_id = response['queryId']
        
        # Wait for query completion
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
            
            if status in ['Complete', 'Failed', 'Cancelled']:
                break
            
            # Progress update
            elapsed = int(time.time() - start_query_time)
            if progress_callback:
                progress_callback({
                    'stage': 'Querying flow logs',
                    'status': f'Query running... ({elapsed}s elapsed)'
                })
            
            time.sleep(2)
        
        if status == 'Complete':
            records = result.get('results', [])
            statistics = result.get('statistics', {})
            bytes_scanned = statistics.get('bytesScanned', 0)
            records_matched = statistics.get('recordsMatched', 0)
            
            # Check if we hit the 10K limit
            hit_limit = (len(records) >= 10000 and records_matched > 10000)
            
            return (records, bytes_scanned, hit_limit)
        else:
            raise Exception(f"Flow log query {status.lower()}: {result.get('statistics', {})}")
    
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
        
        # Use custom dates if provided, otherwise calculate from days
        if self.use_custom_dates:
            # Convert date to datetime with time components
            start_time = datetime.combine(self.start_date, datetime.min.time())
            end_time = datetime.combine(self.end_date, datetime.max.time())
        else:
            # Legacy behavior
            end_time = datetime.now()
            start_time = end_time - timedelta(days=self.days)
        
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
            
            if status in ['Complete', 'Failed', 'Cancelled']:
                break
            
            # Progress update
            elapsed = int(time.time() - start_query_time)
            if progress_callback:
                progress_callback({
                    'stage': 'Querying alert logs',
                    'status': f'Query running... ({elapsed}s elapsed)'
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
                    try:
                        ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        if earliest_alert_ts is None or ts < earliest_alert_ts:
                            earliest_alert_ts = ts
                        if latest_alert_ts is None or ts > latest_alert_ts:
                            latest_alert_ts = ts
                    except:
                        pass
            
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
    
    def correlate_logs(self, flow_logs: List[Dict], alert_logs: List[Dict],
                      progress_callback: Optional[Callable] = None) -> tuple:
        """Correlate flow and alert logs by flow_id
        
        Critical: Groups flows by flow_id and sums bytes bidirectionally.
        The netflow.bytes field is UNIDIRECTIONAL - must sum both directions.
        
        Args:
            flow_logs: List of flow log entries
            alert_logs: List of alert log entries
            progress_callback: Optional callback for progress updates
            
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
                'status': f'Processing {len(flow_logs):,} flow records...'
            })
        
        # CRITICAL: Group flows by flow_id and sum bytes bidirectionally
        # netflow.bytes is UNIDIRECTIONAL - need to sum both directions
        flow_totals = {}
        
        # Track unique AZs and timestamps for endpoint cost calculation
        # Also track bytes per AZ for traffic distribution analysis
        unique_azs = set()
        az_traffic = {}  # Map AZ -> total bytes processed
        earliest_timestamp = None
        latest_timestamp = None
        
        for i, flow in enumerate(flow_logs):
            if self.cancel_requested:
                return (None, None, None, None, None)
            
            flow_id = self._get_field_value(flow, 'event.flow_id')
            src_ip = self._get_field_value(flow, 'event.src_ip')
            dest_ip = self._get_field_value(flow, 'event.dest_ip')
            src_port = self._get_field_value(flow, 'event.src_port')
            dest_port = self._get_field_value(flow, 'event.dest_port')
            proto = self._get_field_value(flow, 'event.proto')
            bytes_str = self._get_field_value(flow, 'event.netflow.bytes')
            app_proto = self._get_field_value(flow, 'event.app_proto')
            az = self._get_field_value(flow, 'availability_zone')
            timestamp_str = self._get_field_value(flow, '@timestamp')
            
            if not flow_id:
                continue
            
            bytes_val = int(bytes_str) if bytes_str else 0
            
            # Track AZ for endpoint cost calculation and traffic distribution
            if az:
                unique_azs.add(az)
                # Aggregate bytes per AZ
                if az not in az_traffic:
                    az_traffic[az] = 0
                az_traffic[az] += bytes_val
            
            # Track timestamp range for endpoint cost calculation
            if timestamp_str:
                try:
                    # Parse ISO timestamp
                    ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if earliest_timestamp is None or ts < earliest_timestamp:
                        earliest_timestamp = ts
                    if latest_timestamp is None or ts > latest_timestamp:
                        latest_timestamp = ts
                except:
                    pass
            
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
            
            # Sum bytes from both directions
            flow_totals[flow_id]['bytes'] += bytes_val
            
            # Capture timestamp from first packet (or most recent if already set)
            if timestamp_str and flow_totals[flow_id]['timestamp'] is None:
                try:
                    flow_totals[flow_id]['timestamp'] = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except:
                    pass
            
            # Determine initiating source and destination
            # CRITICAL: Only capture port/protocol from OUTBOUND traffic (private → public)
            # Return traffic (public → private) has ephemeral ports which we must ignore
            src_is_private = self.aws_service_detector.is_rfc1918_private(src_ip) if src_ip else False
            dest_is_private = self.aws_service_detector.is_rfc1918_private(dest_ip) if dest_ip else False
            
            # If we don't have IPs yet, capture them from first packet seen
            if flow_totals[flow_id]['src_ip'] is None:
                if src_is_private and not dest_is_private:
                    # OUTBOUND: private source, public dest (captures real dest port: 443, 80, etc.)
                    flow_totals[flow_id]['src_ip'] = src_ip
                    flow_totals[flow_id]['dest_ip'] = dest_ip
                    flow_totals[flow_id]['dest_port'] = dest_port
                    flow_totals[flow_id]['proto'] = proto
                    flow_totals[flow_id]['app_proto'] = app_proto
                elif not src_is_private and dest_is_private:
                    # RETURN TRAFFIC: public source, private dest
                    # CRITICAL: In return traffic, the source port IS the real destination port
                    # Example: public:443 → private:54321, we want port 443
                    flow_totals[flow_id]['src_ip'] = dest_ip  # VPC IP
                    flow_totals[flow_id]['dest_ip'] = src_ip  # Internet IP
                    flow_totals[flow_id]['dest_port'] = src_port  # src_port from return traffic = service port
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
                # We have IPs but missing port - try to get from outbound packet
                if src_is_private and not dest_is_private:
                    # Found outbound packet - capture the real destination port
                    flow_totals[flow_id]['dest_port'] = dest_port
                    if flow_totals[flow_id]['app_proto'] is None:
                        flow_totals[flow_id]['app_proto'] = app_proto
            
            # Progress update every 10,000 flows
            if i > 0 and i % 10000 == 0 and progress_callback:
                percent = (i / len(flow_logs)) * 100
                progress_callback({
                    'stage': 'Correlating logs',
                    'processed': i,
                    'total': len(flow_logs),
                    'percent': percent,
                    'status': f'Grouping flows by flow_id... ({i:,}/{len(flow_logs):,})'
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
                
                # If no hostname, use dest_ip:port as the key for aggregation
                if hostname == "(No hostname)":
                    # Aggregate by dest IP and port combination
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
    
    def calculate_vpc_endpoint_recommendations(self, service_totals: Dict) -> List[Dict]:
        """Calculate VPC endpoint recommendations with cost-benefit analysis
        
        CRITICAL: Interface endpoints are deployed in the FIREWALL's region (where the client is),
        not the destination service region. Therefore, endpoint cost is ALWAYS based on
        firewall region pricing, regardless of which region the service is in.
        
        Args:
            service_totals: Dict mapping service -> region -> bytes
            
        Returns:
            List of recommendation dictionaries sorted by savings
        """
        recommendations = []
        
        for service, regions in service_totals.items():
            for region, total_bytes in regions.items():
                traffic_gb = total_bytes / (1024**3)  # Convert to GB
                current_cost = traffic_gb * self.firewall_cost_per_gb
                
                is_same_region = (region == self.region)
                
                # Services that support cross-region interface endpoints (as of 2026)
                # Source: https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-cross-region-privatelink-support.html
                CROSS_REGION_SUPPORTED_SERVICES = {
                    'S3', 'LAMBDA', 'ECS', 'KINESIS_FIREHOSE', 
                    'IAM', 'ECR', 'KMS', 'KINESISANALYTICS', 'ROUTE53'
                }
                
                # Determine endpoint type and cost
                # NOTE: ALL interface endpoints use firewall region pricing (same cost for all)
                if service in ['S3', 'DYNAMODB']:
                    if is_same_region:
                        # Gateway endpoint (FREE)
                        endpoint_type = 'Gateway'
                        endpoint_cost = 0
                        savings = current_cost
                        recommendation = 'DEPLOY'
                    else:
                        # Cross-region: Only recommend interface endpoint if service supports it
                        if service in CROSS_REGION_SUPPORTED_SERVICES:
                            endpoint_type = 'Interface (cross-region)'
                            endpoint_cost = self.interface_endpoint_monthly_cost + \
                                          (traffic_gb * self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
                            savings = current_cost - endpoint_cost
                            
                            # Smart recommendation logic for S3 cross-region
                            if traffic_gb > self.cross_region_break_even:
                                # High traffic: interface endpoint is cost-effective
                                recommendation = 'DEPLOY'
                            elif traffic_gb > 20:
                                # Moderate traffic: CRR may be viable alternative
                                # S3 CRR costs ~$0.02/GB, so suggest it for meaningful volumes
                                recommendation = 'SKIP - Consider CRR instead'
                            else:
                                # Low traffic: neither endpoint nor CRR makes sense
                                recommendation = 'SKIP'
                        else:
                            # Service doesn't support cross-region endpoints
                            endpoint_type = 'N/A'
                            endpoint_cost = current_cost
                            savings = 0
                            recommendation = 'SKIP - Cross-region not supported'
                else:
                    # Interface endpoint (deployed in firewall region)
                    endpoint_type = 'Interface'
                    
                    if is_same_region:
                        endpoint_cost = self.interface_endpoint_monthly_cost
                        break_even_gb = self.same_region_break_even
                        
                        savings = current_cost - endpoint_cost
                        
                        if traffic_gb > break_even_gb:
                            recommendation = 'DEPLOY'
                        elif traffic_gb > (break_even_gb * 0.75):
                            recommendation = 'CONSIDER'
                        else:
                            recommendation = 'SKIP'
                    else:
                        # Cross-region for non-S3/DynamoDB services
                        if service in CROSS_REGION_SUPPORTED_SERVICES:
                            endpoint_cost = self.interface_endpoint_monthly_cost + \
                                          (traffic_gb * self.INTERFACE_ENDPOINT_DATA_COST_PER_GB)
                            break_even_gb = self.cross_region_break_even
                            
                            savings = current_cost - endpoint_cost
                            
                            if traffic_gb > break_even_gb:
                                recommendation = 'DEPLOY'
                            elif traffic_gb > (break_even_gb * 0.75):
                                recommendation = 'CONSIDER'
                            else:
                                recommendation = 'SKIP'
                        else:
                            # Service doesn't support cross-region endpoints
                            endpoint_cost = current_cost
                            savings = 0
                            recommendation = 'SKIP - Cross-region not supported'
                
                recommendations.append({
                    'service': service,
                    'region': region,
                    'is_same_region': is_same_region,
                    'endpoint_type': endpoint_type,
                    'traffic_gb': round(traffic_gb, 2),
                    'current_cost': round(current_cost, 2),
                    'endpoint_cost': round(endpoint_cost, 2),
                    'monthly_savings': round(savings, 2),
                    'annual_savings': round(savings * 12, 0),
                    'recommendation': recommendation
                })
        
        # Sort by savings (descending)
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
            # Step 1: Query flow logs
            if progress_callback:
                progress_callback({
                    'stage': 'Querying flow logs',
                    'status': 'Starting...'
                })
            
            flow_result = self.query_flow_logs(progress_callback)
            
            if self.cancel_requested or flow_result == (None, None):
                return None
            
            flow_logs, flow_bytes_scanned = flow_result
            
            # Step 2: Query alert logs
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
            
            # Step 3: Correlate logs
            if progress_callback:
                progress_callback({
                    'stage': 'Correlating logs',
                    'status': 'Starting correlation...'
                })
            
            result_tuple = self.correlate_logs(flow_logs, alert_logs, progress_callback)
            
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
            
            # Step 4: Aggregate by hostname (Tab 1)
            if progress_callback:
                progress_callback({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing internet traffic...'
                })
            
            hostname_aggregation = self.aggregate_by_hostname(enriched_flows)
            
            # Step 5: Aggregate by service (Tab 2)
            if progress_callback:
                progress_callback({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing AWS service traffic...'
                })
            
            service_totals = self.aggregate_by_service(enriched_flows)
            
            # Step 6: Aggregate VPC-to-VPC (Tab 3)
            if progress_callback:
                progress_callback({
                    'stage': 'Aggregating traffic',
                    'status': 'Analyzing VPC-to-VPC traffic...'
                })
            
            vpc_to_vpc_connections = self.aggregate_vpc_to_vpc(enriched_flows)
            
            # Step 7: Calculate VPC endpoint recommendations
            if progress_callback:
                progress_callback({
                    'stage': 'Calculating recommendations',
                    'status': 'Analyzing VPC endpoint opportunities...'
                })
            
            vpc_endpoint_recommendations = self.calculate_vpc_endpoint_recommendations(service_totals)
            
            # Calculate total traffic and costs
            total_bytes = sum(flow['bytes'] for flow in enriched_flows)
            total_gb = total_bytes / (1024**3)
            total_cost = total_gb * self.firewall_cost_per_gb
            
            # Calculate hostname coverage statistics
            flows_with_hostname = sum(1 for f in enriched_flows if f['hostname'] != "(No hostname)")
            hostname_coverage_pct = (flows_with_hostname / len(enriched_flows) * 100) if enriched_flows else 0
            
            bytes_with_hostname = sum(f['bytes'] for f in enriched_flows if f['hostname'] != "(No hostname)")
            bytes_coverage_pct = (bytes_with_hostname / total_bytes * 100) if total_bytes > 0 else 0
            
            # Calculate CloudWatch Logs Insights query cost
            # Pricing: $0.005 per GB scanned (consistent across all regions)
            total_bytes_scanned = flow_bytes_scanned + alert_bytes_scanned
            cloudwatch_gb_scanned = total_bytes_scanned / (1024**3)
            cloudwatch_query_cost = cloudwatch_gb_scanned * 0.005
            
            # Calculate firewall endpoint costs
            endpoint_hourly_rate = self.ENDPOINT_HOURLY_PRICING.get(self.region, 0.395)
            num_endpoints = len(unique_azs)
            
            # Calculate actual runtime hours from timestamps
            if earliest_timestamp and latest_timestamp:
                runtime_hours = (latest_timestamp - earliest_timestamp).total_seconds() / 3600
            else:
                # Fallback: use analysis period if timestamps unavailable
                runtime_hours = self.days * 24
            
            # Calculate per-endpoint costs with traffic volume
            endpoint_costs = []
            sorted_azs = sorted(list(unique_azs))
            for az in sorted_azs:
                cost = endpoint_hourly_rate * runtime_hours
                az_bytes = az_traffic.get(az, 0)
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
                    'flow_logs_retrieved': len(flow_logs),
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
                    'earliest_timestamp': earliest_timestamp,
                    'latest_timestamp': latest_timestamp,
                    'start_date': self.start_date.strftime('%Y-%m-%d') if self.use_custom_dates else None,
                    'end_date': self.end_date.strftime('%Y-%m-%d') if self.use_custom_dates else None,
                    'use_custom_dates': self.use_custom_dates,
                    'cloudwatch_gb_scanned': round(cloudwatch_gb_scanned, 3),
                    'cloudwatch_query_cost': round(cloudwatch_query_cost, 2)
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
                'earliest_timestamp': earliest_ts_str,
                'latest_timestamp': latest_ts_str,
                'endpoint_costs': metadata['endpoint_costs']
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
                    'cloudwatch_gb_scanned': 0  # Can't recalculate from saved data
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
