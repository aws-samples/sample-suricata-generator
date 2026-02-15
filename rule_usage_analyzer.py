"""
Rule Usage Analyzer - AWS CloudWatch Logs Integration

This module provides functionality to analyze Suricata rule usage from AWS CloudWatch Logs.
It queries CloudWatch Logs Insights to determine which rules are triggering and provides
comprehensive analytics including:
- Unused rule detection with deployment-aware confidence levels
- Low-frequency rule identification (potential shadow rules)
- Overly-broad rule detection (security risks)
- Rule effectiveness analysis (Pareto principle)
- Efficiency tier classification

Dependencies:
- boto3 (optional) - AWS SDK for Python. Feature gracefully degrades if not installed.
"""

import datetime
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
import time

# Optional boto3 import with graceful degradation
HAS_BOTO3 = False
try:
    import boto3
    from botocore.exceptions import (
        ClientError, NoCredentialsError, 
        EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError
    )
    HAS_BOTO3 = True
except ImportError:
    # boto3 not available - feature will gracefully degrade
    boto3 = None
    ClientError = None
    NoCredentialsError = None


class RuleUsageAnalyzer:
    """Analyzes Suricata rule usage from AWS CloudWatch Logs"""
    
    # CloudWatch Logs Insights query to aggregate rule hits
    # AWS Network Firewall stores signature_id in event.alert.signature_id
    CLOUDWATCH_QUERY = """fields event.alert.signature_id as sid
| stats count() as hits, 
        max(@timestamp) as last_hit
        by sid
| filter hits > 0
| sort hits desc
| limit 10000"""
    
    # Category analysis query - retrieves per-alert category and hostname data
    # Only returns alerts that have aws_category data (from aws_domain_category/aws_url_category rules)
    CATEGORY_QUERY = """fields event.alert.signature_id as sid,
       event.aws_category as categories,
       event.http.hostname as http_host,
       event.tls.sni as tls_sni
| filter event.event_type = "alert"
| filter isPresent(event.aws_category)
| limit 10000"""
    
    def __init__(self, debug_force_pagination=False):
        """Initialize the Rule Usage Analyzer
        
        Args:
            debug_force_pagination: If True, always triggers pagination logic
                                   regardless of result count (for testing)
        """
        self.last_analysis_results = None
        self.last_analysis_timestamp = None
        self.debug_force_pagination = debug_force_pagination
    
    @staticmethod
    def is_unlogged_rule(rule) -> bool:
        """Determine if a rule doesn't write to CloudWatch Logs
        
        Rules that don't log:
        1. Pass rules WITHOUT the 'alert' keyword
        2. Drop/reject rules WITH the 'noalert' keyword
        
        Args:
            rule: SuricataRule object
            
        Returns:
            bool: True if rule doesn't log to CloudWatch, False otherwise
        """
        # Skip comments and blanks
        if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
            return False
        
        action = rule.action.lower()
        
        # Combine content and original_options for keyword search
        options_text = f"{rule.content} {rule.original_options}".lower()
        
        # Pass rules don't log UNLESS they have the 'alert' keyword
        if action == "pass":
            # Check if 'alert' keyword is present
            # Need to match 'alert' as a standalone keyword (not part of another word)
            import re
            if re.search(r'\balert\b', options_text):
                return False  # Has alert keyword, so it DOES log
            else:
                return True   # No alert keyword, so it does NOT log
        
        # Drop/reject rules don't log if they have 'noalert' keyword
        if action in ["drop", "reject"]:
            if "noalert" in options_text:
                return True   # Has noalert, so it does NOT log
            else:
                return False  # No noalert, so it DOES log
        
        # Alert rules always log
        return False
    
    def is_boto3_available(self) -> bool:
        """Check if boto3 is available
        
        Returns:
            bool: True if boto3 is installed and importable
        """
        return HAS_BOTO3
    
    def analyze_rules(
        self,
        rule_sids: List[int],
        log_group_name: str,
        time_range_days: int,
        low_frequency_threshold: int = 10,
        min_days_in_production: int = 14,
        progress_callback=None,
        cancel_flag=None,
        rules: Optional[List] = None,
        region: Optional[str] = None,
        start_date=None,
        end_date=None
    ) -> Optional[Dict]:
        """Analyze rule usage from CloudWatch Logs
        
        Args:
            rule_sids: List of SIDs from current rule set
            log_group_name: CloudWatch log group name
            time_range_days: Number of days to analyze (7, 30, 60, or 90)
            low_frequency_threshold: Threshold for low-frequency classification (default: 10 hits)
            min_days_in_production: Minimum days in production to be "confirmed unused" (default: 14)
            progress_callback: Optional callback function(current, total, status_text, batch_info=None)
            cancel_flag: Optional list with single boolean element to check for cancellation
            rules: Optional list of SuricataRule objects (needed to detect unlogged rules)
            region: Optional AWS region to use (uses default credentials region if not specified)
            start_date: Optional custom start date (datetime.date) for custom date range
            end_date: Optional custom end date (datetime.date) for custom date range
            
        Returns:
            Dict with comprehensive analysis results, or None if cancelled/failed
        """
        if not HAS_BOTO3:
            raise ImportError("boto3 is required for CloudWatch analysis")
        
        try:
            # Calculate time range - use custom dates if provided, otherwise use days offset
            if start_date and end_date:
                # Custom date range: convert date objects to datetime at start/end of day
                start_time = datetime.combine(start_date, datetime.min.time())
                end_time = datetime.combine(end_date, datetime.max.time())
            else:
                # Preset range: calculate from current time
                end_time = datetime.now()
                start_time = end_time - timedelta(days=time_range_days)
            
            # Create CloudWatch Logs client with specified region
            client = boto3.client('logs', region_name=region) if region else boto3.client('logs')
            
            # Submit query
            if progress_callback:
                progress_callback(0, 100, "Submitting query to CloudWatch...")
            
            response = client.start_query(
                logGroupName=log_group_name,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=self.CLOUDWATCH_QUERY,
                limit=10000
            )
            
            query_id = response['queryId']
            
            # Poll for results with timeout
            timeout = 90  # 90 second timeout
            poll_start = datetime.now()
            
            while True:
                # Check for timeout
                elapsed = (datetime.now() - poll_start).total_seconds()
                if elapsed > timeout:
                    raise TimeoutError("CloudWatch query timed out after 90 seconds")
                
                # Check for cancellation
                if cancel_flag and cancel_flag[0]:
                    return None
                
                # Get query status
                result = client.get_query_results(queryId=query_id)
                status = result['status']
                
                # Update progress if callback provided
                if progress_callback and 'statistics' in result:
                    records_scanned = result['statistics'].get('recordsScanned', 0)
                    progress_callback(
                        records_scanned,  # Current record count
                        result['statistics'].get('recordsMatched', 0),  # Total matched
                        f"Querying CloudWatch Logs... ({int(elapsed)}s elapsed)"
                    )
                
                if status == 'Complete':
                    break
                elif status == 'Failed':
                    raise RuntimeError("CloudWatch query failed")
                elif status == 'Cancelled':
                    return None
                
                # Wait before polling again
                time.sleep(1)
            
            # Parse initial results
            initial_stats = self._parse_cloudwatch_results(result)
            
            # Detect unlogged rules (rules that don't write to CloudWatch)
            unlogged_sids = set()
            if rules:
                for rule in rules:
                    if self.is_unlogged_rule(rule):
                        unlogged_sids.add(rule.sid)
            
            # Convert rule_sids list to set for calculations
            file_sids = set(rule_sids)
            
            # IMPORTANT: Exclude unlogged rules from analysis
            # These rules don't write to CloudWatch, so they can't be tracked
            logged_file_sids = file_sids - unlogged_sids
            
            # Check if we hit the 10,000 limit and may need pagination
            # Use 9999 threshold to detect when exactly at limit
            # OR debug mode enabled for testing
            choice = None
            if len(initial_stats) >= 9999 or self.debug_force_pagination:
                # Print debug message if forcing pagination
                if self.debug_force_pagination and len(initial_stats) < 9999:
                    print(f"DEBUG: Force pagination enabled for testing (only {len(initial_stats)} results)")
                # Potential incompleteness - offer user choice
                choice = self._handle_potential_incompleteness(
                    initial_stats, log_group_name, start_time, end_time,
                    logged_file_sids, progress_callback, cancel_flag, client
                )
                
                if choice == 'full':
                    # Run paginated analysis
                    sid_stats = self._run_paginated_analysis_hit_count(
                        initial_stats, log_group_name, start_time, end_time,
                        logged_file_sids, progress_callback, cancel_flag, client
                    )
                    if sid_stats is None:
                        return None  # User cancelled during pagination
                elif choice == 'partial':
                    sid_stats = initial_stats
                else:
                    return None  # User cancelled
            else:
                # No pagination needed
                sid_stats = initial_stats
            
            # Calculate unused rules (set difference) - only for logged rules
            triggered_sids = set(sid_stats.keys())
            unused_sids = logged_file_sids - triggered_sids
            
            # NEW: Identify untracked SIDs (in CloudWatch but not in file)
            # These are rules that exist in CloudWatch logs but not in the current rule file
            # This can happen when:
            # - User recently deleted/commented out rules (still in CloudWatch during timeframe)
            # - AWS applies default firewall policy rules (not in user's rules file)
            untracked_sids = triggered_sids - file_sids
            
            # Track if results are partial (for UI warning badge)
            # Check if choice is not None before comparing (user may have cancelled)
            partial_results = (len(initial_stats) >= 9999 and choice == 'partial') if (len(initial_stats) >= 9999 and choice is not None) else False
            
            # Calculate total hits
            total_hits = sum(stats['hits'] for stats in sid_stats.values())
            
            # Enhance statistics with calculated metrics
            for sid, stats in sid_stats.items():
                # Calculate percentage of total traffic
                stats['percent'] = (stats['hits'] / total_hits * 100) if total_hits > 0 else 0
                
                # Calculate hits per day
                stats['hits_per_day'] = stats['hits'] / time_range_days if time_range_days > 0 else 0
                
                # Determine category based on frequency
                hits = stats['hits']
                hits_per_day = stats['hits_per_day']
                
                if hits < low_frequency_threshold:
                    stats['category'] = 'low_freq'
                elif hits_per_day >= 10:
                    stats['category'] = 'high'
                elif hits_per_day >= 1:
                    stats['category'] = 'medium'
                else:
                    stats['category'] = 'low_freq'
                
                # Add placeholder values for rule details (will be None)
                stats['days_in_production'] = None
                stats['last_modified'] = None
            
            # Add entries for unused rules with 0 hits
            for sid in unused_sids:
                sid_stats[sid] = {
                    'hits': 0,
                    'percent': 0.0,
                    'category': 'unused',
                    'last_hit': None,
                    'last_hit_days': None,
                    'hits_per_day': 0,
                    'days_in_production': None,  # Will be populated by UI
                    'last_modified': None
                }
            
            # Calculate category counts (exclude untracked SIDs from all categories except 'untracked')
            categories = {
                'unused': len(unused_sids),
                'low_freq': len([sid for sid, s in sid_stats.items() if s.get('category') == 'low_freq' and sid not in untracked_sids]),
                'medium': len([sid for sid, s in sid_stats.items() if s.get('category') == 'medium' and sid not in untracked_sids]),
                'high': len([sid for sid, s in sid_stats.items() if s.get('category') == 'high' and sid not in untracked_sids]),
                'unlogged': len(unlogged_sids),
                'untracked': len(untracked_sids)
            }
            
            # Count broad rules (rules handling >10% of traffic - security risks)
            broad_rule_count = len([sid for sid, s in sid_stats.items() if s.get('percent', 0) > 10 and sid not in untracked_sids])
            
            # Calculate health score using only logged rules
            # Unlogged rules are excluded because they can't be tracked via CloudWatch
            # But we penalize for visibility gaps (unlogged rules create monitoring blind spots)
            health_score = self._calculate_health_score(
                len(logged_file_sids),  # Only count logged rules
                len(unused_sids),
                categories['low_freq'],
                broad_rule_count,  # Count broad rules
                len(unlogged_sids),  # Visibility penalty for unlogged rules
                len(file_sids)  # Total including unlogged for percentage calculation
            )
            
            # Run category analysis query (separate, non-blocking)
            # This retrieves per-alert category/hostname data for rules using
            # aws_domain_category or aws_url_category keywords
            if progress_callback:
                progress_callback(0, 100, "Querying category data...")
            
            category_data = self.query_category_data(
                client, log_group_name, start_time, end_time,
                progress_callback, cancel_flag, rules
            )
            
            # Store and return results in format expected by UI
            self.last_analysis_timestamp = datetime.now()
            self.last_analysis_results = {
                'timestamp': self.last_analysis_timestamp,
                'log_group': log_group_name,
                'time_range_days': time_range_days,
                'total_rules': len(file_sids),
                'total_logged_rules': len(logged_file_sids),  # For health score context
                'records_analyzed': result['statistics'].get('recordsMatched', 0),
                'sid_stats': sid_stats,
                'unused_sids': unused_sids,
                'unlogged_sids': unlogged_sids,  # Track unlogged rules
                'untracked_sids': untracked_sids,  # NEW: Track untracked rules (in CloudWatch but not in file)
                'file_sids': list(file_sids),  # BUG FIX #3: Add file_sids for right-click menu
                'categories': categories,
                'health_score': health_score,
                'low_freq_threshold': low_frequency_threshold,
                'min_days_in_production': min_days_in_production,
                'partial_results': partial_results,  # CloudWatch pagination: track if results are partial
                'category_analysis': category_data  # Category domain analysis data
            }
            
            return self.last_analysis_results
            
        except NoCredentialsError:
            raise NoCredentialsError("AWS credentials not configured")
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            raise ClientError(e.response, e.operation_name)
        except (EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError) as e:
            raise ConnectionError(f"Cannot connect to AWS: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Analysis failed: {str(e)}")
    
    def _handle_potential_incompleteness(
        self,
        initial_stats: Dict,
        log_group_name: str,
        start_time: datetime,
        end_time: datetime,
        logged_file_sids: Set[int],
        progress_callback,
        cancel_flag,
        client
    ) -> Optional[str]:
        """Handle potential incompleteness when 10,000 limit is reached
        
        This method is called by ui_manager to show a choice dialog to the user.
        The ui_manager will inject this method to display the dialog.
        
        Args:
            initial_stats: Initial query results (potentially incomplete)
            log_group_name: CloudWatch log group name
            start_time: Analysis start time
            end_time: Analysis end time
            logged_file_sids: Set of logged SIDs from file
            progress_callback: Progress update callback
            cancel_flag: Cancellation flag
            client: boto3 CloudWatch Logs client
            
        Returns:
            'full' for full analysis, 'partial' for partial results, None for cancel
        """
        # This will be called by UI layer to show the choice dialog
        # Default to partial if no UI handler is set
        return 'partial'
    
    def _run_paginated_analysis_hit_count(
        self,
        initial_stats: Dict,
        log_group_name: str,
        start_time: datetime,
        end_time: datetime,
        logged_file_sids: Set[int],
        progress_callback,
        cancel_flag,
        client
    ) -> Optional[Dict]:
        """Run paginated analysis using hit-count threshold strategy
        
        This is the optimal pagination strategy with minimal duplicates.
        Each batch filters by `hits <= threshold` where threshold is the
        minimum hit count from the previous batch.
        
        Args:
            initial_stats: Initial batch results (top 10,000)
            log_group_name: CloudWatch log group name
            start_time: Analysis start time
            end_time: Analysis end time
            logged_file_sids: Set of logged SIDs from file
            progress_callback: Progress update callback
            cancel_flag: Cancellation flag
            client: boto3 CloudWatch Logs client
            
        Returns:
            Complete sid_stats dict with all results, or None if cancelled
        """
        all_sid_stats = initial_stats.copy()
        retrieved_sids = set(initial_stats.keys())
        
        # Find minimum hit count from first batch (threshold for next query)
        if initial_stats:
            max_hits_threshold = min(stats['hits'] for stats in initial_stats.values())
        else:
            return all_sid_stats
        
        batch_number = 2
        max_batches = 3  # Safety limit (30,000 rules max per AWS Network Firewall)
        
        while batch_number <= max_batches:
            # Update progress
            if progress_callback:
                progress_callback(
                    len(all_sid_stats),
                    len(logged_file_sids),
                    f"Running query batch {batch_number}...",
                    batch_info={'batch_num': batch_number, 'total_retrieved': len(retrieved_sids)}
                )
            
            # Check for cancellation
            if cancel_flag and cancel_flag[0]:
                return None
            
            # Build query with hit count threshold
            query = f"""fields event.alert.signature_id as sid
| stats count() as hits, 
        max(@timestamp) as last_hit
        by sid
| filter hits > 0 and hits <= {max_hits_threshold}
| sort hits desc
| limit 10000"""
            
            # Execute query
            try:
                response = client.start_query(
                    logGroupName=log_group_name,
                    startTime=int(start_time.timestamp()),
                    endTime=int(end_time.timestamp()),
                    queryString=query,
                    limit=10000
                )
                
                query_id = response['queryId']
                
                # Poll for results
                timeout = 90
                poll_start = datetime.now()
                
                while True:
                    if (datetime.now() - poll_start).total_seconds() > timeout:
                        raise TimeoutError(f"Batch {batch_number} query timed out")
                    
                    if cancel_flag and cancel_flag[0]:
                        return None
                    
                    result = client.get_query_results(queryId=query_id)
                    status = result['status']
                    
                    if status == 'Complete':
                        break
                    elif status in ['Failed', 'Cancelled']:
                        raise RuntimeError(f"Batch {batch_number} query failed")
                    
                    time.sleep(1)
                
            except Exception as e:
                # Handle batch error gracefully
                print(f"Batch {batch_number} failed: {str(e)}")
                # Return what we have so far
                return all_sid_stats
            
            # Parse batch results
            batch_stats = self._parse_cloudwatch_results(result)
            
            if len(batch_stats) == 0:
                # No more results - done!
                break
            
            # Filter out duplicates (only at threshold boundary - typically 5-20)
            new_stats = {
                sid: stats for sid, stats in batch_stats.items() 
                if sid not in retrieved_sids
            }
            
            duplicate_count = len(batch_stats) - len(new_stats)
            if duplicate_count > 0 and batch_number == 2:
                # Expected on first paginated batch
                print(f"Batch {batch_number}: Filtered {duplicate_count} duplicate SIDs at threshold boundary (expected)")
            
            # Merge only new results
            all_sid_stats.update(new_stats)
            retrieved_sids.update(new_stats.keys())
            
            # Update threshold for next batch (minimum hits from this batch)
            if new_stats:
                max_hits_threshold = min(stats['hits'] for stats in new_stats.values())
            
            # Check if done
            if len(batch_stats) < 10000:
                break
            
            batch_number += 1
        
        # Success
        if progress_callback:
            progress_callback(
                len(all_sid_stats),
                len(logged_file_sids),
                f"Complete! Retrieved {len(all_sid_stats):,} rules across {batch_number} queries."
            )
        
        return all_sid_stats
    
    def _parse_cloudwatch_results(self, result: Dict) -> Dict:
        """Parse CloudWatch query results into usable format
        
        Args:
            result: CloudWatch query result dictionary
            
        Returns:
            Dict mapping SID to statistics: {sid: {'hits': int, 'last_hit': datetime, ...}}
        """
        sid_stats = {}
        
        for row in result.get('results', []):
            sid = None
            hits = None
            last_hit = None
            
            # Extract fields from row
            for field in row:
                field_name = field.get('field', '')
                field_value = field.get('value', '')
                
                if field_name == 'sid':
                    try:
                        sid = int(field_value)
                    except (ValueError, TypeError):
                        continue
                elif field_name == 'hits':
                    try:
                        hits = int(field_value)
                    except (ValueError, TypeError):
                        continue
                elif field_name == 'last_hit':
                    try:
                        # Parse CloudWatch timestamp
                        last_hit = datetime.fromisoformat(field_value.replace(' ', 'T'))
                    except (ValueError, TypeError):
                        continue
            
            # Only add if we have valid SID and hits
            if sid is not None and hits is not None:
                # BUG FIX #2: Use date() comparison to avoid negative values from timezone issues
                # Strip timezone info from both datetimes before comparing to ensure consistency
                if last_hit:
                    # Convert both to naive datetime in local timezone, then compare dates
                    now_naive = datetime.now().replace(tzinfo=None)
                    last_hit_naive = last_hit.replace(tzinfo=None)
                    last_hit_days = (now_naive.date() - last_hit_naive.date()).days
                    
                    # Ensure non-negative (in case of clock skew)
                    last_hit_days = max(0, last_hit_days)
                else:
                    last_hit_days = None
                
                sid_stats[sid] = {
                    'hits': hits,
                    'last_hit': last_hit,
                    'last_hit_days': last_hit_days
                }
        
        return sid_stats
    
    def _extract_file_sids(self, rules: List) -> Set[int]:
        """Extract all SIDs from current rule file
        
        Args:
            rules: List of SuricataRule objects
            
        Returns:
            Set of SIDs from actual rules (excludes comments and blanks)
        """
        file_sids = set()
        
        for rule in rules:
            # Skip comments and blank lines
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            # Add SID to set
            file_sids.add(rule.sid)
        
        return file_sids
    
    def _enhance_sid_stats(
        self,
        sid_stats: Dict,
        time_range_days: int,
        total_hits: int,
        rules: List,
        min_days_prod: int
    ) -> Dict:
        """Add calculated metrics to each SID's statistics
        
        Args:
            sid_stats: Raw statistics from CloudWatch
            time_range_days: Analysis time range
            total_hits: Sum of all hits across all rules
            rules: List of SuricataRule objects
            min_days_prod: Minimum days to be considered "in production"
            
        Returns:
            Enhanced sid_stats with additional fields
        """
        # Create SID to rule mapping for quick lookup
        sid_to_rule = {}
        for rule in rules:
            if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False):
                sid_to_rule[rule.sid] = rule
        
        for sid, stats in sid_stats.items():
            # Calculate percentage of total traffic
            stats['percent'] = (stats['hits'] / total_hits * 100) if total_hits > 0 else 0
            
            # Calculate hits per day
            stats['hits_per_day'] = stats['hits'] / time_range_days if time_range_days > 0 else 0
            
            # Get rule age from revision history (if available)
            # This will be integrated with existing change tracking
            rule = sid_to_rule.get(sid)
            if rule:
                stats['action'] = rule.action
                stats['protocol'] = rule.protocol
                stats['message'] = rule.message
                # Rule age calculation will be added when integrating with main app
                stats['age_days'] = None
                stats['rev'] = getattr(rule, 'rev', 1)
            
            # Determine category
            stats['category'] = self._determine_rule_category(stats, time_range_days)
        
        return sid_stats
    
    def _determine_rule_category(self, stats: Dict, time_range_days: int) -> str:
        """Determine which category a rule belongs to
        
        Args:
            stats: Rule statistics dictionary
            time_range_days: Analysis time range
            
        Returns:
            String category name
        """
        hits = stats['hits']
        hits_per_day = stats['hits_per_day']
        percent = stats['percent']
        
        # Broadness detection (Critical > High > Medium)
        if percent > 30:
            return "Critical-Broad"
        elif percent > 15:
            return "High-Broad"
        elif percent > 10:
            return "Medium-Broad"
        
        # Efficiency tier classification
        if hits_per_day > 100:
            return "Critical"
        elif hits_per_day >= 10:
            return "High"
        elif hits_per_day >= 1:
            return "Medium"
        elif hits > 0:
            return "Low-Frequency"
        else:
            # This shouldn't happen (query filters hits > 0)
            return "Unused"
    
    def _categorize_unused_rules(
        self,
        unused_sids: Set[int],
        rules: List,
        min_days_prod: int
    ) -> Dict:
        """Categorize unused rules by confidence level
        
        Args:
            unused_sids: Set of SIDs with 0 hits
            rules: List of SuricataRule objects
            min_days_prod: Minimum days to be "confirmed unused"
            
        Returns:
            Dict with three categories: confirmed, recent, never_observed
        """
        confirmed = []  # ≥14 days old, 0 hits
        recent = []     # <14 days old, 0 hits
        never_observed = []  # Unknown age, 0 hits
        
        # Create SID to rule mapping
        sid_to_rule = {}
        for rule in rules:
            if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False):
                sid_to_rule[rule.sid] = rule
        
        for sid in unused_sids:
            rule = sid_to_rule.get(sid)
            if not rule:
                continue
            
            # Get rule age (will integrate with change tracking)
            # For now, assume unknown age
            age_days = None  # Will be populated from revision history
            
            rule_info = {
                'sid': sid,
                'action': rule.action,
                'protocol': rule.protocol,
                'message': rule.message,
                'age_days': age_days,
                'rev': getattr(rule, 'rev', 1)
            }
            
            if age_days is not None:
                if age_days >= min_days_prod:
                    confirmed.append(rule_info)
                else:
                    recent.append(rule_info)
            else:
                never_observed.append(rule_info)
        
        return {
            'confirmed': confirmed,
            'recent': recent,
            'never_observed': never_observed
        }
    
    def _calculate_health_score(
        self,
        total_rules: int,
        unused_rules: int,
        low_freq_rules: int,
        broad_rules: int,
        unlogged_rules: int = 0,
        total_rules_including_unlogged: int = None
    ) -> int:
        """Calculate overall rule group health score (0-100)
        
        IMPROVED FORMULA (Option C + Option 5):
        Separates unused and low-frequency rules for clearer scoring.
        
        Components:
        - Base: 20 points (for having rules deployed)
        - Effectiveness: 0-50 points (reward medium/high-frequency rules)
        - Usage: 0-30 points (reward ANY usage, strongly penalize unused)
        - Broad penalty: 0-15 points (penalize security risks)
        - Visibility penalty: 0-15 points (penalize monitoring blind spots)
        
        Maximum: 100 points (naturally, no scaling needed)
        Minimum: 0 points (negative scores floored at 0)
        
        Grading scale:
        - 80-100: Excellent (outstanding effectiveness)
        - 60-79: Good (solid effectiveness)
        - 40-59: Fair (acceptable, room for improvement)
        - 0-39: Poor (needs significant work)
        
        Args:
            total_rules: Total number of logged rules
            unused_rules: Number of unused rules (0 hits)
            low_freq_rules: Number of low-frequency rules (<10 hits)
            broad_rules: Number of overly-broad rules (>10% traffic)
            unlogged_rules: Number of unlogged rules (monitoring blind spots)
            total_rules_including_unlogged: Total rules including unlogged (for visibility %)
            
        Returns:
            Integer score from 0-100
        """
        if total_rules == 0:
            return 0
        
        total_for_pct = total_rules_including_unlogged if total_rules_including_unlogged else total_rules
        
        # Calculate effective rules (medium/high frequency)
        effective_rules = total_rules - unused_rules - low_freq_rules
        effective_rules = max(0, effective_rules)
        
        # Calculate used rules (any hits, including low-freq)
        used_rules = total_rules - unused_rules
        used_rules = max(0, used_rules)
        
        # Base score: 20 points for having rules deployed
        base = 20.0
        
        # Effectiveness reward: 0-50 points
        # Rewards having rules that are medium/high frequency
        effectiveness_ratio = effective_rules / total_rules if total_rules > 0 else 0
        effectiveness_reward = effectiveness_ratio * 50.0
        
        # Usage reward: 0-30 points
        # Rewards ANY usage (even low-frequency), strongly penalizes unused
        usage_ratio = used_rules / total_rules if total_rules > 0 else 0
        usage_reward = usage_ratio * 30.0
        
        # Broad rules penalty: 0-15 points
        # Penalize rules handling >10% of traffic (security concern)
        broad_penalty = min(15, broad_rules * 4)
        
        # Visibility penalty: 0-15 points (Balanced Hybrid - Option 5)
        # Penalize unlogged rules (monitoring blind spots)
        # Scale-aware: balances absolute count with percentage
        if unlogged_rules > 0:
            unlogged_pct = (unlogged_rules / total_for_pct) * 100
            absolute_component = unlogged_rules * 1.0
            percentage_component = unlogged_pct * 0.5
            visibility_penalty = min(15, (absolute_component + percentage_component) / 2)
        else:
            visibility_penalty = 0
        
        # Calculate final score
        score = base + effectiveness_reward + usage_reward - broad_penalty - visibility_penalty
        
        # Ensure bounds [0, 100]
        return int(max(0, min(100, score)))
    
    def query_category_data(self, client, log_group_name, start_time, end_time,
                            progress_callback, cancel_flag, rules):
        """Query CloudWatch for category and hostname data from alerts.
        
        This runs a separate query to retrieve per-alert category/hostname data
        for rules using aws_domain_category or aws_url_category keywords.
        
        Args:
            client: boto3 CloudWatch Logs client
            log_group_name: CloudWatch log group name
            start_time: Analysis start time
            end_time: Analysis end time
            progress_callback: Progress update callback
            cancel_flag: Cancellation flag
            rules: List of SuricataRule objects (for action lookup)
        
        Returns:
            Dict mapping category → domain aggregation data,
            or empty dict if no category data found or query fails.
        """
        try:
            if progress_callback:
                progress_callback(0, 100, "Querying category data from CloudWatch...")
            
            response = client.start_query(
                logGroupName=log_group_name,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=self.CATEGORY_QUERY,
                limit=10000
            )
            
            query_id = response['queryId']
            
            # Poll for results (same pattern as existing query)
            timeout = 90
            poll_start = datetime.now()
            
            while True:
                elapsed = (datetime.now() - poll_start).total_seconds()
                if elapsed > timeout:
                    return {}  # Timeout — return empty, don't block main analysis
                
                if cancel_flag and cancel_flag[0]:
                    return {}
                
                result = client.get_query_results(queryId=query_id)
                status = result['status']
                
                if progress_callback:
                    try:
                        progress_callback(0, 100,
                            f"Querying category data... ({int(elapsed)}s elapsed)")
                    except:
                        pass
                
                if status == 'Complete':
                    break
                elif status in ['Failed', 'Cancelled']:
                    return {}
                
                time.sleep(1)
            
            # Parse results
            alert_records = self._parse_category_results(result)
            
            if not alert_records:
                return {}
            
            # Build SID → rule lookup
            rules_by_sid = {}
            if rules:
                for rule in rules:
                    if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False):
                        rules_by_sid[rule.sid] = rule
            
            # Build set of SIDs that belong to category rules, and which
            # specific categories each SID targets
            # Only these SIDs should appear in the category analysis results
            category_rule_sids, sid_to_categories = self._extract_category_rule_sids(rules)
            
            # Aggregate into category → domain structure
            category_data = self._aggregate_category_data(
                alert_records, rules_by_sid, category_rule_sids, sid_to_categories)
            
            # Track if results are potentially truncated
            if len(result.get('results', [])) >= 10000:
                category_data['_truncated'] = True
            
            return category_data
        
        except Exception as e:
            # Category query failure should not block main analysis
            print(f"Category query failed (non-fatal): {str(e)}")
            return {}
    
    def _parse_category_results(self, result):
        """Parse CloudWatch category query results into list of alert records.
        
        Args:
            result: CloudWatch query result dictionary
        
        Returns:
            List of dicts with keys: sid, categories, http_host, tls_sni
        """
        records = []
        
        for row in result.get('results', []):
            record = {}
            for field in row:
                field_name = field.get('field', '')
                field_value = field.get('value', '')
                
                if field_name == 'sid':
                    record['sid'] = field_value
                elif field_name == 'categories':
                    record['categories'] = field_value
                elif field_name == 'http_host':
                    record['http_host'] = field_value
                elif field_name == 'tls_sni':
                    record['tls_sni'] = field_value
            
            if record.get('categories'):
                records.append(record)
        
        return records
    
    def _extract_category_rule_sids(self, rules):
        """Extract SIDs of rules that use aws_domain_category or aws_url_category keywords,
        along with which specific categories each SID targets.
        
        This identifies which rules are "category rules" so that alerts from
        non-category rules can be excluded from the category analysis. It also
        maps each SID to the specific categories it targets, so that a SID is
        only associated with the categories its rule actually matches against.
        
        Args:
            rules: List of SuricataRule objects
            
        Returns:
            Tuple of (category_rule_sids, sid_to_categories) where:
              - category_rule_sids: Set of SIDs (int) for rules that use category keywords
              - sid_to_categories: Dict mapping SID (int) → set of category name strings
                that the rule targets
        """
        import re
        category_sids = set()
        sid_to_categories = {}
        
        if not rules:
            return category_sids, sid_to_categories
        
        for rule in rules:
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            # Check content and original_options for category keywords
            options_text = f"{rule.content} {getattr(rule, 'original_options', '')}"
            
            # Match aws_domain_category:Value or aws_url_category:Value
            # Categories can be comma-separated: aws_domain_category:Malware,Phishing
            targeted_cats = set()
            for match in re.finditer(r'aws_(?:domain|url)_category:([^;]+)', options_text):
                cat_str = match.group(1).strip()
                for cat in cat_str.split(','):
                    cat = cat.strip()
                    if cat:
                        targeted_cats.add(cat)
            
            if targeted_cats:
                category_sids.add(rule.sid)
                sid_to_categories[rule.sid] = targeted_cats
        
        return category_sids, sid_to_categories
    
    def _aggregate_category_data(self, alert_records, rules_by_sid,
                                 category_rule_sids=None, sid_to_categories=None):
        """Aggregate alert records into category → domain structure.
        
        Only includes alerts from rules that use aws_domain_category or
        aws_url_category keywords. Alerts from non-category rules are excluded
        to prevent unrelated SIDs from appearing in the category analysis.
        
        Additionally, a SID is only associated with the specific categories
        that its rule targets. For example, if SID 100 targets "Business and Economy"
        and a domain belongs to both "Business and Economy" and "Technology and Internet",
        SID 100 will only appear under "Business and Economy" — not under
        "Technology and Internet" (unless another rule targeting that category also matched).
        
        The rule_count field reflects how many rules in the file TARGET each category,
        not just how many rules fired in CloudWatch data. This ensures the dropdown
        label accurately shows that the user has rules defined for a category even if
        a different rule (earlier in strict rule ordering) fired first.
        
        Args:
            alert_records: List of parsed alert record dicts
            rules_by_sid: Dict mapping SID → SuricataRule
            category_rule_sids: Set of SIDs that belong to category rules.
                If provided, alerts from non-category rules are excluded.
            sid_to_categories: Dict mapping SID (int) → set of category name strings
                that the rule targets. If provided, a SID is only associated with
                the categories its rule actually matches against.
        
        Returns:
            Dict mapping category_name → {
                'total_hits': int,
                'rule_count': int,
                'rule_sids': list,
                'unique_domains': int,
                'domains': {
                    hostname: {
                        'hits': int,
                        'percent': float,
                        'matched_sids': list,
                        'actions': list
                    }
                }
            }
        """
        import json
        from collections import defaultdict
        
        # Build category → set of SIDs that target it (from rule file, not CloudWatch)
        # This gives the "defined rule count" for each category regardless of what fired
        category_to_defined_sids = defaultdict(set)
        if sid_to_categories:
            for sid, cats in sid_to_categories.items():
                for cat in cats:
                    category_to_defined_sids[cat].add(sid)
        
        # Temporary structure using sets for deduplication
        cat_temp = defaultdict(lambda: {
            'total_hits': 0,
            'direct_hits': 0,
            'rule_sids': set(),
            'domains': defaultdict(lambda: {
                'hits': 0,
                'matched_sids': set(),
                'actions': set()
            })
        })
        
        for alert in alert_records:
            sid_str = alert.get('sid')
            aws_category_str = alert.get('categories')
            hostname = alert.get('http_host') or alert.get('tls_sni') or '(unknown)'
            
            if not aws_category_str:
                continue
            
            sid = int(sid_str) if sid_str else None
            
            # Skip alerts from non-category rules
            # The CloudWatch query returns all alerts with aws_category data present,
            # but aws_category can be present on alerts from ANY rule that fires on a
            # connection where category evaluation occurred. We only want alerts from
            # rules that actually use aws_domain_category or aws_url_category keywords.
            if category_rule_sids is not None and sid is not None:
                if sid not in category_rule_sids:
                    continue
            
            try:
                categories = json.loads(aws_category_str)
            except (json.JSONDecodeError, TypeError):
                continue
            
            rule = rules_by_sid.get(sid) if sid else None
            action = rule.action.upper() if rule else '(unknown)'
            
            # Determine which categories this SID actually targets
            # If sid_to_categories is available, only associate the SID with
            # categories the rule actually matches against
            sid_targeted_cats = None
            if sid_to_categories is not None and sid is not None:
                sid_targeted_cats = sid_to_categories.get(sid)
            
            for category in categories:
                # Determine if the SID should be associated with this category
                # The alert record always lists ALL categories the domain belongs to,
                # but the SID should only appear under categories it actually targets
                sid_targets_this_cat = True
                if sid_targeted_cats is not None:
                    sid_targets_this_cat = category in sid_targeted_cats
                
                cat = cat_temp[category]
                cat['total_hits'] += 1
                if sid and sid_targets_this_cat:
                    cat['direct_hits'] += 1
                    cat['rule_sids'].add(sid)
                
                dom = cat['domains'][hostname]
                dom['hits'] += 1
                if sid and sid_targets_this_cat:
                    dom['matched_sids'].add(sid)
                dom['actions'].add(action)
        
        # Convert to serializable format with percentages
        result = {}
        for category, data in cat_temp.items():
            total = data['total_hits']
            domains = {}
            for hostname, dom_data in data['domains'].items():
                domains[hostname] = {
                    'hits': dom_data['hits'],
                    'percent': round((dom_data['hits'] / total * 100), 1) if total > 0 else 0,
                    'matched_sids': sorted(list(dom_data['matched_sids'])),
                    'actions': sorted(list(dom_data['actions']))
                }
            
            # rule_count reflects how many rules in the file TARGET this category,
            # not just how many fired. This is important when strict rule ordering
            # causes an earlier rule to fire instead of the one targeting this category.
            defined_sids = category_to_defined_sids.get(category, set())
            
            result[category] = {
                'total_hits': total,
                'direct_hits': data['direct_hits'],
                'rule_count': len(defined_sids),
                'rule_sids': sorted(list(data['rule_sids'])),
                'unique_domains': len(domains),
                'domains': domains
            }
        
        return result
    
    @staticmethod
    def extract_rule_categories(rules):
        """Extract aws_domain_category and aws_url_category values from rules.
        
        Scans all rules for aws_domain_category and aws_url_category keywords
        and returns the set of category names that have rules defined for them.
        
        Args:
            rules: List of SuricataRule objects
            
        Returns:
            Set of category name strings found in rules
        """
        import re
        categories = set()
        
        if not rules:
            return categories
        
        for rule in rules:
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            # Check content and original_options for category keywords
            options_text = f"{rule.content} {getattr(rule, 'original_options', '')}"
            
            # Match aws_domain_category:Value or aws_url_category:Value
            # Categories can be comma-separated: aws_domain_category:Malware,Phishing
            for match in re.finditer(r'aws_(?:domain|url)_category:([^;]+)', options_text):
                cat_str = match.group(1).strip()
                # Split comma-separated categories
                for cat in cat_str.split(','):
                    cat = cat.strip()
                    if cat:
                        categories.add(cat)
        
        return categories
    
    def get_health_status(self, score: int) -> str:
        """Get health status label from score
        
        Args:
            score: Health score (0-100)
            
        Returns:
            String label: "Poor", "Fair", "Good", or "Excellent"
        """
        if score >= 80:
            return "Excellent"
        elif score >= 60:
            return "Good"
        elif score >= 40:
            return "Fair"
        else:
            return "Poor"
