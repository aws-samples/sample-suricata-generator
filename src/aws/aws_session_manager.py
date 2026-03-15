"""
AWS Session Manager for Suricata Rule Generator

Centralizes AWS credential and session management with profile support.
Provides a single point of control for AWS profile selection, ensuring all
AWS API calls use the same credentials and default region.

This module is designed for graceful degradation: if boto3 is not installed,
all methods return safe defaults and no errors are raised at import time.
"""

import os

# Optional boto3 import with graceful degradation
HAS_BOTO3 = False
try:
    import boto3
    import botocore.session
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
    HAS_BOTO3 = True
except ImportError:
    boto3 = None


class AWSSessionManager:
    """Manages AWS sessions with profile support.
    
    Provides methods to:
    - List available AWS profiles from ~/.aws/credentials and ~/.aws/config
    - Create boto3 sessions with a selected profile
    - Create boto3 clients that respect the selected profile
    - Get the default region for the selected profile
    - Validate profile credentials via sts:GetCallerIdentity
    
    The selected profile is session-only (not persisted to disk). On every
    program launch, the profile resets to (default), which uses the standard
    AWS credential chain — identical to behavior without this module.
    
    Cross-platform: Works on Windows, macOS, and Linux. All file path
    resolution is delegated to boto3/botocore which handles platform
    differences natively via os.path.expanduser('~').
    """
    
    def __init__(self):
        self._profile_name = None  # None = default credential chain
        self._session = None       # Cached boto3.Session
    
    @property
    def profile_name(self):
        """Get the currently selected profile name (None = default)"""
        return self._profile_name
    
    @profile_name.setter
    def profile_name(self, value):
        """Set the profile name and invalidate cached session.
        
        Treats empty string and '(default)' as None (default credential chain).
        Setting a profile does NOT trigger any AWS API call — credentials are
        only validated when the user performs an explicit AWS action.
        """
        if value in (None, '', '(default)'):
            value = None
        self._profile_name = value
        self._session = None  # Invalidate cached session
    
    @property
    def display_name(self):
        """Human-readable name for the current profile.
        
        Returns:
            str: The profile name, or '(default)' if using the default credential chain.
        """
        return self._profile_name if self._profile_name else '(default)'
    
    def get_session(self):
        """Get or create a boto3 Session with the selected profile.
        
        Returns:
            boto3.Session configured with the selected profile.
            
        Raises:
            ImportError: If boto3 is not installed.
        """
        if not HAS_BOTO3:
            raise ImportError("boto3 is required for AWS operations. Install with: pip install boto3")
        
        if self._session is None:
            if self._profile_name:
                self._session = boto3.Session(profile_name=self._profile_name)
            else:
                self._session = boto3.Session()
        
        return self._session
    
    def get_client(self, service_name, region_name=None):
        """Create a boto3 client for the given service.
        
        The client inherits the profile's credentials and default region.
        The region_name parameter overrides the profile's default region
        if provided (preserving existing dialog region selector behavior).
        
        Args:
            service_name: AWS service name (e.g., 'network-firewall', 'logs')
            region_name: Optional region override. If None, uses profile's default region.
            
        Returns:
            boto3 client configured with the selected profile and region.
            
        Raises:
            ImportError: If boto3 is not installed.
        """
        session = self.get_session()
        if region_name:
            return session.client(service_name, region_name=region_name)
        else:
            return session.client(service_name)
    
    def get_default_region(self):
        """Get the default region for the selected profile.
        
        Returns:
            str: Region name (e.g., 'us-east-1'). Falls back to 'us-east-1'
                 if not configured or if boto3 is not installed.
        """
        if not HAS_BOTO3:
            return 'us-east-1'
        
        try:
            session = self.get_session()
            return session.region_name or 'us-east-1'
        except Exception:
            return 'us-east-1'
    
    def list_available_profiles(self):
        """List all available AWS profiles from config files.
        
        Reads profile names from both ~/.aws/credentials and ~/.aws/config.
        Always includes 'default' as the first entry if it exists.
        Non-default profiles are sorted alphabetically.
        
        Returns:
            list: Profile names (e.g., ['default', 'dev-account', 'prod-account']).
                  Returns empty list if boto3 is not installed or no config files exist.
        """
        if not HAS_BOTO3:
            return []
        
        try:
            # Use botocore's session to enumerate profiles
            # This reads both ~/.aws/credentials and ~/.aws/config
            session = botocore.session.Session()
            available = session.available_profiles
            
            # Ensure 'default' is first if it exists
            if 'default' in available:
                profiles = ['default'] + [p for p in sorted(available) if p != 'default']
            else:
                profiles = sorted(available)
            
            return profiles
        except Exception:
            return []
    
    def validate_profile(self, profile_name=None):
        """Validate credentials by calling sts:GetCallerIdentity.
        
        This method makes an actual AWS API call and should only be called
        when explicitly requested by the user (e.g., Help > AWS Setup).
        It is NOT called on profile selection or on startup.
        
        Args:
            profile_name: Profile to validate. If None, validates the
                         currently selected profile.
            
        Returns:
            tuple: (is_valid: bool, info_or_error: dict or str)
                   On success, info_or_error contains 'Account', 'Arn', 'UserId'.
                   On failure, info_or_error contains an error message string.
        """
        if not HAS_BOTO3:
            return (False, "boto3 is not installed. Install with: pip install boto3")
        
        try:
            if profile_name is not None:
                # Validate a specific profile (treat '(default)' as None)
                effective_profile = profile_name if profile_name not in ('(default)', '') else None
                session = boto3.Session(profile_name=effective_profile)
            else:
                # Validate the currently selected profile
                session = self.get_session()
            
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            
            return (True, {
                'Account': identity.get('Account', 'Unknown'),
                'Arn': identity.get('Arn', 'Unknown'),
                'UserId': identity.get('UserId', 'Unknown')
            })
        except NoCredentialsError:
            return (False, "No credentials found for this profile")
        except ProfileNotFound as e:
            return (False, f"Profile not found: {str(e)}")
        except ClientError as e:
            return (False, str(e))
        except Exception as e:
            return (False, str(e))