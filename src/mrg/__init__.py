"""
Managed Rule Group (MRG) Generator Module

Provides functionality for cherry-picking rules from AWS-managed threat
signature rule groups, deploying filtered rule groups to AWS Network Firewall,
and maintaining automatic synchronization via Lambda.
"""

from src.mrg.version import MRG_VERSION

__all__ = ["MRG_VERSION"]
