"""
Version Management for Managed Rule Group (MRG) Generator Module

The MRG version is maintained centrally in src/core/version.py alongside
all other sub-feature versions. This module re-exports it for convenience.
"""

from src.core.version import MRG_VERSION, get_mrg_version

__all__ = ["MRG_VERSION", "get_mrg_version"]
