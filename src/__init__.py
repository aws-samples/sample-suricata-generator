"""
Suricata Generator source package.

Provides PROJECT_ROOT for resolving data file paths from any submodule.
"""
import os

# PROJECT_ROOT points to the repository root directory (parent of src/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))