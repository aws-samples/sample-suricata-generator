"""
Version Management for Suricata Rule Generator

This module centralizes version information for the main program.
The rule analyzer and flow tester have their own separate version numbers.
"""

# Main program version - update this single location for version changes
MAIN_VERSION = "1.18.12"

# Rule analyzer version (managed separately)
ANALYZER_VERSION = "1.8.2"

# Flow tester version (managed separately)
FLOW_TESTER_VERSION = "1.0.2"


def get_main_version() -> str:
    """Get the main program version number"""
    return MAIN_VERSION


def get_analyzer_version() -> str:
    """Get the rule analyzer version number"""
    return ANALYZER_VERSION


def get_flow_tester_version() -> str:
    """Get the flow tester version number"""
    return FLOW_TESTER_VERSION
