"""
MRG GUI Package

Contains all GUI components for the Managed Rule Group Generator:
- config_panel: Configuration panel with region, profile, source, filter controls
- source_browser: Multi-select checklist for AWS managed rule groups
- filter_builder: Dynamic row-based filter builder
- rule_table: Read-only rule display table with color-coded actions
- status_bar: Bottom status bar with capacity, action counts, SID range
- view_filter_bar: Display-only protocol/network/SID view filters
- search_bar: Ctrl+F find bar for rule table
- deploy_dialog: Deployment progress dialog
- browse_configs_dialog: Browse deployed configurations in AWS
- backup_manager: Manage backup rule groups
- rollback_dialog: Rollback to a backup rule group
- log_viewer: Session log viewer window
- help_dialogs: AWS Setup Guide and About dialog
"""
