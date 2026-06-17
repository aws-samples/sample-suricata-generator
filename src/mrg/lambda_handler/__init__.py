"""
MRG Lambda handler package.

Contains the AWS Lambda entry point for automatic rule group synchronization.
Note: The handler retains 'from core.xxx' import paths since it runs in its
own isolated deployment package where core modules are bundled at the top level.
"""
