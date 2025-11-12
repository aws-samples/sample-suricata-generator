"""
Security Validation Module for Suricata Rule Generator

This module provides comprehensive security validation to protect against
various attack vectors including injection attacks, path traversal, and
malicious input.
"""

import re
import os
from typing import Optional
from constants import SuricataConstants, SecurityConstants, ValidationMessages


class SecurityValidator:
    """Provides security validation for all user inputs and file operations"""
    
    def __init__(self):
        """Initialize the security validator with compiled patterns"""
        # Pre-compile regex patterns for better performance
        self.dangerous_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in SecurityConstants.DANGEROUS_PATTERNS
        ]
        self.safe_filename_pattern = re.compile(SecurityConstants.SAFE_FILENAME_PATTERN)
        self.domain_pattern = re.compile(SecurityConstants.DOMAIN_PATTERN)
    
    def validate_input_safety(self, input_text: str, max_length: Optional[int] = None) -> bool:
        """Validate input text for dangerous patterns and length
        
        Args:
            input_text: The text to validate
            max_length: Maximum allowed length (optional)
            
        Returns:
            bool: True if input is safe
            
        Raises:
            ValueError: If input contains dangerous patterns or exceeds length
        """
        if not isinstance(input_text, str):
            raise ValueError("Input must be a string")
        
        # Check length if specified
        if max_length and len(input_text) > max_length:
            raise ValueError(ValidationMessages.INPUT_TOO_LONG.format(max_length=max_length))
        
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if pattern.search(input_text):
                raise ValueError(ValidationMessages.DANGEROUS_INPUT)
        
        return True
    
    def validate_rule_message(self, message: str) -> bool:
        """Validate rule message for safety and length
        
        Args:
            message: Rule message text
            
        Returns:
            bool: True if message is safe
            
        Raises:
            ValueError: If message is unsafe or too long
        """
        return self.validate_input_safety(message, SecurityConstants.MAX_MESSAGE_LENGTH)
    
    def validate_rule_content(self, content: str) -> bool:
        """Validate rule content keywords for safety and length
        
        Args:
            content: Rule content keywords
            
        Returns:
            bool: True if content is safe
            
        Raises:
            ValueError: If content is unsafe or too long
        """
        return self.validate_input_safety(content, SecurityConstants.MAX_CONTENT_LENGTH)
    
    def validate_comment_text(self, comment: str) -> bool:
        """Validate comment text for safety and length
        
        Args:
            comment: Comment text
            
        Returns:
            bool: True if comment is safe
            
        Raises:
            ValueError: If comment is unsafe or too long
        """
        return self.validate_input_safety(comment, SecurityConstants.MAX_COMMENT_LENGTH)
    
    def validate_variable_name(self, var_name: str) -> bool:
        """Validate variable name for safety and length
        
        Args:
            var_name: Variable name (e.g., $HOME_NET)
            
        Returns:
            bool: True if variable name is safe
            
        Raises:
            ValueError: If variable name is unsafe or too long
        """
        if len(var_name) > SecurityConstants.MAX_VARIABLE_NAME_LENGTH:
            raise ValueError(ValidationMessages.INPUT_TOO_LONG.format(
                max_length=SecurityConstants.MAX_VARIABLE_NAME_LENGTH
            ))
        
        # Variable names should only contain safe characters
        if not re.match(r'^[$@][a-zA-Z0-9_]+$', var_name):
            raise ValueError("Variable name contains invalid characters. Use only letters, numbers, and underscores after $ or @.")
        
        return True
    
    def validate_variable_value(self, var_value: str) -> bool:
        """Validate variable value for safety and length
        
        Args:
            var_value: Variable value (CIDR list, port list, or ARN)
            
        Returns:
            bool: True if variable value is safe
            
        Raises:
            ValueError: If variable value is unsafe or too long
        """
        return self.validate_input_safety(var_value, SecurityConstants.MAX_VARIABLE_VALUE_LENGTH)
    
    def validate_domain_name(self, domain: str) -> bool:
        """Validate domain name format and safety
        
        Args:
            domain: Domain name to validate
            
        Returns:
            bool: True if domain is valid and safe
            
        Raises:
            ValueError: If domain is invalid, unsafe, or too long
        """
        if len(domain) > SecurityConstants.MAX_DOMAIN_LENGTH:
            raise ValueError(f"Domain name too long (max {SecurityConstants.MAX_DOMAIN_LENGTH} characters)")
        
        # Check for dangerous patterns in domain
        self.validate_input_safety(domain)
        
        # Validate domain format (basic check)
        if not self.domain_pattern.match(domain):
            raise ValueError("Invalid domain name format")
        
        return True
    
    def validate_filename(self, filename: str) -> bool:
        """Validate filename for safety (no path traversal)
        
        Args:
            filename: Filename to validate
            
        Returns:
            bool: True if filename is safe
            
        Raises:
            ValueError: If filename contains dangerous characters
        """
        # Get just the filename part (no directory)
        base_filename = os.path.basename(filename)
        
        # Check for path traversal attempts
        if '..' in filename or '/' in base_filename or '\\' in base_filename:
            raise ValueError("Filename contains path traversal characters")
        
        # Check for safe characters only
        if not self.safe_filename_pattern.match(base_filename):
            raise ValueError("Filename contains unsafe characters. Use only letters, numbers, dots, underscores, and hyphens.")
        
        return True
    
    def validate_file_size(self, filepath: str, max_size: int) -> bool:
        """Validate file size against maximum allowed
        
        Args:
            filepath: Path to file to check
            max_size: Maximum allowed size in bytes
            
        Returns:
            bool: True if file size is acceptable
            
        Raises:
            ValueError: If file is too large
            FileNotFoundError: If file doesn't exist
            PermissionError: If file cannot be accessed
        """
        try:
            file_size = os.path.getsize(filepath)
            if file_size > max_size:
                max_mb = max_size / (1024 * 1024)
                raise ValueError(ValidationMessages.FILE_TOO_LARGE.format(max_size=max_mb))
            return True
        except FileNotFoundError:
            raise FileNotFoundError(ValidationMessages.FILE_NOT_FOUND.format(filename=filepath))
        except PermissionError:
            raise PermissionError(ValidationMessages.FILE_PERMISSION_DENIED.format(filename=filepath))
    
    def validate_import_limits(self, item_count: int, max_items: int, item_type: str = "items") -> bool:
        """Validate import operation limits to prevent resource exhaustion
        
        Args:
            item_count: Number of items being imported
            max_items: Maximum allowed items
            item_type: Type of items for error message
            
        Returns:
            bool: True if within limits
            
        Raises:
            ValueError: If import exceeds limits
        """
        if item_count > max_items:
            raise ValueError(f"Import exceeds maximum allowed {item_type}: {item_count} > {max_items}")
        
        return True
    
    def sanitize_user_input(self, user_input: str, preserve_case: bool = True) -> str:
        """Sanitize user input by removing dangerous characters
        
        Args:
            user_input: Raw user input
            preserve_case: Whether to preserve original case
            
        Returns:
            str: Sanitized input
        """
        if not isinstance(user_input, str):
            return str(user_input)
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', user_input)
        
        # Remove potentially dangerous script tags and protocols
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'vbscript:', '', sanitized, flags=re.IGNORECASE)
        
        # Normalize case if requested
        if not preserve_case:
            sanitized = sanitized.lower()
        
        return sanitized.strip()


# Singleton instance for global use
security_validator = SecurityValidator()


def validate_rule_input(message: str = "", content: str = "", comment: str = "") -> bool:
    """Convenience function to validate all rule input fields
    
    Args:
        message: Rule message (optional)
        content: Rule content (optional) 
        comment: Comment text (optional)
        
    Returns:
        bool: True if all inputs are safe
        
    Raises:
        ValueError: If any input is unsafe
    """
    if message:
        security_validator.validate_rule_message(message)
    
    if content:
        security_validator.validate_rule_content(content)
    
    if comment:
        security_validator.validate_comment_text(comment)
    
    return True


def validate_domain_import(domains: list, domain_count_limit: int = None) -> bool:
    """Convenience function to validate domain import operations
    
    Args:
        domains: List of domain names to validate
        domain_count_limit: Maximum number of domains allowed (optional)
        
    Returns:
        bool: True if all domains are safe and within limits
        
    Raises:
        ValueError: If domains are unsafe or exceed limits
    """
    # Check import limits
    if domain_count_limit:
        security_validator.validate_import_limits(
            len(domains), domain_count_limit, "domains"
        )
    
    # Validate each domain
    for domain in domains:
        security_validator.validate_domain_name(domain.strip())
    
    return True


def validate_file_operation(filepath: str, operation: str = "read") -> bool:
    """Convenience function to validate file operations
    
    Args:
        filepath: Path to file
        operation: Type of operation ("read", "write", "import")
        
    Returns:
        bool: True if file operation is safe
        
    Raises:
        ValueError: If file operation is unsafe
        FileNotFoundError: If file doesn't exist (for read operations)
        PermissionError: If file cannot be accessed
    """
    # Validate filename safety
    security_validator.validate_filename(filepath)
    
    # Validate file size based on operation type
    if operation == "read" and os.path.exists(filepath):
        security_validator.validate_file_size(filepath, SuricataConstants.MAX_RULE_FILE_SIZE)
    elif operation == "import" and os.path.exists(filepath):
        security_validator.validate_file_size(filepath, SecurityConstants.MAX_IMPORT_FILE_SIZE)
    
    return True
