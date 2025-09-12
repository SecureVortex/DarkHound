"""
Security utilities for DarkHound - secure logging, input validation, and sanitization
"""
import logging
import re
import os
import sys
from typing import Any, Dict, Union


class SecureLogger:
    """Secure logging that redacts sensitive information"""
    
    SENSITIVE_PATTERNS = [
        # Email patterns
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
        # Password-like strings
        (r'(?i)(password|pwd|pass)["\s]*[:=]["\s]*[^\s"]+', r'\1:[REDACTED]'),
        # API keys (common patterns)
        (r'\b[A-Za-z0-9]{32,}\b', '[API_KEY_REDACTED]'),
        # Credit card numbers
        (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CC_REDACTED]'),
        # Social security numbers
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]'),
    ]
    
    def __init__(self, name: str = "darkhound", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Configure secure logging format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler if LOG_FILE environment variable is set
        log_file = os.getenv('DARKHOUND_LOG_FILE')
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def _sanitize_message(self, message: str) -> str:
        """Remove sensitive information from log messages"""
        sanitized = str(message)
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized)
        return sanitized
    
    def info(self, message: str):
        self.logger.info(self._sanitize_message(message))
    
    def warning(self, message: str):
        self.logger.warning(self._sanitize_message(message))
    
    def error(self, message: str):
        self.logger.error(self._sanitize_message(message))
    
    def debug(self, message: str):
        self.logger.debug(self._sanitize_message(message))


class InputValidator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format and scheme"""
        if not isinstance(url, str) or not url:
            return False
        
        # Allow http, https, and onion URLs
        allowed_schemes = ['http://', 'https://']
        if not any(url.startswith(scheme) for scheme in allowed_schemes):
            return False
        
        # Basic URL format validation
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(url_pattern, url))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not isinstance(email, str) or not email:
            return False
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    @staticmethod
    def sanitize_html_content(content: str, max_length: int = 10000) -> str:
        """Basic HTML content sanitization"""
        if not isinstance(content, str):
            return ""
        
        # Truncate to prevent memory issues
        content = content[:max_length]
        
        # Remove script tags and their content
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove other potentially dangerous tags
        dangerous_tags = ['iframe', 'object', 'embed', 'form', 'input']
        for tag in dangerous_tags:
            content = re.sub(f'<{tag}[^>]*>.*?</{tag}>', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        return content
    
    @staticmethod
    def validate_config_structure(config: Dict[str, Any]) -> bool:
        """Validate configuration structure"""
        if not isinstance(config, dict):
            return False
        
        # Required top-level keys
        required_keys = ['dark_web_sources', 'alerting', 'database']
        return all(key in config for key in required_keys)


def get_env_or_config(env_key: str, config_value: str, default: str = "") -> str:
    """Get value from environment variable first, then config, then default"""
    return os.getenv(env_key, config_value or default)


def secure_exit(logger: SecureLogger, exit_code: int = 0):
    """Perform secure cleanup and exit"""
    logger.info(f"DarkHound shutting down with code {exit_code}")
    # Add any cleanup operations here
    sys.exit(exit_code)