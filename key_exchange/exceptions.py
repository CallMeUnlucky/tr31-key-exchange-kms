"""
Custom exception classes for key exchange operations.

Follows industrial-grade practices for error handling:
- SecurityError: Raised when cryptographic security checks fail
- ValidationError: Raised when input validation fails
- IntegrityError: Raised when data integrity checks fail
"""


class KeyExchangeException(Exception):
    """Base exception for all key exchange operations."""

    pass


class SecurityError(KeyExchangeException):
    """
    Raised when a security check fails.

    Examples:
    - KCV validation failure
    - HMAC/MAC integrity check failure
    - Unauthorized key operation
    """

    pass


class ValidationError(KeyExchangeException):
    """
    Raised when validation of input parameters fails.

    Examples:
    - Invalid hexadecimal format
    - Incorrect component length
    - Missing or malformed arguments
    """

    pass


class IntegrityError(KeyExchangeException):
    """
    Raised when data integrity verification fails.

    Examples:
    - TR-31 keyblock integrity check failure
    - KCV mismatch after decryption
    """

    pass
