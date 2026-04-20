"""
Core cryptographic logic for key exchange operations.
"""
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend


class SecurityError(Exception):
    """Raised when a security check fails."""
    pass


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


def recombine_kek(component_1: str, component_2: str) -> bytes:
    """
    Recombine two hex-encoded KEK components using XOR operation.

    Args:
        component_1: First KEK component as hex string
        component_2: Second KEK component as hex string

    Returns:
        Combined KEK as 32 bytes (AES-256 key)

    Raises:
        ValidationError: If components have different lengths or invalid hex
        ValueError: If resulting key is not 32 bytes
    """
    if not component_1 or not component_2:
        raise ValidationError("KEK components cannot be empty")

    if len(component_1) != len(component_2):
        raise ValidationError(
            f"KEK components must have the same length. "
            f"Got {len(component_1)} and {len(component_2)} characters"
        )

    try:
        bytes_1 = bytes.fromhex(component_1)
        bytes_2 = bytes.fromhex(component_2)
    except ValueError as e:
        raise ValidationError(f"Invalid hexadecimal format in KEK components: {str(e)}")

    if len(bytes_1) != len(bytes_2):
        raise ValidationError("KEK components must decode to the same byte length")

    kek = bytes(b1 ^ b2 for b1, b2 in zip(bytes_1, bytes_2))

    if len(kek) != 32:
        raise ValueError(f"Resulting KEK must be 32 bytes (AES-256), got {len(kek)} bytes")

    return kek


def validate_kck_kcv(kek: bytes, expected_kcv: str) -> None:
    """
    Validate KCV (Key Check Value) using AES-CMAC.

    Generates a zero block (16 bytes), computes its CMAC with the provided KEK,
    and validates it matches the expected KCV. The KCV is the first 3 bytes
    of the CMAC result as uppercase hex.

    Args:
        kek: The KEK (Key Encryption Key) as bytes
        expected_kcv: Expected KCV as hex string (6 characters)

    Raises:
        ValidationError: If KCV format is invalid
        SecurityError: If computed KCV does not match expected KCV
    """
    if not isinstance(kek, bytes):
        raise ValidationError("KEK must be bytes")

    if len(kek) != 32:
        raise ValidationError(f"KEK must be 32 bytes, got {len(kek)}")

    if not expected_kcv or not isinstance(expected_kcv, str):
        raise ValidationError("Expected KCV must be a non-empty string")

    if len(expected_kcv) != 6:
        raise ValidationError(f"Expected KCV must be 6 hex characters, got {len(expected_kcv)}")

    try:
        expected_kcv_bytes = bytes.fromhex(expected_kcv)
    except ValueError:
        raise ValidationError(f"Invalid hexadecimal format in expected KCV")

    zero_block = b'\x00' * 16

    c = cmac.CMAC(algorithms.AES(kek), backend=default_backend())
    c.update(zero_block)
    cmac_result = c.finalize()

    computed_kcv = cmac_result[:3]
    computed_kcv_hex = computed_kcv.hex().upper()

    if computed_kcv_hex != expected_kcv.upper():
        raise SecurityError("KCV validation failed: computed KCV does not match expected KCV")


class KeyExchange:
    """Handle cryptographic key exchange operations."""

    @staticmethod
    def recombine_kek(component_1: str, component_2: str) -> bytes:
        """
        Recombine two hex-encoded KEK components using XOR operation.

        Args:
            component_1: First KEK component as hex string
            component_2: Second KEK component as hex string

        Returns:
            Combined KEK as 32 bytes (AES-256 key)

        Raises:
            ValidationError: If components have different lengths or invalid hex
        """
        return recombine_kek(component_1, component_2)

    @staticmethod
    def validate_kck_kcv(kek: bytes, expected_kcv: str) -> None:
        """
        Validate KCV (Key Check Value) using AES-CMAC.

        Args:
            kek: The KEK (Key Encryption Key) as bytes
            expected_kcv: Expected KCV as hex string (6 characters)

        Raises:
            SecurityError: If KCV validation fails
            ValidationError: If parameters are invalid
        """
        validate_kck_kcv(kek, expected_kcv)
