"""
Core cryptographic logic for key exchange operations.
"""
import os
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.backends import default_backend

try:
    from psec import tr31 as tr31_module
except ImportError:
    tr31_module = None

try:
    import dukpt as dukpt_lib
except ImportError:
    dukpt_lib = None


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


def compute_kcv(key: bytes) -> str:
    """
    Compute KCV (Key Check Value) using AES-CMAC.

    Computes the CMAC of a 16-byte zero block and returns the first 3 bytes
    as uppercase hexadecimal.

    Args:
        key: The key (any AES key size in bytes)

    Returns:
        KCV as 6-character uppercase hex string

    Raises:
        ValidationError: If key is invalid
    """
    if not isinstance(key, bytes):
        raise ValidationError("Key must be bytes")

    if len(key) not in (16, 24, 32):
        raise ValidationError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")

    zero_block = b'\x00' * 16
    c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(zero_block)
    cmac_result = c.finalize()

    return cmac_result[:3].hex().upper()


def unwrap_bdk(tr31_block: str, kek: bytes) -> bytes:
    """
    Unwrap BDK (Base Derivation Key) from TR-31 keyblock.

    Uses the psec library to parse and unwrap the TR-31 keyblock using the
    provided KEK. The tr31_block parameter must be a hex string.

    Args:
        tr31_block: TR-31 keyblock as hex string (not converted to bytes)
        kek: Key Encryption Key (32 bytes) to unwrap the BDK

    Returns:
        Unwrapped BDK as bytes

    Raises:
        ValidationError: If TR-31 format is invalid or KEK is invalid
        SecurityError: If unwrapping fails (integrity check, etc.)
    """
    if not tr31_module:
        raise SecurityError("psec library not available. Install: pip install psec")

    if not isinstance(kek, bytes):
        raise ValidationError("KEK must be bytes")

    if len(kek) != 32:
        raise ValidationError(f"KEK must be 32 bytes, got {len(kek)}")

    if not tr31_block or not isinstance(tr31_block, str):
        raise ValidationError("TR-31 block must be a non-empty string")

    try:
        header, bdk_bytes = tr31_module.unwrap(kek, tr31_block)
        return bdk_bytes
    except Exception as e:
        error_msg = str(e).lower()
        if "mac" in error_msg or "integrity" in error_msg or "auth" in error_msg:
            raise SecurityError(f"TR-31 unwrap failed: integrity check or authentication failed")
        elif "format" in error_msg or "parse" in error_msg or "invalid" in error_msg:
            raise ValidationError(f"TR-31 unwrap failed: invalid TR-31 format or structure")
        else:
            raise SecurityError(f"TR-31 unwrap failed: {str(e)}")


def derive_dukpt_key_and_decrypt(
    bdk: bytes,
    ksn: str,
    ciphertext_3des: bytes,
) -> bytes:
    """
    Derive DUKPT working key and decrypt 3DES ECB ciphertext.

    Uses the DUKPT algorithm to derive a working key from the BDK and KSN,
    then decrypts the provided 3DES ECB ciphertext.

    Args:
        bdk: Base Derivation Key as bytes (8 or 16 bytes)
        ksn: Key Serial Number as hex string (10 bytes = 20 hex chars)
        ciphertext_3des: 3DES ECB encrypted data as bytes

    Returns:
        Decrypted plaintext as bytes

    Raises:
        ValidationError: If inputs are invalid
        SecurityError: If DUKPT derivation or decryption fails
    """
    if not dukpt_lib:
        raise SecurityError("dukpt library not available. Install: pip install dukpt")

    if not isinstance(bdk, bytes):
        raise ValidationError("BDK must be bytes")

    if len(bdk) not in (8, 16):
        raise ValidationError(f"BDK must be 8 or 16 bytes, got {len(bdk)}")

    if not ksn or not isinstance(ksn, str):
        raise ValidationError("KSN must be a non-empty string")

    if len(ksn) != 20:
        raise ValidationError(f"KSN must be 20 hex characters (10 bytes), got {len(ksn)}")

    try:
        ksn_bytes = bytes.fromhex(ksn)
    except ValueError as e:
        raise ValidationError(f"Invalid hexadecimal format in KSN: {str(e)}")

    if not isinstance(ciphertext_3des, bytes):
        raise ValidationError("Ciphertext must be bytes")

    if len(ciphertext_3des) == 0:
        raise ValidationError("Ciphertext cannot be empty")

    if len(ciphertext_3des) % 8 != 0:
        raise ValidationError(
            f"3DES ciphertext must be multiple of 8 bytes, got {len(ciphertext_3des)}"
        )

    try:
        working_key = dukpt_lib.derive(bdk, ksn_bytes)

        cipher = Cipher(
            algorithms.TripleDES(working_key),
            modes.ECB(),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext_3des) + decryptor.finalize()

        return plaintext
    except Exception as e:
        error_msg = str(e).lower()
        if "key" in error_msg or "invalid" in error_msg:
            raise ValidationError(f"DUKPT derivation failed: invalid key or KSN format")
        else:
            raise SecurityError(f"DUKPT decryption failed: {str(e)}")


def generate_and_export_pek(kek: bytes) -> tuple:
    """
    Generate a secure PEK and wrap it in a TR-31 keyblock.

    Generates a random 16-byte PIN Encryption Key, wraps it using the provided
    KEK in a TR-31 keyblock with proper PIN key headers, and computes the KCV.

    Args:
        kek: Key Encryption Key (32 bytes) to wrap the PEK

    Returns:
        Tuple of (tr31_keyblock_str: str, pek_kcv: str)
        where tr31_keyblock_str is the hex-encoded TR-31 keyblock

    Raises:
        ValidationError: If KEK is invalid
        SecurityError: If TR-31 wrapping or KCV computation fails
    """
    if not isinstance(kek, bytes):
        raise ValidationError("KEK must be bytes")

    if len(kek) != 32:
        raise ValidationError(f"KEK must be 32 bytes, got {len(kek)}")

    if not tr31_module:
        raise SecurityError("psec library not available. Install: pip install psec")

    try:
        pek = os.urandom(16)
        pek_kcv = compute_kcv(pek)

        try:
            # 1. Creamos el objeto Header con las especificaciones
            header = tr31_module.Header(
                version_id="D",
                key_usage="PE",
                algorithm="T",
                mode_of_use="E",
                exportability="N",
            )
            
            # 2. Envolvemos pasando la KEK, el Header y la PEK en ese orden exacto
            tr31_keyblock_str = tr31_module.wrap(kek, header, pek)
            
            return tr31_keyblock_str, pek_kcv

        except Exception as e:
            error_msg = str(e).lower()
            if "key" in error_msg or "format" in error_msg:
                raise ValidationError(f"TR-31 keyblock generation failed: {str(e)}")
            else:
                raise SecurityError(f"TR-31 keyblock encryption failed: {str(e)}")

    except SecurityError:
        raise
    except ValidationError:
        raise
    except Exception as e:
        raise SecurityError(f"PEK generation and export failed: {str(e)}")


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

    @staticmethod
    def compute_kcv(key: bytes) -> str:
        """
        Compute KCV (Key Check Value) using AES-CMAC.

        Args:
            key: The key (any AES key size in bytes)

        Returns:
            KCV as 6-character uppercase hex string
        """
        return compute_kcv(key)

    @staticmethod
    def unwrap_bdk(tr31_block: str, kek: bytes) -> bytes:
        """
        Unwrap BDK (Base Derivation Key) from TR-31 keyblock.

        Args:
            tr31_block: TR-31 keyblock as hex string
            kek: Key Encryption Key (32 bytes) to unwrap the BDK

        Returns:
            Unwrapped BDK as bytes

        Raises:
            ValidationError: If TR-31 format is invalid or KEK is invalid
            SecurityError: If unwrapping fails
        """
        return unwrap_bdk(tr31_block, kek)

    @staticmethod
    def derive_dukpt_key_and_decrypt(
        bdk: bytes,
        ksn: str,
        ciphertext_3des: bytes,
    ) -> bytes:
        """
        Derive DUKPT working key and decrypt 3DES ECB ciphertext.

        Args:
            bdk: Base Derivation Key as bytes (8 or 16 bytes)
            ksn: Key Serial Number as hex string (10 bytes = 20 hex chars)
            ciphertext_3des: 3DES ECB encrypted data as bytes

        Returns:
            Decrypted plaintext as bytes

        Raises:
            ValidationError: If inputs are invalid
            SecurityError: If DUKPT derivation or decryption fails
        """
        return derive_dukpt_key_and_decrypt(bdk, ksn, ciphertext_3des)

    @staticmethod
    def generate_and_export_pek(kek: bytes) -> tuple:
        """
        Generate a secure PEK and wrap it in a TR-31 keyblock.

        Args:
            kek: Key Encryption Key (32 bytes) to wrap the PEK

        Returns:
            Tuple of (tr31_keyblock_hex: str, pek_kcv: str)

        Raises:
            ValidationError: If KEK is invalid
            SecurityError: If TR-31 wrapping or KCV computation fails
        """
        return generate_and_export_pek(kek)
