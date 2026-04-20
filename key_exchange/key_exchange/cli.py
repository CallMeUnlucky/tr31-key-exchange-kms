"""
Command-line interface for key exchange operations.
"""
import argparse
import sys
from typing import Optional

from key_exchange.core import (
    KeyExchange,
    recombine_kek,
    validate_kck_kcv,
    compute_kcv,
    unwrap_bdk,
    ValidationError,
    SecurityError,
)


def create_parser() -> argparse.ArgumentParser:
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        description="KMS Key Exchange Tool",
        prog="key_exchange",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    export_parser = subparsers.add_parser(
        "export-pek",
        help="Export and validate PEK (PIN Encryption Key)",
    )
    export_parser.add_argument(
        "--kek-component-1",
        required=True,
        help="First KEK component (hex string)",
        type=str,
    )
    export_parser.add_argument(
        "--kek-component-2",
        required=True,
        help="Second KEK component (hex string)",
        type=str,
    )
    export_parser.add_argument(
        "--kek-kcv",
        required=True,
        help="Expected KCV for validation (6 hex characters)",
        type=str,
    )
    export_parser.add_argument(
        "--out",
        default=None,
        help="Output file path (reserved for future use)",
        type=str,
    )

    import_parser = subparsers.add_parser(
        "import-bdk",
        help="Import and validate BDK (Base Derivation Key) from TR-31 keyblock",
    )
    import_parser.add_argument(
        "--kek-component-1",
        required=True,
        help="First KEK component (hex string)",
        type=str,
    )
    import_parser.add_argument(
        "--kek-component-2",
        required=True,
        help="Second KEK component (hex string)",
        type=str,
    )
    import_parser.add_argument(
        "--kek-kcv",
        required=True,
        help="Expected KCV for KEK validation (6 hex characters)",
        type=str,
    )
    import_parser.add_argument(
        "--bdk-keyblock",
        required=True,
        help="TR-31 keyblock containing the BDK (hex string)",
        type=str,
    )
    import_parser.add_argument(
        "--bdk-kcv",
        required=True,
        help="Expected KCV for BDK validation (6 hex characters)",
        type=str,
    )

    return parser


def handle_export_pek(
    kek_component_1: str,
    kek_component_2: str,
    kek_kcv: str,
    out: Optional[str] = None,
) -> int:
    """
    Handle the export-pek command.

    Recombines KEK components using XOR and validates the KCV.

    Args:
        kek_component_1: First KEK component (hex string)
        kek_component_2: Second KEK component (hex string)
        kek_kcv: Expected KCV for validation (hex string)
        out: Output file path (reserved for future use)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        kek = recombine_kek(kek_component_1, kek_component_2)
        validate_kck_kcv(kek, kek_kcv)

        print("SUCCESS: KEK validation passed. KCV is valid.")
        if out:
            print(f"NOTE: Output file parameter '{out}' is reserved for future use.")

        return 0

    except ValidationError as e:
        print(f"VALIDATION ERROR: {str(e)}", file=sys.stderr)
        return 1

    except SecurityError as e:
        print(f"SECURITY ERROR: {str(e)}", file=sys.stderr)
        return 1

    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {type(e).__name__}", file=sys.stderr)
        return 1


def handle_import_bdk(
    kek_component_1: str,
    kek_component_2: str,
    kek_kcv: str,
    bdk_keyblock: str,
    bdk_kcv: str,
) -> int:
    """
    Handle the import-bdk command.

    Recombines KEK components, unwraps the BDK from TR-31 keyblock,
    and validates the BDK KCV.

    Args:
        kek_component_1: First KEK component (hex string)
        kek_component_2: Second KEK component (hex string)
        kek_kcv: Expected KCV for KEK validation (hex string)
        bdk_keyblock: TR-31 keyblock containing the BDK (hex string)
        bdk_kcv: Expected KCV for BDK validation (hex string)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        kek = recombine_kek(kek_component_1, kek_component_2)
        validate_kck_kcv(kek, kek_kcv)

        bdk = unwrap_bdk(bdk_keyblock, kek)

        computed_bdk_kcv = compute_kcv(bdk)

        if computed_bdk_kcv.upper() != bdk_kcv.upper():
            raise SecurityError(
                f"BDK KCV validation failed: computed {computed_bdk_kcv} "
                f"does not match expected {bdk_kcv}"
            )

        print("SUCCESS: BDK import and validation passed.")
        print(f"BDK KCV validated: {computed_bdk_kcv}")

        return 0

    except ValidationError as e:
        print(f"VALIDATION ERROR: {str(e)}", file=sys.stderr)
        return 1

    except SecurityError as e:
        print(f"SECURITY ERROR: {str(e)}", file=sys.stderr)
        return 1

    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {type(e).__name__}", file=sys.stderr)
        return 1


def main(args: Optional[list] = None) -> int:
    """
    Main CLI entry point.

    Args:
        args: Command-line arguments (for testing). If None, uses sys.argv.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    if parsed_args.command == "export-pek":
        return handle_export_pek(
            kek_component_1=parsed_args.kek_component_1,
            kek_component_2=parsed_args.kek_component_2,
            kek_kcv=parsed_args.kek_kcv,
            out=parsed_args.out,
        )

    if parsed_args.command == "import-bdk":
        return handle_import_bdk(
            kek_component_1=parsed_args.kek_component_1,
            kek_component_2=parsed_args.kek_component_2,
            kek_kcv=parsed_args.kek_kcv,
            bdk_keyblock=parsed_args.bdk_keyblock,
            bdk_kcv=parsed_args.bdk_kcv,
        )

    return 0
