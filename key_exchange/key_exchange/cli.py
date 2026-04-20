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

    return 0
