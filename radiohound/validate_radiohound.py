#!/usr/bin/env python3

#################
#
# NOTE: This script is obviated by the RadioHound schema repo validation script.
# Prefer that script instead.
#
#################

import argparse
import json
import logging
from datetime import datetime
from difflib import unified_diff
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from zoneinfo import ZoneInfo

import requests
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

SCHEMA_URL = "https://json.schemastore.org/radiohound-v0.json"


def fetch_schema() -> Dict[str, Any]:
    """
    Fetch the RadioHound JSON schema from the schema store.

    Returns:
        Dict[str, Any]: The RadioHound JSON schema

    Raises:
        requests.RequestException: If the schema cannot be fetched
        json.JSONDecodeError: If the schema is not valid JSON
    """
    try:
        response = requests.get(SCHEMA_URL, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch schema from {SCHEMA_URL}: {e}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON schema at {SCHEMA_URL}: {e}")


def load_json_file(file_path: Path) -> Dict[str, Any]:
    """
    Load a JSON file and return its contents.

    Args:
        file_path: Path to the JSON file

    Returns:
        Dict[str, Any]: The contents of the JSON file

    Raises:
        json.JSONDecodeError: If the file is not valid JSON
        OSError: If the file cannot be read
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in file {file_path}: {e}")
    except OSError as e:
        raise OSError(f"Failed to read file {file_path}: {e}")


def fix_radiohound_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fix common validation issues in RadioHound data.

    Args:
        data: Original RadioHound data dictionary

    Returns:
        Dict[str, Any]: Fixed RadioHound data
    """
    # Create a copy to avoid modifying the original
    fixed = data.copy()

    # Remove non-standard and deprecated fields
    fixed.pop("_id", None)
    fixed.pop("beaglelogic_kernel_driver", None)
    fixed.pop("batch", None)  # Deprecated field

    # Add required gain if missing
    if "gain" not in fixed:
        fixed["gain"] = fixed.get("requested", {}).get("gain", 0)

    # Add required version if missing
    if "version" not in fixed:
        fixed["version"] = "v0"

    # Convert float values to integers where required
    if "sample_rate" in fixed:
        fixed["sample_rate"] = int(fixed["sample_rate"])

    # Fix metadata
    if "metadata" in fixed:
        metadata = fixed["metadata"].copy()
        # Remove deprecated and invalid fields
        metadata.pop("archiveResult", None)
        metadata.pop("xstop", None)
        metadata.pop("xstart", None)  # Deprecated field
        metadata.pop("xcount", None)  # Deprecated field
        # Convert metadata fields to integers
        if "fmin" in metadata:
            metadata["fmin"] = int(metadata["fmin"])
        if "fmax" in metadata:
            metadata["fmax"] = int(metadata["fmax"])
        fixed["metadata"] = metadata

    # Fix requested fields
    if "requested" in fixed:
        requested = fixed["requested"].copy()
        if "fmin" in requested:
            requested["fmin"] = int(requested["fmin"])
        if "fmax" in requested:
            requested["fmax"] = int(requested["fmax"])
        if "span" in requested:
            requested["span"] = int(requested["span"])
        fixed["requested"] = requested

    # Fix timestamp format and set Eastern timezone
    if "timestamp" in fixed:
        try:
            # Parse the timestamp (it's already in Eastern time)
            dt = datetime.strptime(fixed["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
            # Set Eastern timezone without shifting the time
            dt = dt.replace(tzinfo=ZoneInfo("America/New_York"))
            # Convert to RFC3339 format
            fixed["timestamp"] = dt.isoformat()
        except ValueError:
            # If the timestamp is already in RFC3339 format, leave it alone
            try:
                dt = datetime.fromisoformat(fixed["timestamp"])
            except ValueError as e:
                logger.error(f"Could not parse timestamp '{fixed['timestamp']}': {e}")

    return fixed


def show_changes(
    original: Dict[str, Any], fixed: Dict[str, Any], file_path: Path
) -> bool:
    """
    Show changes between original and fixed data and ask for confirmation.

    Args:
        original: Original data dictionary
        fixed: Fixed data dictionary
        file_path: Path to the file being modified

    Returns:
        bool: True if changes should be applied, False otherwise
    """
    original_json = json.dumps(original, indent=2)
    fixed_json = json.dumps(fixed, indent=2)

    if original_json == fixed_json:
        print(f"\nNo changes needed for {file_path}")
        return False

    print(f"\nProposed changes for {file_path}:")
    print("=" * 40)

    # Show unified diff
    diff = unified_diff(
        original_json.splitlines(keepends=True),
        fixed_json.splitlines(keepends=True),
        fromfile="Original",
        tofile="Fixed",
    )
    print("".join(diff))

    while True:
        response = input("\nApply these changes? [y/n]: ").lower().strip()
        if response in ("y", "n"):
            return response == "y"
        print("Please answer 'y' or 'n'")


def save_fixed_data(file_path: Path, data: Dict[str, Any]) -> None:
    """
    Save the fixed data back to the file.

    Args:
        file_path: Path to save the file to
        data: Data to save
    """
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)
    logger.info(f"Saved changes to {file_path}")


def validate_file(
    file_path: Path,
    validator: Draft7Validator,
    interactive: bool = False,
    fix: bool = False,
) -> Tuple[List[str], bool]:
    """
    Validate a single RadioHound JSON file against the schema.

    Args:
        file_path: Path to the RadioHound JSON file
        validator: JSON schema validator instance
        interactive: Whether to run in interactive mode
        fix: Whether to allow file modifications

    Returns:
        Tuple[List[str], bool]: List of validation error messages and whether fixes were needed
    """
    try:
        data = load_json_file(file_path)
        errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
        error_list = [
            f"{' -> '.join(str(p) for p in error.path)}: {error.message}"
            for error in errors
        ]
        if errors:
            logger.info(f"Errors found in {file_path}:")
            logger.info("\n".join(error_list))
        else:
            logger.info(f"No errors found in {file_path}")

        fixed_data = fix_radiohound_data(data)
        needs_fixes = json.dumps(data) != json.dumps(fixed_data)

        if interactive and needs_fixes:
            if show_changes(data, fixed_data, file_path):
                save_fixed_data(file_path, fixed_data)
                errors = sorted(validator.iter_errors(fixed_data), key=lambda e: e.path)
                error_list = [
                    f"{' -> '.join(str(p) for p in error.path)}: {error.message}"
                    for error in errors
                ]
        elif fix and needs_fixes:
            logger.info(f"Fixing {file_path}")
            save_fixed_data(file_path, fixed_data)
            errors = sorted(validator.iter_errors(fixed_data), key=lambda e: e.path)
            error_list = [
                f"{' -> '.join(str(p) for p in error.path)}: {error.message}"
                for error in errors
            ]

        return error_list, needs_fixes
    except (ValueError, OSError) as e:
        return [str(e)], True


def validate_directory(
    directory: Path,
    validator: Draft7Validator,
    interactive: bool = False,
    fix: bool = False,
) -> List[Tuple[Path, List[str], bool]]:
    """
    Validate all .rh.json files in a directory against the RadioHound schema.

    Args:
        directory: Directory containing RadioHound files
        validator: JSON schema validator instance
        interactive: Whether to run in interactive mode
        fix: Whether to allow file modifications

    Returns:
        List[Tuple[Path, List[str], bool]]: List of (file_path, error_messages, needs_fixes) tuples
    """
    results = []
    for file_path in directory.glob("*.rh.json"):
        logger.info(f"Validating {file_path}")
        errors, needs_fixes = validate_file(file_path, validator, interactive, fix)
        results.append((file_path, errors, needs_fixes))
    return results


def main() -> None:
    """
    Main entry point for the RadioHound JSON validation script.
    """
    parser = argparse.ArgumentParser(
        description="Validate RadioHound JSON files against schema"
    )
    parser.add_argument(
        "directory", type=Path, help="Directory containing RadioHound .rh.json files"
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Show and confirm changes before applying",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Allow modifying files to fix validation issues",
    )
    args = parser.parse_args()

    if not args.directory.is_dir():
        logger.error(f"Directory does not exist: {args.directory}")
        return

    try:
        # Fetch and validate schema
        schema = fetch_schema()
        validator = Draft7Validator(schema)
    except (RuntimeError, SchemaError) as e:
        logger.error(f"Schema error: {e}")
        return

    # Validate all files
    results = validate_directory(args.directory, validator, args.interactive, args.fix)

    # Calculate statistics
    total_count = len(results)
    valid_count = sum(
        1 for _, errors, needs_fixes in results if not errors and not needs_fixes
    )
    invalid_count = total_count - valid_count

    # Count files with schema errors and those needing fixes
    schema_error_count = sum(1 for _, errors, _ in results if errors)
    needs_fixes_count = sum(1 for _, _, needs_fixes in results if needs_fixes)

    # Count files that were actually fixed
    fixed_count = sum(
        1
        for _, errors, needs_fixes in results
        if needs_fixes and (args.fix or (args.interactive and show_changes))
    )

    print("\nValidation Results:")
    print("==================")

    for file_path, errors, needs_fixes in results:
        if errors or needs_fixes:
            print(f"\nFile: {file_path}")
            if needs_fixes:
                print("Status: Requires fixes to comply with schema")
            if errors:
                print("Errors:")
                for error in errors:
                    print(f"  - {error}")
        else:
            print(f"✓ {file_path} is valid")

    print("\nSummary:")
    print(f"Total files processed: {total_count}")
    print(f"Valid files: {valid_count}")
    print(f"Invalid files: {invalid_count}")
    if invalid_count > 0:
        print(f"  - Files with JSON schema errors: {schema_error_count}")
        print(f"  - Files needing other fixes: {needs_fixes_count}")
        if args.fix or args.interactive:
            print(f"  - Files fixed: {fixed_count}")


if __name__ == "__main__":
    main()
