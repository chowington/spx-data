import argparse
import json
import logging
import uuid
from pathlib import Path
from typing import Any, List

from spectrumx.client import Client
from spectrumx.errors import NetworkError, SDSError, ServiceError
from spectrumx.models.captures import CaptureType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def is_valid_uuid(val: str) -> bool:
    """
    Check if a string is a valid UUID.

    Args:
        val: String to validate

    Returns:
        bool: True if string is a valid UUID, False otherwise
    """
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def load_radiohound_file(file_path: Path) -> dict[str, Any]:
    """
    Load and validate a RadioHound JSON file.

    Args:
        file_path: Path to the RadioHound JSON file

    Returns:
        Dict containing the RadioHound data

    Raises:
        ValueError: If the file cannot be read or parsed
    """
    try:
        with open(file_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format in {file_path}: {e}")
    except Exception as e:
        raise ValueError(f"Error reading file {file_path}: {e}")


def update_scan_group(file_path: Path, rh_data: dict, scan_group: str) -> bool:
    """
    Update the scan_group in the RadioHound data.

    Args:
        file_path: Path to the RadioHound file
        rh_data: RadioHound data dictionary
        scan_group: UUID to set as scan_group

    Returns:
        bool: True if update was successful, False otherwise
    """
    rh_data["scan_group"] = scan_group
    logger.info(f"Setting scan_group UUID '{scan_group}' for file {file_path}")

    try:
        with open(file_path, "w") as f:
            json.dump(rh_data, f, indent=2)
        logger.info(f"Updated {file_path} with scan_group UUID")
        return True
    except Exception as e:
        logger.error(f"Failed to write updated scan_group to {file_path}: {e}")
        return False


def upload_file(sds_client: Client, file_path: Path, sds_dir: str) -> bool:
    """
    Upload a single file to SDS.

    Args:
        sds_client: Authenticated SDS client
        file_path: Path to the file to upload
        sds_dir: SDS directory to upload to

    Returns:
        bool: True if upload was successful, False otherwise
    """
    try:
        # Upload the file using absolute path
        abs_path = file_path.resolve()
        logger.info(f"Uploading file {abs_path} to SDS")
        sds_client.upload_file(
            local_file=abs_path,
            sds_path=sds_dir,
        )
        logger.info(f"Finished upload of {file_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload file to SDS: {e}")
        return False


def create_capture(sds_client: Client, sds_dir: str, scan_group: str) -> bool:
    """
    Create a capture in the SDS.

    Args:
        sds_client: Authenticated SDS client
        sds_dir: SDS directory containing the file
        scan_group: Scan group UUID

    Returns:
        bool: True if capture was created successfully, False otherwise
    """
    try:
        logger.info(f"Creating capture at {sds_dir} with scan_group {scan_group}")
        capture = sds_client.captures.create(
            top_level_dir=sds_dir,
            scan_group=scan_group,
            capture_type=CaptureType.RadioHound,
        )
        logger.info(f"Created capture with UUID {capture.uuid}")
        return True
    except (NetworkError, ServiceError, SDSError) as e:
        logger.error(
            f"Error creating capture at {sds_dir} with scan_group {scan_group}: {e}"
        )
        return False


def get_radiohound_files(directory: Path) -> List[Path]:
    """
    Get all RadioHound files in the directory.

    Args:
        directory: Directory to search for RadioHound files

    Returns:
        List of RadioHound file paths
    """
    # Get all .json files
    json_files = list(directory.glob("*.json"))

    # Filter for RadioHound files (either .rh.json or files containing RadioHound data)
    rh_files = []
    for file_path in json_files:
        try:
            data = load_radiohound_file(file_path)
            # Check if it's a RadioHound file by looking for common fields
            if any(key in data for key in ["scan_group", "radiohound_version"]):
                rh_files.append(file_path)
        except Exception:
            continue

    return rh_files


def get_scan_group_from_files(files: List[Path]) -> str | None:
    """
    Check if all files have the same scan group.

    Args:
        files: List of RadioHound file paths

    Returns:
        str | None: The common scan group if all files have the same one, None otherwise
    """
    scan_groups = set()

    for file_path in files:
        try:
            data = load_radiohound_file(file_path)
            scan_group = data.get("scan_group")
            if scan_group:
                scan_groups.add(scan_group)
        except Exception:
            continue

    return next(iter(scan_groups)) if len(scan_groups) == 1 else None


def process_directory(
    sds_client: Client,
    directory: Path,
    scan_group: str | None = None,
    force_new_scan_group: bool = False,
    skip_upload: bool = False,
) -> None:
    """
    Process all RadioHound files in the directory and create a single SDS capture.

    Args:
        sds_client: Authenticated SDS client
        directory: Directory containing RadioHound files
        scan_group: Optional scan group UUID to use. If None, will check if all files have the same scan group.
        force_new_scan_group: If True, generate a new scan group even if files share the same one.
        skip_upload: If True, skip file uploads and only create the capture.
    """
    # Get all RadioHound files in the directory
    files = get_radiohound_files(directory)
    if not files:
        logger.warning(f"No RadioHound files found in {directory}")
        return

    # Determine scan group
    if scan_group is None:
        if force_new_scan_group:
            scan_group = str(uuid.uuid4())
            logger.info(f"Force flag set, generating new scan_group UUID: {scan_group}")
        else:
            common_scan_group = get_scan_group_from_files(files)
            if common_scan_group:
                scan_group = common_scan_group
                logger.info(f"Using existing scan_group UUID from files: {scan_group}")
            else:
                scan_group = str(uuid.uuid4())
                logger.info(f"Generated new scan_group UUID: {scan_group}")
    elif force_new_scan_group:
        logger.warning(
            "Both --scan-group and --force-new-scan-group provided. Using provided scan group."
        )

    sds_dir = f"/radiohound/{scan_group}"

    if not skip_upload:
        # Process each file
        for file_path in files:
            try:
                logger.info(f"Processing file: {file_path}")

                # Load and validate the file
                rh_data = load_radiohound_file(file_path)

                # Update scan group
                if not update_scan_group(file_path, rh_data, scan_group):
                    logger.error(
                        f"Failed to update scan group for {file_path}, skipping"
                    )
                    continue

                # Upload the file
                if not upload_file(sds_client, file_path, sds_dir):
                    logger.error(
                        f"Failed to upload {file_path}, skipping capture creation"
                    )
                    continue

            except Exception:
                logger.exception(f"Error processing {file_path}")
                continue
    else:
        logger.info("Skipping file uploads as --skip-upload flag was provided")

    # Create the capture after all files are processed
    create_capture(sds_client, sds_dir, scan_group)


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Create a single SDS capture from RadioHound files in a directory"
    )
    parser.add_argument(
        "directory", type=Path, help="Directory containing RadioHound files"
    )
    parser.add_argument(
        "--host", default="sds.crc.nd.edu", help="SDS host (default: sds.crc.nd.edu)"
    )
    parser.add_argument(
        "--scan-group",
        help="Optional scan group UUID to use. If not provided, a new one will be generated.",
    )
    parser.add_argument(
        "--force-new-scan-group",
        action="store_true",
        help="Force generation of a new scan group even if files share the same one.",
    )
    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Skip uploading files and only create the capture.",
    )

    args = parser.parse_args()

    # Validate directory exists
    if not args.directory.is_dir():
        raise ValueError(f"Directory does not exist: {args.directory}")

    # Validate scan group if provided
    if args.scan_group and not is_valid_uuid(args.scan_group):
        raise ValueError(f"Invalid scan group UUID: {args.scan_group}")

    # Token
    token = ""

    # Initialize SDS client
    sds = Client(host=args.host, env_config={"SDS_SECRET_TOKEN": token})

    # Enable actual changes (not dry run)
    sds.dry_run = False

    # Authenticate
    try:
        sds.authenticate()
    except Exception as e:
        raise RuntimeError(f"Failed to authenticate with SDS: {e}")

    # Process the directory
    process_directory(
        sds,
        args.directory,
        args.scan_group,
        args.force_new_scan_group,
        args.skip_upload,
    )


if __name__ == "__main__":
    main()
