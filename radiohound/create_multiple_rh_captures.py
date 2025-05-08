import argparse
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from spectrumx.client import Client
from spectrumx.errors import NetworkError
from spectrumx.errors import SDSError
from spectrumx.errors import ServiceError
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


def update_scan_group(file_path: Path, rh_data: dict) -> bool:
    """
    Update the scan_group in the RadioHound data if needed.

    Args:
        file_path: Path to the RadioHound file
        rh_data: RadioHound data dictionary

    Returns:
        bool: True if update was successful, False otherwise
    """
    if "scan_group" not in rh_data or not is_valid_uuid(rh_data["scan_group"]):
        scan_group = str(uuid.uuid4())
        rh_data["scan_group"] = scan_group
        logger.info(
            f"Generated new scan_group UUID '{scan_group}' for file {file_path}"
        )

        try:
            with open(file_path, "w") as f:
                json.dump(rh_data, f, indent=2)
            logger.info(f"Updated {file_path} with new scan_group UUID")
            return True
        except Exception as e:
            logger.error(f"Failed to write updated scan_group to {file_path}: {e}")
            return False

    logger.info(
        f"Using existing scan_group UUID '{rh_data['scan_group']}' from file {file_path}"
    )
    return True


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

        # if not upload_results:
        #     logger.error(f"No upload results returned for {file_path}")
        #     return False

        # failures = [result for result in upload_results if not result]
        # if failures:
        #     logger.error(f"Upload failed for {file_path}: {failures}")
        #     return False

        # # Get the uploaded file
        # uploaded_files = [result() for result in upload_results if result]
        # if not uploaded_files:
        #     logger.error(f"No files were uploaded for {file_path}")
        #     return False

        # # Verify file is listed in the directory
        # files_listed = sds_client.list_files(sds_path=sds_dir)
        # listed_uuids = {str(file.uuid) for file in files_listed if file.uuid}
        # uploaded_uuids = {str(file.uuid) for file in uploaded_files if file.uuid}

        # if not uploaded_uuids.issubset(listed_uuids):
        #     logger.error(
        #         f"Uploaded file not found in directory listing: {uploaded_uuids - listed_uuids}"
        #     )
        #     return False

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


def rename_files(directory: Path) -> list[Path]:
    """
    Rename all .json files in the directory to have .rh.json extension.

    Args:
        directory: Directory containing files to rename

    Returns:
        list[Path]: List of renamed file paths
    """
    renamed_files = []
    for file_path in directory.glob("*.json"):
        if not file_path.name.endswith(".rh.json"):
            new_path = file_path.with_name(f"{file_path.stem}.rh.json")
            try:
                file_path.rename(new_path)
                logger.info(f"Renamed {file_path} to {new_path}")
                renamed_files.append(new_path)
            except Exception as e:
                logger.error(f"Failed to rename {file_path}: {e}")
                continue
        else:
            renamed_files.append(file_path)

    return renamed_files


def process_directory(
    sds_client: Client,
    directory: Path,
    skip_upload: bool = False,
) -> None:
    """
    Process all RadioHound files in the given directory.

    Args:
        sds_client: Authenticated SDS client
        directory: Directory containing RadioHound files
        skip_upload: If True, skip file uploads and only create captures
    """
    # First rename all files to have .rh.json extension
    files_to_process = rename_files(directory)
    if not files_to_process:
        logger.warning(f"No .json files found in {directory}")
        return

    sds_dir = "/radiohound_0"

    # Process each file
    for file_path in files_to_process:
        try:
            logger.info(f"Processing file: {file_path}")

            # Load and validate the file
            rh_data = load_radiohound_file(file_path)
            if not update_scan_group(file_path, rh_data):
                continue

            if not skip_upload:
                # Upload the file
                if not upload_file(sds_client, file_path, sds_dir):
                    logger.error(
                        f"Failed to upload {file_path}, skipping capture creation"
                    )
                    continue
            else:
                logger.info(
                    f"Skipping upload for {file_path} as --skip-upload flag was provided"
                )

            # Create the capture
            create_capture(sds_client, sds_dir, rh_data["scan_group"])

        except Exception:
            logger.exception(f"Error processing {file_path}")


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Create SDS captures from RadioHound files"
    )
    parser.add_argument(
        "directory", type=Path, help="Directory containing RadioHound files"
    )
    parser.add_argument(
        "--host", default="sds.crc.nd.edu", help="SDS host (default: sds.crc.nd.edu)"
    )
    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Skip uploading files and only create captures.",
    )

    args = parser.parse_args()

    # Validate directory
    if not args.directory.is_dir():
        raise ValueError(f"Directory does not exist: {args.directory}")

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
    process_directory(sds, args.directory, args.skip_upload)


if __name__ == "__main__":
    main()
