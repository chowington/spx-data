import argparse
import logging
from pathlib import Path

from spectrumx.client import Client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def upload_drf_dir(sds_client: Client, directory: Path, sds_dir: str) -> bool:
    """
    Upload a DRF directory to SDS.

    Args:
        sds_client: Authenticated SDS client
        directory: Path to the directory to upload
        sds_dir: SDS directory to upload to

    Returns:
        bool: True if upload was successful, False otherwise
    """
    try:
        # Upload the file using absolute path
        abs_path = directory.resolve()
        logger.info(f"Uploading directory {abs_path} to SDS")
        sds_client.upload(
            local_path=abs_path,
            sds_path=sds_dir,
            verbose=True,
        )
        logger.info(f"Finished upload of {directory}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload directory to SDS: {e}")
        return False


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Upload a DRF directory to SDS")
    parser.add_argument("directory", type=Path, help="Directory containing DRF files")
    parser.add_argument(
        "--host", default="sds.crc.nd.edu", help="SDS host (default: sds.crc.nd.edu)"
    )

    args = parser.parse_args()

    # Validate directory exists
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

    # Upload the directory
    upload_drf_dir(sds, args.directory, "/digital_rf/" + args.directory.name)


if __name__ == "__main__":
    main()
