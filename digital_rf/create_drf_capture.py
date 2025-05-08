import argparse
import logging
from pathlib import Path

from spectrumx.client import Client
from spectrumx.errors import NetworkError, SDSError, ServiceError
from spectrumx.models.captures import CaptureType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_capture(sds_client: Client, sds_dir: str, channel: str) -> bool:
    """
    Create a capture in the SDS.

    Args:
        sds_client: Authenticated SDS client
        sds_dir: SDS directory containing the file
        channel: Channel to use for the capture

    Returns:
        bool: True if capture was created successfully, False otherwise
    """
    try:
        logger.info(f"Creating capture at {sds_dir} with channel {channel}")
        capture = sds_client.captures.create(
            top_level_dir=sds_dir,
            channel=channel,
            capture_type=CaptureType.DigitalRF,
        )
        logger.info(f"Created capture with UUID {capture.uuid}")
        return True
    except (NetworkError, ServiceError, SDSError) as e:
        logger.error(f"Error creating capture at {sds_dir} with channel {channel}: {e}")
        return False


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Create a single SDS capture from Digital RF files in a directory"
    )
    parser.add_argument(
        "sds_dir", type=Path, help="SDS directory containing Digital RF files"
    )
    parser.add_argument(
        "--host", default="sds.crc.nd.edu", help="SDS host (default: sds.crc.nd.edu)"
    )
    parser.add_argument(
        "--channel",
        help="Channel to use for the capture.",
    )

    args = parser.parse_args()

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

    create_capture(sds, args.sds_dir, args.channel)


if __name__ == "__main__":
    main()
