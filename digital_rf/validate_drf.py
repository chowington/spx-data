import argparse
from digital_rf import DigitalRFReader
from pathlib import Path


def validate_drf(drf_path: Path) -> bool:
    # Initialize Digital RF reader with the given directory
    reader = DigitalRFReader(str(drf_path))
    channels = reader.get_channels()

    if not channels:
        raise ValueError("No channels found in DigitalRF data")

    for channel in channels:
        start_sample, end_sample = reader.get_bounds(channel)
        print(f"Channel {channel} has {end_sample - start_sample} samples")

    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a DigitalRF directory")
    parser.add_argument("drf_path", type=Path, help="Path to the DigitalRF directory")
    args = parser.parse_args()

    result = validate_drf(args.drf_path)
    print(f"Validation result: {result}")


if __name__ == "__main__":
    main()
