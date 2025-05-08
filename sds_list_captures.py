import logging
from spectrumx import Client

logging.basicConfig(level=logging.INFO)

# Token
token = ""

# Initialize SDS client
sds = Client(host="sds.crc.nd.edu", env_config={"SDS_SECRET_TOKEN": token})

# Enable actual changes (not dry run)
sds.dry_run = False

# Authenticate
try:
    sds.authenticate()
except Exception as e:
    raise RuntimeError(f"Failed to authenticate with SDS: {e}")

# Get all captures
try:
    captures = sds.captures.listing()
    # Print the captures
    for capture in captures:
        print(capture)
except Exception as e:
    logging.exception(e)
