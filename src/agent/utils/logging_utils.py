import logging
import sys

# Configure standard root logger if it hasn't been configured already
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def get_logger(name: str) -> logging.Logger:
    """
    Returns a logger prefixed with the agent workspace name.
    """
    return logging.getLogger(f"threat_intel_curator.{name}")
