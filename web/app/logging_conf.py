"""Configuration du logging SecLog (niveau via LOG_LEVEL, format horodaté)."""
import logging
import os
import sys


def setup_logging() -> logging.Logger:
    level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logger = logging.getLogger("seclog")
    logger.setLevel(level)
    if not logger.handlers:  # évite les doublons (create_app appelé plusieurs fois)
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(handler)
    logger.propagate = False
    return logger
