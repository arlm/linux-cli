import logging
import os
from logging.handlers import RotatingFileHandler

from .constants import LOGGER_NAME
from protonvpn_nm_lib.constants import PROTON_XDG_CACHE_HOME_LOGS
import time


def get_logger():
    """Create the logger."""
    FORMATTER = logging.Formatter(
        "%(asctime)s — %(filename)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s" # noqa
    )
    FORMATTER.converter = time.gmtime

    if not os.path.isdir(PROTON_XDG_CACHE_HOME_LOGS):
        os.makedirs(PROTON_XDG_CACHE_HOME_LOGS)

    LOGFILE = os.path.join(PROTON_XDG_CACHE_HOME_LOGS, "protonvpn-cli.log")

    logger = logging.getLogger(LOGGER_NAME)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(FORMATTER)

    logging_level = logging.INFO
    # Only log to console when using PROTONVPN_DEBUG=1
    if str(os.environ.get("PROTONVPN_CLI_DEBUG", False)).lower() == "true":
        logging_level = logging.DEBUG
        logger.addHandler(console_handler)

    logger.setLevel(logging_level)
    # Starts a new file at 3MB size limit
    file_handler = RotatingFileHandler(
        LOGFILE, maxBytes=3145728, backupCount=3
    )
    file_handler.setFormatter(FORMATTER)
    logger.addHandler(file_handler)

    return logger


logger = get_logger()
