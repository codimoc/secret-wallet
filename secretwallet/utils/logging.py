import logging
from logging.handlers import RotatingFileHandler

from secretwallet.constants import LOG_FILE, LOG_MAX_FILE_SIZE, LOG_BACKUP_COUNT, make_log_level
from secretwallet.utils.fileutils import touch



def get_logger(name, log_level="info"):
    """Returns a logger
    input:
    name        the name of the logger, typically a python_module name
    level       the logging level
    """
    level = make_log_level(log_level)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    # Create the rotating file handler. Limit the size to 1000000Bytes ~ 1MB .
    touch(LOG_FILE) #if it does not exits, create it
    handler = RotatingFileHandler(LOG_FILE,
                                  mode='a',
                                  maxBytes=LOG_MAX_FILE_SIZE,
                                  backupCount=LOG_BACKUP_COUNT,
                                  encoding='utf-8',
                                  delay=0)
    handler.setLevel(level)
    # Create a formatter.
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Add handler and formatter.
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger