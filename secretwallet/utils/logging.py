import logging
from logging.handlers import RotatingFileHandler
from secretwallet.constants import LOG_FILE, LOG_MAX_FILE_SIZE, LOG_BACKUP_COUNT


def get_logger(name, level=logging.INFO):
    """Returns a logger
    input:
    name        the name of the logger, typically a python_module name
    level       the logging level
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    # Create the rotating file handler. Limit the size to 1000000Bytes ~ 1MB .
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