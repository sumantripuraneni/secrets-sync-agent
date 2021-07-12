import logging
import os

def get_module_logger(mod_name):
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger(mod_name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(log_level)
    return logger


#   log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
# logging.basicConfig(
#     stream=sys.stdout, format="[%(asctime)s] [%(levelname)s] - %(message)s"
# )
# log = logging.getLogger()
# level = logging.getLevelName(log_level)
# log.setLevel(log_level)