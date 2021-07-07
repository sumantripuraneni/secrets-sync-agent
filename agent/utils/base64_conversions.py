
import base64
import logging
import logging.config

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
log = logging.getLogger("agent")

# Function to check if a string in base64 encoded or not
def isBase64(str):
    try:
        return base64.b64encode(base64.b64decode(str)).decode() == str
    except Exception:
        return False


# Function to convert a string to base64
def toBase64(str):
    try:
        return base64.b64encode(str.encode("utf-8")).decode()
    except Exception as e:
        log.error("Error while converting a string to base64")
        log.error(e)