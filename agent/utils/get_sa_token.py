import logging
import logging.config
import sys

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
log = logging.getLogger("agent")

def get_sa_token() -> str:
    '''Function to get mounted Service Account token'''

    k8_token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"

    try:
        with open(k8_token_file, "r") as f:
            sa_token = f.read()
            return sa_token
    except (OSError, IOError) as e:
        log.error("Error reading from file: {}".format(e))
        sys.exit(1)
        print("Error")

