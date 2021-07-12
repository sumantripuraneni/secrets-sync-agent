# import logging
# import logging.config
import sys

# logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
# log = logging.getLogger("agent")
#from agent.utils.define_vars import *

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)

# Function to get namespace name with in the pod
def get_namespace_name() -> str:
    
    '''Function to get namespace name with in the pod'''

    ns_file = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    try:
        with open(ns_file, "r") as f:
            return f.read().strip("\n")
    except (OSError, IOError) as e:
        log.error("Error reading from file: {}".format(e))
        sys.exit(1)
