# import logging
# import logging.config
import sys

from agent.k8_utils.get_k8_client import get_client
from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)

# Function to read data from from OpenShift ConfigMap
def read_data_from_configmap(configmap: str, namespace: str) -> dict:

    """Function to read data from from OpenShift ConfigMap"""

    # Get OpenShift dynamic client to work with api
    dyn_client = get_client()

    log.info("Reading configmap: {}".format(configmap))

    try:
        v1_cm = dyn_client.resources.get(api_version="v1", kind="ConfigMap")
    except Exception as error:
        log.error("An exception occurred: {}".format(error))
        sys.exit(1)

    try:
        configMapData = v1_cm.get(namespace=namespace, name=configmap)
    except Exception as error:
        log.error("An exception occurred while reading configmap: {}".format(configmap))
        log.error(error)
        sys.exit(1)

    configMapData = dict(configMapData.get("data"))
    configMapDataKeys = list(configMapData.keys())

    if len(configMapDataKeys) > 1:
        log.error(
            "ConfigMap: {} has more than one configuration file mentioned".format(
                configmap
            )
        )
        log.error("Only one configuration file in ConfigMap is allowed")
        log.error("Please correct ConfigMap: {}".format(configmap))

    return configMapData[configMapDataKeys[0]]
