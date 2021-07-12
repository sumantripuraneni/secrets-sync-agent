import json
# import logging
# import logging.config
import sys

from agent.utils.base64_conversions import toBase64
from agent.utils.base64_conversions import isBase64
from agent.utils.define_vars import *

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)

# logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
# log = logging.getLogger("agent")

# Function to create SSH Auth Secret Definition
def create_ssh_auth_secret_body(secret_data: dict, secret_name: str) -> dict:

    '''Function to create SSH Auth Secret Definition'''

    log.info("Creating definition for ssh-auth secret: {}".format(secret_name))

    # Block to validate if all necessary fields to create ssh-auth secrets are received from vault
    log.info(
        "Validating if all necessary fields to create Ssh Auth secrets are received from vault"
    )

    try:
        if "ssh-privatekey" in secret_data.get("data"):
            log.info("Necessary field to create Ssh Auth secret received from vault")
        else:
            log.error(
                "Necessary field to create Ssh Auth secrets not received from vault"
            )
            sys.exit(1)
    except Exception as error:
        log.error("Error while accessing retrieved secret data")
        log.error(error)
        sys.exit(1)

    # Check if the data is already encoded to base64 or not
    if isBase64(secret_data["data"]["ssh-privatekey"]):
        ssh_auth_data = secret_data["data"]["ssh-privatekey"]
    else:
        ssh_auth_data = toBase64(secret_data["data"]["ssh-privatekey"])

    secret_body = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secret_name, "annotations": {"createdBy": "secrets-sync-agent"}},
        "type": "kubernetes.io/ssh-auth",
        "data": {
            "ssh-privatekey": ssh_auth_data,
        },
    }

    log.debug("Json definition for SSH Auth secret: {}".format(secret_name))
    log.debug(json.dumps(secret_body, indent=4))

    return secret_body
