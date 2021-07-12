# import logging
# import logging.config
import sys
import json
from agent.utils.base64_conversions import toBase64
from agent.utils.base64_conversions import isBase64

from agent.utils.define_vars import *

# logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
# log = logging.getLogger("agent")

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)


# Function to create TLS secret definition
def create_tls_secret_body(secret_data: dict, secret_name: str) -> dict:

    '''Function to create TLS secret definition'''

    # Block to validate if all necessary fields to create TLS secrets are received from vault
    log.info(
        "Validating if all necessary fields to create TLS secrets are received from vault"
    )

    try:

        if "tls.crt" in secret_data["data"] and "tls.key" in secret_data["data"]:
            log.info(
                "All necessary fields to create TLS secrets are received from vault"
            )
        else:
            log.error(
                "All necessary fields to create TLS secrets are not received from vault"
            )
            log.error("Need both tls.crt and tls.key to proceed")
            log.error("Data received from vault: {}".format(secret_data["data"]))
            log.error("Please check secret definition in vault")
            sys.exit(1)

    except Exception as error:

        log.error(
            "Error while validating for all necessary fields to create TLS secrets"
        )
        log.error(error)
        sys.exit(1)

    log.info("Creating definition for TLS secret: {}".format(secret_name))

    # Check if the data is already encoded to base64 or not
    if isBase64(secret_data["data"]["tls.crt"]) and isBase64(
        secret_data["data"]["tls.crt"]
    ):
        tlsCrt = secret_data["data"]["tls.crt"]
        tlsKey = secret_data["data"]["tls.key"]
    else:
        tlsCrt = toBase64(secret_data["data"]["tls.crt"])
        tlsKey = toBase64(secret_data["data"]["tls.key"])

    secret_body = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secret_name, "annotations": {"createdBy": "secrets-sync-agent"}},
        "type": "SecretTypeTLS",
        "data": {"tls.crt": tlsCrt, "tls.key": tlsKey},
    }

    log.debug("Json definition for TLS secret: {}".format(secret_name))
    log.debug(json.dumps(secret_body, indent=4))

    return secret_body
