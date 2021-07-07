import logging
import logging.config
import sys
import requests
import json
from agent.utils.base64_conversions import toBase64

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
log = logging.getLogger("agent")


# Function to create image pull secret definition
def create_image_pull_secret_body(data, secret_name):

    # Block to validate if all necessary fields to create image pull secrets are received from vault
    log.info(
        "Validating if all necessary fields to create image pull secrets are received from vault"
    )
    try:
        if (
            "registry-server" in data["data"]
            and "username" in data["data"]
            and "password" in data["data"]
        ):
            log.info(
                "All necessary fields to create image pull secrets are received from vault"
            )
        else:
            log.error(
                "All necessary fields to create image pull secrets are not received from vault"
            )
            log.error("Need registry-server, username and password to proceed")
            log.error("Data received from vault: {}".format(data["data"]))
            log.error("Please check secret definition in vault")
            sys.exit(1)
    except Exception as error:
        log.error(
            "Error while validating for all necessary fields to create image pull secrets"
        )
        log.error(error)
        sys.exit(1)

    log.info("Creating definition for image pull secret: {}".format(secret_name))

    cred_payload = {
        "auths": {
            data["data"]["registry-server"]: {
                "Username": data["data"]["username"],
                "Password": data["data"]["password"],
            }
        }
    }

    dockerConfigString = {".dockerconfigjson": toBase64(json.dumps(cred_payload))}

    secret_body = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secret_name, "annotations": {"createdBy": "secrets-sync-agent"}},
        "type": "kubernetes.io/dockerconfigjson",
        "data": dockerConfigString,
    }

    log.debug("Json definition for image pull secret: {}".format(secret_name))
    log.debug(json.dumps(secret_body, indent=4))

    return secret_body