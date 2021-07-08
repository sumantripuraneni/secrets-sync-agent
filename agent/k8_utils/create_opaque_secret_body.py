import logging
import logging.config
import sys
import requests
import json
from agent.utils.base64_conversions import toBase64

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
log = logging.getLogger("agent")


# Function to create opaque secret definition
def create_opaque_secret_body(secret_data: dict, secret_name: str) -> dict:

    log.info("Creating definition for opaque secret: {}".format(secret_name))

    sec_data = {}

    for d in secret_data["data"]:
        sec_data[d] = toBase64(secret_data["data"][d])

    secret_body = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secret_name, "annotations": {"createdBy": "secrets-sync-agent"}},
        "data": sec_data,
        "type": "Opaque",
    }

    log.debug("Json definition for opaque secert: {}".format(secret_name))
    log.debug(json.dumps(secret_body, indent=4))

    return secret_body
