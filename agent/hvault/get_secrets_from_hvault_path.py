# import logging
# import logging.config
import sys
import requests
import json

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)


# Function to read the secrets from HashiVault path
def get_secret(vault_url: str, secret_path: str, k8_hvault_token: str) -> dict:

    '''Function to read the secrets from HashiVault path'''

    secret_retrival_url = vault_url + secret_path
    headers = {"X-Vault-Token": k8_hvault_token}

    log.debug("Using path to retrieval secret: {}".format(secret_retrival_url))
    log.debug("Using vault token: {}".format(k8_hvault_token))

    try:
        resp = requests.get(secret_retrival_url, headers=headers, verify=False)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error("Error while retriving secret from vault: {}".format(e))

    return resp.json().get("data")
