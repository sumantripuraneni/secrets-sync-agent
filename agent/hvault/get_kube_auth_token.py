
# import logging
# import logging.config
import sys
import requests
import json
#from agent.utils.define_vars import *

# logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
# log = logging.getLogger("agent")
from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)

def get_vault_kube_auth_token(
    vault_url: str, login_ep: str, role_name: str,
    k8_token: str, vault_login_namespace: str = None
) -> str:

    '''Function to get the KubeAuth token from Hashi Vault'''

    auth_token_url = vault_url + login_ep

    log.debug("Using vault url to get KubeAuth token: {}".format(auth_token_url))
    log.debug("Using vault login namespace to get KubeAuth token : {}".format(vault_login_namespace))

    try:
        if vault_login_namespace:
            resp = requests.post(
                auth_token_url,
                headers={"x-vault-namespace": vault_login_namespace},
                data=json.dumps({"jwt": k8_token, "role": role_name}),
                verify=vault_ssl_verify,
            )
        else:
            resp = requests.post(
                auth_token_url,
                data=json.dumps({"jwt": k8_token, "role": role_name}),
                verify=vault_ssl_verify,
            )

        resp.raise_for_status()

    except requests.exceptions.HTTPError as e:
        log.error(
            "Error while retrieving KubeAuth token from vault: {}".format(e)
        )
        log.error(resp.json())
        print("Error")
        sys.exit(1)

    return resp.json().get("auth").get("client_token")