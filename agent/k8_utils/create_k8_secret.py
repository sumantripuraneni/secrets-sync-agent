import logging
import logging.config
import sys
import requests
import json
from agent.k8_utils.get_k8_client import get_client


logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
log = logging.getLogger("agent")


# Function to create secret in ocp
def create_secret(secret_body: dict, secret_name: str, secret_type: str, namespace: str):

    '''Function to create secret in ocp'''

    dyn_client = get_client()

    try:
        v1_sec = dyn_client.resources.get(api_version="v1", kind="Secret")
    except Exception as error:
        log.error("An exception occurred: {}".format(error))
        sys.exit(1)

    secrets_list = []

    for secret in v1_sec.get(namespace=namespace).items:
        secrets_list.append(secret.metadata.name)

    log.debug("List of Secrets in namespace: {}".format(namespace))
    log.debug(secrets_list)

    if secret_name in secrets_list:
        log.info(
            "Secret: {} exists in Openshift namespace: {}".format(secret_name, namespace)
        )
        log.info("Checking if the secret: {} is modified in vault".format(secret_name))
        log.info(
            "Get secret: {} definition from OpenShift Container Platform".format(
                secret_name
            )
        )

        if secre_type == "dockercfg":

            secret_from_vault = secret_body["data"][".dockerconfigjson"]
            secret_from_ocp   = v1_sec.get(namespace=namespace, name=secret_name)
            secret_from_ocp   = secret_from_ocp["data"][".dockerconfigjson"]

        elif secre_type in ["opaque", "tls", "ssh-auth"]:
            secret_from_vault = dict(secret_body.get("data"))
            secret_from_ocp   = v1_sec.get(namespace=namespace, name=secret_name)
            secret_from_ocp   = dict(secret_from_ocp.get("data"))

        log.debug("Secret from Vault: {}".format(secret_from_vault))
        log.debug("Secret from OpenShift Container Platform: {}".format(secret_from_ocp))

        # Check if the secrets are same. if same, don't update the ocp secret else update
        if secret_from_vault == secret_from_ocp:
            log.info(
                "Secret: {} from Vault and OpenShift namespace: {} are same, so not updating".format(
                    secret_name, namespace
                )
            )
        else:
            log.info(
                "Secret: {} from Vault and OpenShift namespace: {} are not same, so updating".format(
                    secret_name, namespace
                )
            )
            # Update the secret if secrets from vault and openshift are different
            try:
                v1_sec.patch(body=secret_body, namespace=namespace)
            except Exception as error:
                log.error("An exception occurred: {}".format(error))
                sys.exit(1)

            log.info(
                "Secret: {} updated in OpenShift namespace: {}".format(
                    secret_name, namespace
                )
            )
    else:
        log.info(
            "Secret: {} does not exists, so creating in OpenShift namespace: {}".format(
                secret_name, namespace
            )
        )
        try:
            v1_sec.create(body=secret_body, namespace=namespace)
        except Exception as error:
            log.error("An exception occurred: {}".format(error))
            sys.exit(1)

        log.info(
            "Secret: {} created in OpenShift namespace: {}".format(
                secret_name, namespace
            )
        )
