import json
import os
import logging
import sys
import filecmp
import time
import shutil

from agent.utils.get_sa_token import get_sa_token
from agent.hvault.get_kube_auth_token import get_vault_kube_auth_token
from agent.k8_utils.get_namespace_name import get_namespace_name
from agent.hvault.get_secrets_from_hvault_path import get_secret
from agent.k8_utils.create_image_pull_secret_body import create_image_pull_secret_body
from agent.k8_utils.create_opaque_secret_body import create_opaque_secret_body
from agent.k8_utils.create_opaque_secret_body_from_template import create_opaque_secret_body_from_template
from agent.k8_utils.create_ssh_secret_body import create_ssh_auth_secret_body
from agent.k8_utils.create_tls_secret_body import create_tls_secret_body
from agent.k8_utils.create_k8_secret import create_secret
from agent.utils.write_secrets_data_to_file import write_to_file
import agent.utils.get_user_configs as user_configs
import agent.utils.validate_configurations as validate
import agent.utils.get_env as get_env
import agent.utils.logo as logo


# Global Log settings
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    stream=sys.stdout, format="[%(asctime)s] [%(levelname)s] - %(message)s"
)
log = logging.getLogger()
level = logging.getLevelName(log_level)
log.setLevel(log_level)


# TLS cert for secure communication with vault
### ADD TLS here


class SecretsAgent:

     # Main run function
    def run():

        # Print ASCII Art Banner
        print(logo.logo)

        # Print effective log level
        log.info("Log Level: {}".format(logging.getLevelName(log.getEffectiveLevel())))

        log.info("Get environment variables")

        # Load configurations from environment       
        userEnvConfig = get_env.GetEnv.get_from_env()

        log.debug("Environment variables dictionary:")
        log.debug(json.dumps(userEnvConfig, indent=4))

        log.info("Get OpenShift namespace")
        namespace = get_namespace_name()
        log.debug("Default Namespace: {}".format(namespace))

        # Call function to get service account token
        # to authenticate and generate KubeAuth token
        log.info("Get OpenShift service account token")
        sa_token = get_sa_token()

        log.debug("OpenShift Service Account Token: " + sa_token)

        while True:

            # Call function processInput to get the hashi vault connection detail
            # and secrets retrieval details based on input
            object_get_user_configs = user_configs.GetUserConfigs(userEnvConfig, namespace)
            connection_details, secrets_details = object_get_user_configs.process_input()

            # Validate Connection configuration
            validate_obj = validate.ValidateUserConfig(connection_details, secrets_details)
            validate_obj.validate_user_config()

            # Merge the two dicts
            vault_configmap_contents = {**connection_details, **secrets_details}
            log.debug("Merged configuration:")
            log.debug(json.dumps(vault_configmap_contents, indent=4))

            # Add trailing '/' is to hashi-vault-url if not exists
            if not vault_configmap_contents.get("VAULT_ADDR").endswith("/"):
                vault_configmap_contents["VAULT_ADDR"] = (
                    vault_configmap_contents.get("VAULT_ADDR") + "/"
                )         

            # Call function to get KubeAuth token
            log.info("Get the Kubernetes auth token from vault")

            if "VAULT_NAMESPACE" in vault_configmap_contents.keys():

                k8_hvault_token = get_vault_kube_auth_token(
                    vault_configmap_contents.get("VAULT_ADDR"),
                    vault_configmap_contents.get("VAULT_LOGIN_ENDPOINT"),
                    vault_configmap_contents.get("VAULT_ROLE"),
                    sa_token,
                    vault_configmap_contents.get("VAULT_NAMESPACE")
                )

            else:

                k8_hvault_token = get_vault_kube_auth_token(
                    vault_configmap_contents.get("VAULT_ADDR"),
                    vault_configmap_contents.get("VAULT_LOGIN_ENDPOINT"),
                    vault_configmap_contents.get("VAULT_ROLE"),
                    sa_token
                )

            log.debug("Got vault KubeAuth token: " + k8_hvault_token)

            # When KUBE_SECRETS key in ConfigMap
            if "KUBE_SECRETS" in vault_configmap_contents.keys():
                for i_secret in vault_configmap_contents.get("KUBE_SECRETS"):

                    # Call function to retrieve secrets from vault
                    log.info(
                        "Retrieving secret from vault path: {}".format(
                            i_secret.get("VAULT_SECRET_PATH")
                        )
                    )

                    # get namespace if namespace is defined as key,
                    # if NAMESPACE key not mentioned, use the namespace (as default) this process is running
                    namespace = i_secret.get("NAMESPACE", namespace)

                    secret_from_hvault = get_secret(
                        vault_configmap_contents.get("VAULT_ADDR"),
                        i_secret.get("VAULT_SECRET_PATH"),
                        k8_hvault_token,
                    )

                    # If secret received from vault
                    if secret_from_hvault:

                        log.debug("Secret from vault:")
                        log.debug(json.dumps(secret_from_hvault,indent=4))

                        # Block for dockercfg (imagepull secrets)
                        if i_secret.get("SECRET_TYPE").lower() == "dockercfg":

                            log.info("Secret type to create is: dockercfg")

                            secret_body = create_image_pull_secret_body(
                                secret_from_hvault,
                                i_secret.get("KUBERNETES_SECRET")
                            )

                            create_secret(
                                secret_body,
                                i_secret.get("KUBERNETES_SECRET"),
                                "dockercfg",
                                namespace,
                            )

                        # Block for opaque secrets template based 
                        elif (
                            i_secret["SECRET_TYPE"].lower() == "opaque"
                            and "TEMPLATE_AS_CONFIGMAP" in i_secret.keys()
                        ):

                            log.info("Secret type to create is: opaque")
                            secret_body = create_opaque_secret_body_from_template(
                                secret_from_hvault,
                                i_secret.get("KUBERNETES_SECRET"),
                                i_secret.get("SECRET_FILE_NAME", "secret.yaml"),
                                namespace,
                                config_map = i_secret.get("TEMPLATE_AS_CONFIGMAP")
                            )

                            create_secret(
                                secret_body,
                                i_secret.get("KUBERNETES_SECRET"),
                                "opaque",
                                namespace,
                            )

                        # Block for opaque secrets template file based 
                        elif (
                            i_secret["SECRET_TYPE"].lower() == "opaque"
                            and "TEMPLATE_AS_FILE" in i_secret.keys()
                        ):

                            log.info("Secret type to create is: opaque")


                            secret_body = create_opaque_secret_body_from_template(
                                secret_from_hvault,
                                i_secret.get("KUBERNETES_SECRET"),
                                i_secret.get("SECRET_FILE_NAME", "secret.yaml"),
                                namespace,
                                template_file = i_secret.get("TEMPLATE_AS_FILE")      
                            )

                            create_secret(
                                secret_body,
                                i_secret.get("KUBERNETES_SECRET"),
                                "opaque",
                                namespace,
                            )

                        # Block for opaque secrets 
                        elif (
                            i_secret.get("SECRET_TYPE").lower() == "opaque"
                            and not "TEMPLATE_AS_CONFIGMAP" in i_secret.keys()
                        ):

                            log.info("Secret type to create is: opaque")

                            secret_body = create_opaque_secret_body(
                                secret_from_hvault, 
                                i_secret.get("KUBERNETES_SECRET")
                            )

                            create_secret(
                                secret_body,
                                i_secret.get("KUBERNETES_SECRET"),
                                "opaque",
                                namespace,
                            )

                        # Block for TLS secrets
                        elif i_secret.get("SECRET_TYPE").lower() == "tls":

                            log.info("Secret type to create is: tls")

                            secret_body = create_tls_secret_body(
                                secret_from_hvault,
                                i_secret.get("KUBERNETES_SECRET")
                            )

                            create_secret(
                                secret_body,
                                i_secret.get("KUBERNETES_SECRET"),
                                "tls",
                                namespace
                            )

                        # Block for ssh-auth secrets
                        elif i_secret.get("SECRET_TYPE").lower() == "ssh-auth":

                            log.info("Secret type to create is: ssh-auth")

                            secret_body = create_ssh_auth_secret_body(
                                secret_from_hvault,
                                i_secret.get("KUBERNETES_SECRET")
                            )

                            create_secret(
                                secret_body,
                                i_secret.get("KUBERNETES_SECRET"),
                                "ssh-auth",
                                namespace,
                            )

                    else:
                        log.error(
                            "Secret could not be retrieved from vault path: {}".format(
                                i_secret.get("VAULT_SECRET_PATH")
                            )
                        )

            # When FILE_SECRETS key in ConfigMap
            elif "FILE_SECRETS" in vault_configmap_contents.keys():

                for i_secret in vault_configmap_contents.get("FILE_SECRETS"):

                    # Call function to retrieve secrets from vault
                    log.info(
                        "Retrieve secret from vault path: {}".format(
                            i_secret.get("VAULT_SECRET_PATH")
                        )
                    )

                    secret_from_hvault = get_secret(
                        vault_configmap_contents.get("VAULT_ADDR"),
                        i_secret.get("VAULT_SECRET_PATH"),
                        k8_hvault_token,
                    )

                    # Block when secret is retrieved from vault
                    if secret_from_hvault:

                        log.debug("Secret from vault: " + str(secret_from_hvault))

                        if os.path.exists(i_secret.get("TO_FILE_NAME")):

                            temp_secrets_file = (
                                "/tmp/" + i_secret.get("TO_FILE_NAME").split("/")[-1]
                            )

                            write_to_file(
                                secret_from_hvault.get("data"),
                                i_secret,
                                namespace,
                                temp_secrets_file,
                            )

                            log.info(
                                "Comparing two secret files, file: {} and file: {}".format(
                                    temp_secrets_file, i_secret.get("TO_FILE_NAME")
                                )
                            )

                            # Block to compare file secrets
                            if not filecmp.cmp(
                                temp_secrets_file, i_secret.get("TO_FILE_NAME"), shallow=False
                            ):

                                log.info(
                                    "Secrets are different!!, so rendering new secret to file: {}".format(
                                        i_secret.get("TO_FILE_NAME")
                                    )
                                )
                                shutil.move(temp_secrets_file, i_secret.get("TO_FILE_NAME"))

                            else:

                                log.info(
                                    "Two secrets in file: {} and file: {} are same. So skipping creating again".format(
                                        temp_secrets_file, i_secret.get("TO_FILE_NAME")
                                    )
                                )
                                log.info(
                                    "Deleting temp file created: {}".format(
                                        temp_secrets_file
                                    )
                                )
                                os.remove(temp_secrets_file)

                        # when actual secret (i_secret["to-file-name"]) file does not exist
                        else:

                            log.info(
                                "Writing secret to {}".format(i_secret.get("TO_FILE_NAME"))
                            )
                            write_to_file(secret_from_hvault["data"], i_secret, namespace)

            # Exit gracefully if RUN_ONCE flag is set to true
            if userEnvConfig.get("RUN_ONCE") in ["true", "yes", "1"]:
                log.info("RUN_ONCE:{} flag was set in environment".format(userEnvConfig.get("RUN_ONCE")))
                log.info("Secrets creation completed")
                log.info("Gracefully exciting")
                sys.exit(0)

            # Refresh Kubernetes secrets
            # See if its provided in environment or in configmaps
            if int(userEnvConfig.get("VAULT_SECRETS_REFRESH_SECONDS")) != 3600:
                refresh_time = userEnvConfig.get("VAULT_SECRETS_REFRESH_SECONDS")
            else:
                refresh_time = vault_configmap_contents.get("VAULT_SECRETS_REFRESH_SECONDS", 3600)
            log.info(
                "Waiting for {} seconds before connecting to vault".format(
                    refresh_time
                )
            )

            time.sleep(int(refresh_time))


if __name__ == "__main__":
    SecretsAgent.run()
