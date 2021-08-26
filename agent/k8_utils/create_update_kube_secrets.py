import json

# Import custom modules
from agent.utils.define_vars import (
    userEnvConfig,
    v_namespace,
    sa_token,
    vault_configmap_contents,
    k8_hvault_token,
)
from agent.hvault.get_secrets_from_hvault_path import get_secret
from agent.k8_utils.create_opaque_secret_body import create_opaque_secret_body
from agent.k8_utils.create_image_pull_secret_body import create_image_pull_secret_body
from agent.k8_utils.create_tls_secret_body import create_tls_secret_body
from agent.k8_utils.create_ssh_secret_body import create_ssh_auth_secret_body
from agent.k8_utils.create_k8_secret import create_secret

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)


class ProcessKubeSecrets:
    def process_secrets():

        """Function to process KUBE_SECRETS"""

        for i_secret in vault_configmap_contents.get("KUBE_SECRETS"):

            # Call function to retrieve secrets from vault
            log.info(
                "Retrieving secret from vault path: {}".format(
                    i_secret.get("VAULT_SECRET_PATH")
                )
            )

            # get namespace if namespace is defined as key,
            # if NAMESPACE key not mentioned -
            # use the namespace (as default) this process is running
            namespace = i_secret.get("NAMESPACE", v_namespace)

            secret_from_hvault = get_secret(
                vault_configmap_contents.get("VAULT_ADDR"),
                i_secret.get("VAULT_SECRET_PATH"),
                k8_hvault_token,
            )

            # If secret received from vault
            if secret_from_hvault:

                log.debug("Secret from vault:")
                log.debug(json.dumps(secret_from_hvault, indent=4))

                # Block for dockercfg (imagepull secrets)
                if i_secret.get("SECRET_TYPE").lower() == "dockercfg":

                    log.info("Secret type to create is: dockercfg")

                    secret_body = create_image_pull_secret_body(
                        secret_from_hvault, i_secret.get("KUBERNETES_SECRET")
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
                        config_map=i_secret.get("TEMPLATE_AS_CONFIGMAP"),
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
                        template_file=i_secret.get("TEMPLATE_AS_FILE"),
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
                        secret_from_hvault, i_secret.get("KUBERNETES_SECRET")
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
                        secret_from_hvault, i_secret.get("KUBERNETES_SECRET")
                    )

                    create_secret(
                        secret_body,
                        i_secret.get("KUBERNETES_SECRET"),
                        "tls",
                        namespace,
                    )

                # Block for ssh-auth secrets
                elif i_secret.get("SECRET_TYPE").lower() == "ssh-auth":

                    log.info("Secret type to create is: ssh-auth")

                    secret_body = create_ssh_auth_secret_body(
                        secret_from_hvault, i_secret.get("KUBERNETES_SECRET")
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
