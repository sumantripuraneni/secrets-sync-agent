import shutil
import filecmp
import os

from agent.utils.define_vars import (
    userEnvConfig,
    v_namespace,
    vault_configmap_contents,
    k8_hvault_token,
)
from agent.hvault.get_secrets_from_hvault_path import get_secret
from agent.utils.write_secrets_data_to_file import write_to_file

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)


class ProcessFileSecrets:
    def process_secrets():

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

                    temp_secrets_file = os.path.join(
                        "/tmp/", i_secret.get("TO_FILE_NAME").split("/")[-1]
                    )

                    write_to_file(
                        secret_from_hvault.get("data"),
                        i_secret,
                        v_namespace,
                        temp_secrets_file,
                    )

                    log.info(
                        "Comparing two secret files, file: {} and file: {}".format(
                            temp_secrets_file, i_secret.get("TO_FILE_NAME")
                        )
                    )

                    # Block to compare file secrets
                    if not filecmp.cmp(
                        temp_secrets_file,
                        i_secret.get("TO_FILE_NAME"),
                        shallow=False,
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
                            "Deleting temp file created: {}".format(temp_secrets_file)
                        )
                        os.remove(temp_secrets_file)

                # when actual secret (i_secret["to-file-name"]) file does not exist
                else:

                    log.info(
                        "Writing secret to {}".format(i_secret.get("TO_FILE_NAME"))
                    )
                    write_to_file(secret_from_hvault["data"], i_secret, v_namespace)
