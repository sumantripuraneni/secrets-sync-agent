import os
import yaml


class GetEnv:
    def get_from_env() -> dict:

        """Function to get environment variables"""

        config = {}

        config["VAULT_CONNECTION_INFO_CONFIGMAP_NAME"] = os.environ.get(
            "VAULT_CONNECTION_INFO_CONFIGMAP_NAME"
        )
        config["VAULT_SECRETS_RETRIEVAL_INFO_CONFIGMAP_NAME"] = os.environ.get(
            "VAULT_SECRETS_RETRIEVAL_INFO_CONFIGMAP_NAME"
        )
        config["VAULT_CONNECTION_INFO_CONFIG_FILE"] = os.environ.get(
            "VAULT_CONNECTION_INFO_CONFIG_FILE"
        )
        config["VAULT_SECRETS_RETRIEVAL_INFO_CONFIG_FILE"] = os.environ.get(
            "VAULT_SECRETS_RETRIEVAL_INFO_CONFIG_FILE"
        )
        config["DEFAULT_CONNECTION_INFO_FILE"] = os.environ.get(
            "DEFAULT_CONNECTION_INFO_FILE",
            "/etc/secrets_sync_agent/connection_info/vault_connection_info.yaml",
        )
        config["DEFAULT_SECRETS_RETRIEVAL_INFO_FILE"] = os.environ.get(
            "DEFAULT_SECRETS_RETRIEVAL_INFO_FILE",
            "/etc/secrets_sync_agent/secrets_info/vault_secrets_info.yaml",
        )

        if os.environ.get("SECRETS_RETRIEVAL_INFO_FROM_ENV"):
            config["SECRETS_RETRIEVAL_INFO_FROM_ENV"] = yaml.safe_load(
                os.environ.get("SECRETS_RETRIEVAL_INFO_FROM_ENV")
            )
        else:
            config["SECRETS_RETRIEVAL_INFO_FROM_ENV"] = None

        if os.environ.get("CONNECTION_INFO_FROM_ENV"):
            config["CONNECTION_INFO_FROM_ENV"] = yaml.safe_load(
                os.environ.get("CONNECTION_INFO_FROM_ENV")
            )
        else:
            config["CONNECTION_INFO_FROM_ENV"] = None

        config["VAULT_SECRETS_REFRESH_SECONDS"] = os.environ.get(
            "VAULT_SECRETS_REFRESH_SECONDS", "3600"
        )

        config["RUN_ONCE"] = os.environ.get("RUN_ONCE", "False").lower()

        # Vault Connection details
        config["VAULT_ADDR"] = os.environ.get("VAULT_ADDR")

        config["VAULT_ROLE"] = os.environ.get("VAULT_ROLE")

        config["VAULT_NAMESPACE"] = os.environ.get("VAULT_NAMESPACE")

        config["VAULT_LOGIN_ENDPOINT"] = os.environ.get("VAULT_LOGIN_ENDPOINT")

        config["KUBE_SECRETS_MGMT_CREDS_PATH"] = os.environ.get("KUBE_SECRETS_MGMT_CREDS_PATH")

        return config
