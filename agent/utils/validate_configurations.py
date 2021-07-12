from pydantic import BaseModel, HttpUrl, ValidationError, validator
from typing import Optional, List, Literal
# import logging
# import logging.config
import sys

from agent.utils.define_vars import *

# logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
# log = logging.getLogger("agent")

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)
# Class definition to validate vault connection configuration
class VaultConnectionModel(BaseModel):

    """A class to parse and validate vault connection information"""

    VAULT_ADDR: HttpUrl
    VAULT_LOGIN_ENDPOINT: str
    VAULT_ROLE: str


# Class definition to validate list of KUBE_SECRETS
class KubeSecretsBase(BaseModel):

    """A class to parse and validate list of KUBE_SECRETS"""

    VAULT_SECRET_PATH: str
    KUBERNETES_SECRET: str
    SECRET_TYPE: str
    TEMPLATE_AS_CONFIGMAP: Optional[str]
    TEMPLATE_AS_FILE: Optional[str]


# Class definition to validate KUBE_SECRETS
class KubeSecrets(BaseModel):

    """A class to parse and validate KUBE_SECRETS"""

    KUBE_SECRETS: List[KubeSecretsBase]


# Class definition to validate list of FILE_SECRETS
class FileSecretsBase(BaseModel):

    """A class to parse and validate list of FILE_SECRETS:"""

    VAULT_SECRET_PATH: str
    FILE_FORMAT: str
    TO_FILE_NAME: str
    TEMPLATE_AS_CONFIGMAP: Optional[str]
    TEMPLATE_AS_FILE: Optional[str]

    @validator("FILE_FORMAT")
    def supported_file_formats(cls, FILE_FORMAT):
        file_formats = ["json", "yaml", "ini", "txt"]
        if FILE_FORMAT.lower() not in file_formats:
            raise ValueError(
                "Unsupported FILE_FORMAT requested. Supported formats - {}".format(
                    file_formats
                )
            )
        return FILE_FORMAT


# Class definition to validate FILE_SECRETS
class FileSecrets(BaseModel):

    """A class to parse and validate FILE_SECRETS:"""

    FILE_SECRETS: List[FileSecretsBase]


# Class definition to validate configuration
class ValidateConfig:

    """Class to validate input configurations"""

    def __init__(self, data):
        self.data = data

    def validate_vault_connection_config(self) -> bool:

        """Function to validate vault connection configuration"""

        try:

            res = VaultConnectionModel(**self.data)

            log.info("Vault connection configuration validations passed")
            log.debug("Vault connection Configuration: {}".format(res))

            return True

        except ValidationError as e:

            log.info("Vault connection configuration validations failed")
            log.error(e)

            return False

    def validate_kube_secrets_config(self) -> bool:

        """Function to validate kube secrets configuration"""

        try:

            res = KubeSecrets(KUBE_SECRETS=self.data)

            log.info("Vault Kube secrets configuration validations passed")
            log.debug("Vault Kube secrets configuration: {}".format(res))

            return True

        except ValidationError as e:

            log.info("Vault Kube secrets configuration validations failed")
            log.error(e)

            return False

    def validate_file_secrets_config(self) -> bool:

        """Function to validate file secrets configuration"""

        try:

            res = FileSecrets(FILE_SECRETS=self.data)

            log.info("Vault File secrets configuration validations passed")
            log.debug("Vault File secrets configuration: {}".format(res))

            return True

        except ValidationError as e:

            log.info("Vault File secrets configuration validations failed")
            log.error(e)

            return False


# Class definition to validate user configuration
class ValidateUserConfig:
    def __init__(self, connection_config, secrets_config):
        self.connection_config = connection_config
        self.secrets_config = secrets_config

    def validate_user_config(self):

        """Function to validate user configurations"""

        if (
            "KUBE_SECRETS" in self.secrets_config.keys()
            and "FILE_SECRETS" in self.secrets_config.keys()
        ):

            log.error(
                "Both KUBE_SECRETS and FILE_SECRETS cannot be used!!. Please check configuration."
            )
            sys.exit(1)

        # Validate vault connection configuration
        conn = ValidateConfig(self.connection_config)

        if not conn.validate_vault_connection_config():
            sys.exit(1)

        # Validate KUBE_SECRETS configuration
        if "KUBE_SECRETS" in self.secrets_config.keys():

            # Validate secret retrieval configuration
            ksec = ValidateConfig(self.secrets_config.get("KUBE_SECRETS"))

            if not ksec.validate_kube_secrets_config():
                sys.exit(1)

        # Validate FILE_SECRETS configuration
        if "FILE_SECRETS" in self.secrets_config.keys():

            fsec = ValidateConfig(self.secrets_config.get("FILE_SECRETS"))

            if not fsec.validate_file_secrets_config():
                sys.exit(1)
