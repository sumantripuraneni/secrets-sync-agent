import sys
import yaml
import json
import os

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)

class GetUserConfigs:

    def __init__(self, user_env_config, namespace):
        self.user_env_config = user_env_config
        self.namespace       = namespace

    @staticmethod
    def read_data_from_file(fileName):

        '''Function to read from mounted config files '''

        log.info("Reading from file: {}".format(fileName))

        try:
            with open(fileName, "r") as file:
                return yaml.full_load(file)
        except (OSError, IOError) as e:
            log.error("Error reading from file: {}".format(e))
            sys.exit(1)
        except yaml.YAMLError as e:
            log.error("Error while loading yaml file: {}".format(e))
            sys.exit(1)


    def process_input(self) -> dict:

        '''Function to determine and process user inputs'''

        default_connection_file             = self.user_env_config.get("DEFAULT_CONNECTION_INFO_FILE")
        default_secrets_file                = self.user_env_config.get("DEFAULT_SECRETS_RETRIEVAL_INFO_FILE")
        user_connection_file                = self.user_env_config.get("VAULT_CONNECTION_INFO_CONFIG_FILE")
        user_secrets_file                   = self.user_env_config.get("VAULT_SECRETS_RETRIEVAL_INFO_CONFIG_FILE")
        user_connection_from_env            = self.user_env_config.get("CONNECTION_INFO_FROM_ENV")
        user_secrets_from_env               = self.user_env_config.get("SECRETS_RETRIEVAL_INFO_FROM_ENV")
        vault_addr_from_env                 = self.user_env_config.get("VAULT_ADDR")
        vault_role_from_env                 = self.user_env_config.get("VAULT_ROLE")
        vault_namespace_from_env            = self.user_env_config.get("VAULT_NAMESPACE")
        vault_login_endpoint_from_env       = self.user_env_config.get("VAULT_LOGIN_ENDPOINT")
        namespace                           = self.namespace


        if vault_addr_from_env is not None and vault_role_from_env is not None:
            connection_dict = {
                "VAULT_ADDR": vault_addr_from_env,
                "VAULT_ROLE": vault_role_from_env,
                "VAULT_LOGIN_ENDPOINT": vault_login_endpoint_from_env
            }

            if vault_namespace_from_env is not None:
                connection_dict["VAULT_NAMESPACE"] = vault_namespace_from_env

            user_connection_dir = "/tmp/secrets_sync_agent"

            if not os.path.isdir(user_connection_dir):
                os.mkdir(user_connection_dir, 0o755)

            user_connection_file = os.path.join(user_connection_dir,'vault_connection_info.yaml')

            with open(user_connection_file, 'w') as f:
                yaml.dump(connection_dict, f)
            
        log.debug("Program will use below to get the details in following precedence")

        log.debug(
            "User provided vault connection details from environment: {}".format(
                user_connection_from_env
            )
        )
        log.debug(
            "User provided vault secrets retrieval from environment: {}".format(
                user_secrets_from_env
            )
        )
        log.debug(
            "Default vault connection details file: {}".format(
                default_connection_file
            )
        )
        log.debug(
            "Default vault secrets retrieval details file: {}".format(
                default_secrets_file
            )
        )
        log.debug(
            "User provided vault connection details file: {}".format(
                user_connection_file
            )
        )
        log.debug(
            "User provided vault secrets retrieval details file: {}".format(
                user_connection_file
            )
        )

        for type in ["connection", "secrets"]:

            eval_default_file = eval("default_" + type + "_file")
            eval_user_file = eval("user_" + type + "_file")
            # eval_user_cm = eval("user_" + type + "_cm")

            log.info("Trying to get vault {} details".format(type))

            try:

                if user_connection_from_env and user_secrets_from_env:

                    log.debug(
                        "Based on precedence reading {} details from user provided values from custom resource".format(
                            type
                        )
                    )
                    log.info(
                        "Reading details from environment to get details from user provided values from custom resource"
                    )

                    temp_dict = eval("user_" + type + "_from_env")

                    if type == 'connection':
                        globals()[type + "_details"] = { k.upper()[1:]:v for k,v in temp_dict.items()}

                    elif type == 'secrets':
                        for list_of_dicts in temp_dict.values():
                            globals()[type + "_details"] = {
                                "KUBE_SECRETS": [ 
                                    { k.upper()[1:]: v  for k,v in dt.items() } 
                                    for dt in list_of_dicts 
                                    ] 
                                }


                elif (
                    os.path.isfile(eval_default_file)
                    and eval_user_file
                ):

                    log.debug(
                        "Based on precedence reading {} details from user provided file: {}".format(
                            type, eval_user_file
                        )
                    )
                    log.info("Reading configuration from file: {}".format(eval_user_file))
                    globals()[type + "_details"] = GetUserConfigs.read_data_from_file(eval_user_file)
                    
                elif (
                    not os.path.isfile(eval_default_file)
                    and eval_user_file
                ):

                    log.debug(
                        "Based on precedence reading {} details from user provided file: {}".format(
                            type, eval_user_file
                        )
                    )
                    log.info("Reading configuration from file: {}".format(eval_user_file))
                    globals()[type + "_details"] = GetUserConfigs.read_data_from_file(eval_user_file)

                elif (
                    os.path.isfile(eval_default_file)
                    and not eval_user_file
                    ):

                    log.debug(
                        "Based on precedence reading {} details from default file: {}".format(
                            type, eval_default_file
                        )
                    )
                    log.info(
                        "Reading configuration from file: {}".format(eval_default_file)
                    )
                    globals()[type + "_details"] = GetUserConfigs.read_data_from_file(eval_default_file)

                else:
                    log.error(
                        "Error occurred in while trying to get vault connection and secret retrieval details"
                    )
                    sys.exit(1)

            except Exception as error:
                log.error(
                    "Error while trying to get vault connection and secret retrieval details"
                )
                log.error("Please check the environment variables passed and default files")
                log.error(error)
                sys.exit(1)

            log.info("Got vault {} details".format(type))

        connection_details = globals()["connection_details"]
        secrets_details = globals()["secrets_details"]

        log.debug("Vault connection details:")
        log.debug(json.dumps(connection_details, indent=4))

        log.debug("Vault secrets retrieval details:")
        log.debug(json.dumps(secrets_details, indent=4))

        return connection_details, secrets_details
