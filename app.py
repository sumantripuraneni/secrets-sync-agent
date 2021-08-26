import json
import logging

# Print ASCII Art Banner
import agent.utils.logo as logo
print(logo.logo)

# Get logger
from agent.utils.get_logger import get_module_logger
log = get_module_logger(__name__)

# Print effective log level
log.info("Log Level: {}".format(logging.getLevelName(log.getEffectiveLevel())))

# Import custom modules
from agent.utils.define_vars import (
    userEnvConfig,
    v_namespace,
    sa_token,
    vault_configmap_contents,
    k8_hvault_token,
)
from agent.utils.loop_control import loop_control
import agent.k8_utils.create_update_kube_secrets as kube_secrets
import agent.k8_utils.create_update_file_secrets as file_secrets


# Main class
class SecretsAgent:

    # Main run function
    def run(self):

        '''Main run function which initiates the program'''

        log.debug("Environment variables dictionary:")
        log.debug(json.dumps(userEnvConfig, indent=4))

        log.debug("Get OpenShift namespace")
        log.debug("Default Namespace: {}".format(v_namespace))

        log.debug("OpenShift Service Account Token: " + sa_token)

        while True:

            log.debug("Merged configuration:")
            log.debug(json.dumps(vault_configmap_contents, indent=4))

            # Call function to get KubeAuth token
            log.info("Get the Kubernetes auth token from vault")

            log.debug("Got vault KubeAuth token: " + k8_hvault_token)

            # When KUBE_SECRETS key in ConfigMap
            # Call ProcessKubeSecrets
            if "KUBE_SECRETS" in vault_configmap_contents.keys():
                kube_secrets.ProcessKubeSecrets.process_secrets()

            # When FILE_SECRETS key in ConfigMap
            # Call ProcessFileSecrets
            elif "FILE_SECRETS" in vault_configmap_contents.keys():
                file_secrets.ProcessFileSecrets.process_secrets()

            # Call function to decide program exit or to loop
            # Exit gracefully if RUN_ONCE flag is set to true
            loop_control()


if __name__ == "__main__":
    agent = SecretsAgent()
    agent.run()
