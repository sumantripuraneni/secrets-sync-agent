from agent.utils.define_vars import (
    userEnvConfig,
    vault_configmap_contents
)
import sys
import time

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)


def loop_control():

    """Function to decide on exit of program"""

    # Exit gracefully if RUN_ONCE flag is set to true
    if userEnvConfig.get("RUN_ONCE") in ["true", "yes", "1"]:
        log.info(
            "RUN_ONCE:{} flag was set in environment".format(
            userEnvConfig.get("RUN_ONCE")
            )
        )
        log.info("Secrets creation completed")
        log.info("Gracefully exciting")
        sys.exit(0)

    # Refresh Kubernetes secrets
    # See if its provided in environment or in configmaps
    if int(userEnvConfig.get("VAULT_SECRETS_REFRESH_SECONDS")) != 3600:
        refresh_time = userEnvConfig.get("VAULT_SECRETS_REFRESH_SECONDS")
    else:
        refresh_time = vault_configmap_contents.get(
                "VAULT_SECRETS_REFRESH_SECONDS", 3600
            )

    log.info(
            "Waiting for {} seconds before connecting to vault".format(refresh_time)
        )

    # Wait for 'refresh_time' period    
    time.sleep(int(refresh_time))
