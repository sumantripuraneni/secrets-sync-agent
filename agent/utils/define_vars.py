import os
import sys

import agent.utils.get_env as get_env
import agent.utils.get_user_configs as user_configs
import agent.utils.validate_configurations as validate
from agent.k8_utils.get_namespace_name import get_namespace_name
from agent.utils.get_sa_token import get_sa_token
from agent.hvault.get_kube_auth_token import get_vault_kube_auth_token

if "KUBERNETES_SERVICE_HOST" in os.environ and "KUBERNETES_SERVICE_PORT" in os.environ:
    K8S_API_ENDPOINT = "https://kubernetes.default.svc.cluster.local"
else:
    K8S_API_ENDPOINT = "https://api.cluster2.openshifthappens.com:6443"


k8s_ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
vault_ca_cert = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"


###Need to check this later
if os.path.exists(vault_ca_cert):
    vault_ssl_verify = vault_ca_cert
else: 
    vault_ca_cert = False


userEnvConfig = get_env.GetEnv.get_from_env()

v_namespace = get_namespace_name()

# Call function processInput to get the hashi vault connection detail
# # and secrets retrieval details based on input
object_get_user_configs = user_configs.GetUserConfigs(userEnvConfig, v_namespace)
connection_details, secrets_details = object_get_user_configs.process_input()

# Validate Connection configuration
validate_obj = validate.ValidateUserConfig(connection_details, secrets_details)
validate_obj.validate_user_config()

# Merge the two dicts
vault_configmap_contents = {**connection_details, **secrets_details}



## Need to get this from configmap
secret_path = vault_configmap_contents.get("KUBE_SECRETS_MGMT_CREDS_PATH")

vault_url = vault_configmap_contents.get("VAULT_ADDR")


# Call function to get service account token
# to authenticate and generate KubeAuth token

sa_token = get_sa_token()


if not vault_configmap_contents.get("VAULT_ADDR").endswith("/"):
    vault_configmap_contents["VAULT_ADDR"] = (
        vault_configmap_contents.get("VAULT_ADDR") + "/"
    )


if "VAULT_NAMESPACE" in vault_configmap_contents.keys():

    k8_hvault_token = get_vault_kube_auth_token(
        vault_configmap_contents.get("VAULT_ADDR"),
        vault_configmap_contents.get("VAULT_LOGIN_ENDPOINT"),
        vault_configmap_contents.get("VAULT_ROLE"),
        sa_token,
        vault_configmap_contents.get("VAULT_NAMESPACE"),
    )

else:

    k8_hvault_token = get_vault_kube_auth_token(
        vault_configmap_contents.get("VAULT_ADDR"),
        vault_configmap_contents.get("VAULT_LOGIN_ENDPOINT"),
        vault_configmap_contents.get("VAULT_ROLE"),
        sa_token,
    )
