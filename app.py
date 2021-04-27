import requests
import json
import os
import logging
import sys
import yaml
import filecmp
import time
import shutil
import logo
import base64
import configparser
import jinja2
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from kubernetes import config, client
from openshift.dynamic import DynamicClient

# Disable InsecureRequestWarning warnings while connecting to OpenShift API
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Global Log settings
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    stream=sys.stdout, format="[%(asctime)s] [%(levelname)s] - %(message)s"
)
log = logging.getLogger()
level = logging.getLevelName(log_level)
log.setLevel(log_level)


# Check if code is running in OpenShift
if "KUBERNETES_SERVICE_HOST" in os.environ and "KUBERNETES_SERVICE_PORT" in os.environ:
    config.load_incluster_config()
else:
    config.load_kube_config()

# Create a client config
k8s_config = client.Configuration()

# Create K8 and dynamic client instances
try:
    k8s_client = client.api_client.ApiClient(configuration=k8s_config)
    dyn_client = DynamicClient(k8s_client)
except Exception as error:
    print("An exception occurred: {}".format(error))
    sys.exit(1)


# Function to read the environment parameters and create config dict
def getFromEnv():

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
        "DEFAULT_CONNECTION_INFO_FILE", "/etc/secrets_sync_agent/connection_info/vault_connection_info.yaml"
    )
    config["DEFAULT_SECRETS_RETRIEVAL_INFO_FILE"] = os.environ.get(
        "DEFAULT_SECRETS_RETRIEVAL_INFO_FILE", "/etc/secrets_sync_agent/secrets_info/vault_secrets_info.yaml"
    )
    config["RUN_ONCE"] = os.environ.get("RUN_ONCE", "False").lower()

    log.debug("Environment variables dictionary:")
    log.debug(json.dumps(config,indent=4))

    return config


# Function to read the service account token
def getSAToken():

    tokenFile = open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r")
    saToken = tokenFile.read().replace("\n", "")
    tokenFile.close()

    return saToken


# Function to get the KubeAuth token from Hashi vault
def getKubeHvaultAuthToken(
    vaultURL, loginEP, roleName, saToken, vaultLoginNamespace=None
):

    authTokenUrl = vaultURL + loginEP

    log.debug("Using vault url to get KubeAuth token: {}".format(authTokenUrl))
    log.debug("Using vault login namespace to get KubeAuth token : {}".format(vaultLoginNamespace))

    try:
        if vaultLoginNamespace:
            resp = requests.post(
                authTokenUrl,
                headers={"x-vault-namespace": vaultLoginNamespace},
                data=json.dumps({"jwt": saToken, "role": roleName}),
                verify=False,
            )
        else:
            resp = requests.post(
                authTokenUrl,
                data=json.dumps({"jwt": saToken, "role": roleName}),
                verify=False,
            )

        resp.raise_for_status()

    except requests.exceptions.HTTPError as e:
        log.error(
            "Error while retriving KubeAuth token from vault: {}".format(e)
        )
        log.error(resp.json())
        sys.exit(1)

    return resp.json().get("auth").get("client_token")


# Function to read the secrets from HashiVault path
def getSecretFromHvault(vaultURL, secretPath, k8HvaultToken):

    secretRetrivalurl = vaultURL + secretPath
    headers = {"X-Vault-Token": k8HvaultToken}

    log.debug("Using path to retrieval secret: {}".format(secretRetrivalurl))
    log.debug("Using vault token: {}".format(k8HvaultToken))

    try:
        resp = requests.get(secretRetrivalurl, headers=headers, verify=False)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error("Error while retriving secret from vault: {}".format(e))

    # secretFromHvault=resp.json().get('data')
    return resp.json().get("data")


# Function to read data from from OpenShift ConfigMap
def readDataFromConfigMap(configMapName, namespace):

    log.info("Reading configmap: {}".format(configMapName))

    try:
        v1_cm = dyn_client.resources.get(api_version="v1", kind="ConfigMap")
    except Exception as error:
        log.error("An exception occurred: {}".format(error))
        sys.exit(1)

    try:
        configMapData = v1_cm.get(namespace=namespace, name=configMapName)
    except Exception as error:
        log.error(
            "An exception occurred while reading configmap: {}".format(configMapName)
        )
        log.error(error)
        sys.exit(1)

    configMapData = dict(configMapData.get("data"))
    configMapDataKeys = list(configMapData.keys())

    if len(configMapDataKeys) > 1:
        log.error(
            "ConfigMap: {} has more than one configuration file mentioned".format(
                configMapName
            )
        )
        log.error("Only one configuration file in ConfigMap is allowed")
        log.error("Please correct ConfigMap: {}".format(configMapName))

    return configMapData[configMapDataKeys[0]]


# Function to read from mounted config files
def readDataFromFile(fileName):

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

# Function to validate connection configuration
def validateConfig(configuration_dict):

    connection_keys = [
                "VAULT_ADDR",
                "VAULT_LOGIN_ENDPOINT",
                "VAULT_ROLE",
            ]

    log.debug("Validating confgiration:")
    log.debug(json.dumps(configuration_dict, indent=4))

    # Condition to check for connection configuration 
    if any(elem in connection_keys for elem in configuration_dict.keys()):

        log.debug("Processing vault connection details configuration")

        # get the list of missing keys from configuration 
        missing_keys = [elem for elem in connection_keys if elem not in configuration_dict.keys()]

        # Exit if any mandatory connections keys are missing 
        if len(missing_keys):
            log.error("Required key(s) not found in the configuration")
            log.error("Missing keys: {}".format(missing_keys))
            log.error("Please add above missing keys to proceed")
            sys.exit(1)

        missing_values = [key for key, value in configuration_dict.items() if value is None]

        if len(missing_values):
            log.error("Required value(s) not found in the configuration")
            log.error("Missing values for keys: {}".format(missing_values))
            log.error("Please provide value(s) for above key(s) to proceed")
            sys.exit(1)               

    # Condition to check secrets retrieval 
    elif "KUBE_SECRETS" in configuration_dict.keys() or "FILE_SECRETS" in configuration_dict.keys():

        log.debug("Processing vault secret retrieval configuration")

        # Validation for KUBE_SECRETS and FILE_SECRETS keys in configMap
        if (
            "KUBE_SECRETS" in configuration_dict.keys()
            and "FILE_SECRETS" in configuration_dict.keys()
        ):
            log.error(
                "Both KUBE_SECRETS and FILE_SECRETS cannot be used!!. Please check configuration."
            )
            sys.exit(1)

        if "KUBE_SECRETS" in configuration_dict.keys():

            missing_values_list = []

            for key, value in configuration_dict.items():
                if value is None:
                    log.info("Got an empty configuration, waiting for user to complete configuration")
                    sys.exit(0)
          
                for index, dct in enumerate(value):
                    key = [key for key, value in dct.items() if value is None]
                    if len(key):
                        missing_values_dict = {"keys-position-in-configuration": index, "missing-value-for-key": key}
                        missing_values_list.append(missing_values_dict)

                if len(missing_values_list):
                    log.error("Keys are missing values in configuration")
                    log.debug("List of missing values for keys:{}".format(missing_values_list))

                    for index, elem in enumerate(missing_values_list):
                        log.error("Missing key(s) position in configuration array: {}".format(missing_values_list[index]["keys-position-in-configuration"]))
                        log.error("Key(s) with missing values: {}".format(missing_values_list[index]["missing-value-for-key"]))

                    log.error("Please provide appropriate value for key(s) with missing value(s)")
                    sys.exit(1)


# Function to read the configuration values from OpenShift ConfigMap
def getAdminConfig(configMapName, namespace):

    try:
        configMapData = readDataFromConfigMap(configMapName, namespace)
        controllerConfig = yaml.full_load(configMapData)

        validateConfig(controllerConfig)

        return controllerConfig

    except Exception as e:
        log.error("Error while reading configmap: {}".format(e))
        sys.exit(1)


# Function to get namespace name with in the pod
def getNamespaceName():

    try:
        with open(
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r"
        ) as file:
            return file.read()
    except (OSError, IOError) as e:
        log.error("Error reading from file: {}".format(e))
        sys.exit(1)


# Function to check if a string in base64 encoded or not
def isBase64(str):
    try:
        return base64.b64encode(base64.b64decode(str)).decode() == str
    except Exception:
        return False


# Function to convert a string to base64
def toBase64(str):
    try:
        return base64.b64encode(str.encode("utf-8")).decode()
    except Exception as e:
        log.error("Error while converting a string to base64")
        log.error(e)


# Function to create image pull secret definition
def createImagePullSecretBody(data, secretName):

    # Block to validate if all necessary fields to create image pull secrets are received from vault
    log.info(
        "Validating if all necessary fields to create image pull secrets are received from vault"
    )
    try:
        if (
            "registry-server" in data["data"]
            and "username" in data["data"]
            and "password" in data["data"]
        ):
            log.info(
                "All necessary fields to create image pull secrets are received from vault"
            )
        else:
            log.error(
                "All necessary fields to create image pull secrets are not received from vault"
            )
            log.error("Need registry-server, username and password to proceed")
            log.error("Data received from vault: {}".format(data["data"]))
            log.error("Please check secret definition in vault")
            sys.exit(1)
    except Exception as error:
        log.error(
            "Error while validating for all necessary fields to create image pull secrets"
        )
        log.error(error)
        sys.exit(1)

    log.info("Creating definition for image pull secret: {}".format(secretName))

    cred_payload = {
        "auths": {
            data["data"]["registry-server"]: {
                "Username": data["data"]["username"],
                "Password": data["data"]["password"],
            }
        }
    }

    dockerConfigString = {".dockerconfigjson": toBase64(json.dumps(cred_payload))}

    secretBody = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secretName, "annotations": {"createdBy": "vault-secret-sync"}},
        "type": "kubernetes.io/dockerconfigjson",
        "data": dockerConfigString,
    }

    log.debug("Json definition for image pull secret: {}".format(secretName))
    log.debug(json.dumps(secretBody, indent=4))

    return secretBody


# Function to render Jinja2 template
def renderJinja2Template(secretData, namespace, configMapName=None, templateFile=None):


    if configMapName:
        templateData = readDataFromConfigMap(configMapName, namespace=namespace)
    elif templateFile:
        log.info("Reading jinja2 template from: {}".format(templateFile))
        with open(templateFile, "r") as file:
            templateData = file.read()

    # Display undefined variables as WARNING
    LoggingUndefined = jinja2.make_logging_undefined(logger=log, base=jinja2.Undefined)

    templateEnv = jinja2.Environment(undefined=LoggingUndefined)

    configTemplate = templateEnv.from_string(templateData)

    try:
        renderedTemplate = configTemplate.render(values=secretData)
        return renderedTemplate
    except Exception as error:
        log.error("Error while rendering template")
        log.error(error)
        log.error("Please check your jinja2 templating variables in configmap: {}".format(configMapName))
        log.error("Please avoid to use characters other than \"[a-zA-Z0-9_]\" in jinja2 template variables")
        log.error("Or convert your jinja2 template variables to wrap it with \"values\"")
        log.error("For example - instead of {{ user-name }}, wrap it as {{ values['user-name'] }}")
        sys.exit(1)


# Function to create opaque secret definition based on temmplate
def createOpaqueSecretBodyFromTemplate(
    secretData, secretName, secretFileName, namespace, configMap=None, templateFile=None
):

    if configMap:
        renderedTemplate = renderJinja2Template(
                            secretData["data"],
                            namespace,
                            configMapName=configMap
                        )

    if templateFile: 
       renderedTemplate = renderJinja2Template(
                            secretData["data"],
                            namespace,
                            templateFile=templateFile
                        )

    if renderedTemplate:
        secretBody = {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {"name": secretName, "annotations": {"createdBy": "vault-secret-sync"}},
            "data": {
                secretFileName: toBase64(renderedTemplate)
            },
            "type": "Opaque",
        }

        log.debug("Json definition for opaque secert: {}".format(secretName))
        log.debug(json.dumps(secretBody, indent=4))

        return secretBody


# Function to create opaque secret definition
def createOpaqueSecretBody(secretData, secretName):

    log.info("Creating definition for opaque secret: {}".format(secretName))

    sec_data = {}

    for d in secretData["data"]:
        sec_data[d] = toBase64(secretData["data"][d])

    secretBody = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secretName, "annotations": {"createdBy": "vault-secret-sync"}},
        "data": sec_data,
        "type": "Opaque",
    }

    log.debug("Json definition for opaque secert: {}".format(secretName))
    log.debug(json.dumps(secretBody, indent=4))

    return secretBody


# Function to create TLS secret definition
def createTLSSecretBody(SecretData, secretName):

    # Block to validate if all necessary fields to create TLS secrets are received from vault
    log.info(
        "Validating if all necessary fields to create TLS secrets are received from vault"
    )
    try:
        if "tls.crt" in SecretData["data"] and "tls.key" in SecretData["data"]:
            log.info(
                "All necessary fields to create TLS secrets are received from vault"
            )
        else:
            log.error(
                "All necessary fields to create TLS secrets are not received from vault"
            )
            log.error("Need both tls.crt and tls.key to proceed")
            log.error("Data received from vault: {}".format(SecretData["data"]))
            log.error("Please check secret definition in vault")
            sys.exit(1)
    except Exception as error:
        log.error(
            "Error while validating for all necessary fields to create TLS secrets"
        )
        log.error(error)
        sys.exit(1)

    log.info("Creating definition for TLS secret: {}".format(secretName))

    # Check if the data is already encoded to base64 or not
    if isBase64(SecretData["data"]["tls.crt"]) and isBase64(
        SecretData["data"]["tls.crt"]
    ):
        tlsCrt = SecretData["data"]["tls.crt"]
        tlsKey = SecretData["data"]["tls.key"]
    else:
        tlsCrt = toBase64(SecretData["data"]["tls.crt"])
        tlsKey = toBase64(SecretData["data"]["tls.key"])

    secretBody = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secretName, "annotations": {"createdBy": "vault-secret-sync"}},
        "type": "SecretTypeTLS",
        "data": {"tls.crt": tlsCrt, "tls.key": tlsKey},
    }

    log.debug("Json definition for TLS secret: {}".format(secretName))
    log.debug(json.dumps(secretBody, indent=4))

    return secretBody


# Function to create SSH Auth Secret Definition
def createSshAuthSecretBody(SecretData, secretName):

    log.info("Creating definition for ssh-auth secret: {}".format(secretName))

    # Block to validate if all necessary fields to create ssh-auth secrets are received from vault
    log.info(
        "Validating if all necessary fields to create Ssh Auth secrets are received from vault"
    )

    try:
        if "ssh-privatekey" in SecretData.get("data"):
            log.info("Necessary field to create Ssh Auth secret received from vault")
        else:
            log.error(
                "Necessary field to create Ssh Auth secrets not received from vault"
            )
            sys.exit(1)
    except Exception as error:
        log.error("Error while accessing retrieved secret data")
        log.error(error)
        sys.exit(1)

    # Check if the data is already encoded to base64 or not
    if isBase64(SecretData["data"]["ssh-privatekey"]):
        sshAuthData = SecretData["data"]["ssh-privatekey"]
    else:
        sshAuthData = toBase64(SecretData["data"]["ssh-privatekey"])

    secretBody = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secretName, "annotations": {"createdBy": "vault-secret-sync"}},
        "type": "kubernetes.io/ssh-auth",
        "data": {
            "ssh-privatekey": sshAuthData,
        },
    }

    log.debug("Json definition for SSH Auth secret: {}".format(secretName))
    log.debug(json.dumps(secretBody, indent=4))

    return secretBody


# Function to create secret in ocp
def createSecret(secretBody, secretName, secretType, namespace):

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

    if secretName in secrets_list:
        log.info(
            "Secret: {} exists in Openshift namespace: {}".format(secretName, namespace)
        )
        log.info("Checking if the secret: {} is modified in vault".format(secretName))
        log.info(
            "Get secret: {} definition from OpenShift Container Platform".format(
                secretName
            )
        )

        if secretType == "dockercfg":

            secretFromVault = secretBody["data"][".dockerconfigjson"]
            secretFromOCP = v1_sec.get(namespace=namespace, name=secretName)
            secretFromOCP = secretFromOCP["data"][".dockerconfigjson"]

        elif secretType in ["opaque", "tls", "ssh-auth"]:
            secretFromVault = dict(secretBody.get("data"))
            secretFromOCP = v1_sec.get(namespace=namespace, name=secretName)
            secretFromOCP = dict(secretFromOCP.get("data"))

        log.debug("Secret from Vault: {}".format(secretFromVault))
        log.debug("Secret from OpenShift Container Platform: {}".format(secretFromOCP))

        # Check if the secrets are same. if same, don't update the ocp secret else update
        if secretFromVault == secretFromOCP:
            log.info(
                "Secret: {} from Vault and OpenShift namespace: {} are same, so not updating".format(
                    secretName, namespace
                )
            )
        else:
            log.info(
                "Secret: {} from Vault and OpenShift namespace: {} are not same, so updating".format(
                    secretName, namespace
                )
            )
            # Update the secret if secrets from vault and openshift are different
            try:
                v1_sec.patch(body=secretBody, namespace=namespace)
            except Exception as error:
                log.error("An exception occurred: {}".format(error))
                sys.exit(1)

            log.info(
                "Secret: {} updated in OpenShift namespace: {}".format(
                    secretName, namespace
                )
            )
    else:
        log.info(
            "Secret: {} does not exists, so creating in OpenShift namespace: {}".format(
                secretName, namespace
            )
        )
        try:
            v1_sec.create(body=secretBody, namespace=namespace)
        except Exception as error:
            log.error("An exception occurred: {}".format(error))
            sys.exit(1)

        log.info(
            "Secret: {} created in OpenShift namespace: {}".format(
                secretName, namespace
            )
        )


# Function to write secrets to a file
def writeToFile(secretData, configData, namespace, tempFile=None):

    try:
        if tempFile:
            file = tempFile
        else:
            file = configData.get("TO_FILE_NAME", "secrets.json")

        if "FILE_FORMAT" in configData.keys():

            fileType = configData.get("FILE_FORMAT")

            if "key" in configData.keys() and fileType == "key":
                key = configData["key"]

        elif (
            "FILE_FORMAT" not in configData.keys()
            and "TEMPLATE_AS_CONFIGMAP" not in configData.keys()
            and "TEMPLATE_AS_FILE" not in configData.keys()
        ):
            log.error("Missing required field: file-format")
            sys.exit(1)

        if "TEMPLATE_AS_CONFIGMAP" in configData.keys():

            fileType = "template"
            renderedTemplate = renderJinja2Template(
                secretData,
                namespace,
                configMapName = configData.get("TEMPLATE_AS_CONFIGMAP")             
            )

        if "TEMPLATE_AS_FILE" in configData.keys():

            fileType = "template"
            renderedTemplate = renderJinja2Template(
                secretData,
                namespace,
                templateFile = configData.get("TEMPLATE_AS_FILE")            
            )

    except Exception as error:
        log.error("Invalid configuration recieved")
        log.error("Missing required field: {}".format(error))
        sys.exit(1)

    log.info("Requested file format: {}".format(fileType))

    try:
        with open(file, "w") as f:
            if fileType.lower() == "json":
                json.dump(secretData, f)

            elif fileType.lower() == "yaml":
                yaml.dump(secretData, f)

            elif fileType.lower() == "ini":
                iniConfig = configparser.ConfigParser()
                sectionName = configData.get("INI_SECTION_NAME", "Secrets")

                iniConfig.add_section(sectionName)

                for sKey in secretData:
                    iniConfig.set(sectionName, sKey, secretData[sKey])
                iniConfig.write(f)

            elif fileType.lower() == "key":
                f.write(secretData[key])

            elif fileType.lower() == "template":
                f.write(renderedTemplate)

            elif fileType.lower() == "env":
                for key in secretData.keys():
                    f.write("{}={}\n".format(key, secretData[key]))

            else:
                log.error("Unsupported file format: {}".format(fileType))
                log.error("Please check the configuration")
                sys.exit(1)

        log.info("Secrets written to file: {}".format(file))
        f.close()

    except OSError as e:
        log.error("Error writing to file: {}".format(file))
        log.error(e)
        sys.exit(1)


# Function to get the Hashi vault connection and secret retrieval details
def processInput(userEnvConfig, namespace):

    default_connection_file = userEnvConfig.get("DEFAULT_CONNECTION_INFO_FILE")
    default_secrets_file    = userEnvConfig.get("DEFAULT_SECRETS_RETRIEVAL_INFO_FILE")
    user_connection_file    = userEnvConfig.get("VAULT_CONNECTION_INFO_CONFIG_FILE")
    user_connection_cm      = userEnvConfig.get("VAULT_CONNECTION_INFO_CONFIGMAP_NAME")
    user_secrets_file       = userEnvConfig.get("VAULT_SECRETS_RETRIEVAL_INFO_CONFIG_FILE")
    user_secrets_cm         = userEnvConfig.get("VAULT_SECRETS_RETRIEVAL_INFO_CONFIGMAP_NAME")

    log.debug("Program will use below to get the details in following precedence")
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
    log.debug(
        "User provided vault connection details configmap: {}".format(
            user_connection_cm
        )
    )
    log.debug(
        "User provided vault secrets retrieval details configmap: {}".format(
            user_secrets_cm
        )
    )

    for type in ["connection", "secrets"]:

        eval_default_file = eval("default_" + type + "_file")
        eval_user_file = eval("user_" + type + "_file")
        eval_user_cm = eval("user_" + type + "_cm")

        log.info("Trying to get vault {} details".format(type))

        try:
            if (
                os.path.isfile(eval_default_file)
                and eval_user_file
                and eval_user_cm
            ):

                log.debug(
                    "Based on precedence reading {} details from user provided configmap: {}".format(
                        type, eval_user_cm
                    )
                )
                log.info(
                    "Reading configuration from configmap: {}".format(eval_user_cm)
                )
                globals()[type + "_details"] = getAdminConfig(eval_user_cm, namespace)

            elif (
                not os.path.isfile(eval_default_file)
                and eval_user_file
                and eval_user_cm
            ):

                log.debug(
                    "Based on precedence reading {} details from user provided configmap: {}".format(
                        type, eval_user_cm
                    )
                )
                log.info(
                    "Reading configuration from configmap: {}".format(eval_user_cm)
                )
                globals()[type + "_details"] = getAdminConfig(eval_user_cm, namespace)

            elif (
                os.path.isfile(eval_default_file)
                and eval_user_file
                and not eval_user_cm
            ):

                log.debug(
                    "Based on precedence reading {} details from user provided file: {}".format(
                        type, eval_user_file
                    )
                )
                log.info("Reading configuration from file: {}".format(eval_user_file))
                globals()[type + "_details"] = readDataFromFile(eval_user_file)

            elif (
                not os.path.isfile(eval_default_file)
                and eval_user_file
                and not eval_user_cm
            ):

                log.debug(
                    "Based on precedence reading {} details from user provided file: {}".format(
                        type, eval_user_file
                    )
                )
                log.info("Reading configuration from file: {}".format(eval_user_file))
                globals()[type + "_details"] = readDataFromFile(eval_user_file)

            elif (
                os.path.isfile(eval_default_file)
                and not eval_user_file
                and not eval_user_cm
            ):

                log.debug(
                    "Based on precedence reading {} details from default file: {}".format(
                        type, eval_default_file
                    )
                )
                log.info(
                    "Reading configuration from file: {}".format(eval_default_file)
                )
                globals()[type + "_details"] = readDataFromFile(eval_default_file)

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

    log.debug("Vault connection details:")
    log.debug(json.dumps(connection_details, indent=4))

    log.debug("Vault secrets retrieval details:")
    log.debug(json.dumps(secrets_details, indent=4))

    return connection_details, secrets_details


# Main function
def main():

    # Print ASCII Art Banner
    print(logo.logo)

    # Print effective log level
    log.info("Log Level: {}".format(logging.getLevelName(log.getEffectiveLevel())))

    log.info("Get environment variables")

    # Load configurations from environment
    userEnvConfig = getFromEnv()

    log.info("Get OpenShift namespace")
    namespace = getNamespaceName().strip("\n")
    log.debug("Default Namespace: {}".format(namespace))

    # Call function to get service account token
    log.info("Get OpenShift service account token")

    saToken = getSAToken()

    log.debug("OpenShift Service Account Token: " + saToken)

    while True:

        # Call function processInput to get the hashi vault connection detail
        # and secrets retrieval details based on input
        connection_details, secrets_details = processInput(userEnvConfig, namespace)

        # Validate Connection configuration
        validateConfig(connection_details)

        # Validate secret retrieval configuration 
        validateConfig(secrets_details)

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

            k8HvaultToken = getKubeHvaultAuthToken(
                vault_configmap_contents.get("VAULT_ADDR"),
                vault_configmap_contents.get("VAULT_LOGIN_ENDPOINT"),
                vault_configmap_contents.get("VAULT_ROLE"),
                saToken,
                vault_configmap_contents.get("VAULT_NAMESPACE")
            )

        else:

            k8HvaultToken = getKubeHvaultAuthToken(
                vault_configmap_contents.get("VAULT_ADDR"),
                vault_configmap_contents.get("VAULT_LOGIN_ENDPOINT"),
                vault_configmap_contents.get("VAULT_ROLE"),
                saToken
            )

        log.debug("Got vault KubeAuth token: " + k8HvaultToken)

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

                secretFromHvault = getSecretFromHvault(
                    vault_configmap_contents.get("VAULT_ADDR"),
                    i_secret.get("VAULT_SECRET_PATH"),
                    k8HvaultToken,
                )

                # If secret received from vault
                if secretFromHvault:

                    log.debug("Secret from vault:")
                    log.debug(json.dumps(secretFromHvault,indent=4))

                    # Block for dockercfg (imagepull secrets)
                    if i_secret.get("SECRET_TYPE").lower() == "dockercfg":

                        log.info("Secret type to create is: dockercfg")

                        secretBody = createImagePullSecretBody(
                            secretFromHvault,
                            i_secret.get("KUBERNETES_SECRET")
                        )

                        createSecret(
                            secretBody,
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
                        secretBody = createOpaqueSecretBodyFromTemplate(
                            secretFromHvault,
                            i_secret.get("KUBERNETES_SECRET"),
                            i_secret.get("SECRET_FILE_NAME", "secret.yaml"),
                            namespace,
                            configMap = i_secret.get("TEMPLATE_AS_CONFIGMAP")
                        )

                        createSecret(
                            secretBody,
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


                        secretBody = createOpaqueSecretBodyFromTemplate(
                            secretFromHvault,
                            i_secret.get("KUBERNETES_SECRET"),
                            i_secret.get("SECRET_FILE_NAME", "secret.yaml"),
                            namespace,
                            templateFile = i_secret.get("TEMPLATE_AS_FILE")      
                        )

                        createSecret(
                            secretBody,
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

                        secretBody = createOpaqueSecretBody(
                            secretFromHvault, 
                            i_secret.get("KUBERNETES_SECRET")
                        )

                        createSecret(
                            secretBody,
                            i_secret.get("KUBERNETES_SECRET"),
                            "opaque",
                            namespace,
                        )

                    # Block for TLS secrets
                    elif i_secret.get("SECRET_TYPE").lower() == "tls":

                        log.info("Secret type to create is: tls")

                        secretBody = createTLSSecretBody(
                            secretFromHvault,
                            i_secret.get("KUBERNETES_SECRET")
                        )

                        createSecret(
                            secretBody,
                            i_secret.get("KUBERNETES_SECRET"),
                            "tls",
                            namespace
                        )

                    # Block for ssh-auth secrets
                    elif i_secret.get("SECRET_TYPE").lower() == "ssh-auth":

                        log.info("Secret type to create is: ssh-auth")

                        secretBody = createSshAuthSecretBody(
                            secretFromHvault,
                            i_secret.get("KUBERNETES_SECRET")
                        )

                        createSecret(
                            secretBody,
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

                secretFromHvault = getSecretFromHvault(
                    vault_configmap_contents.get("VAULT_ADDR"),
                    i_secret.get("VAULT_SECRET_PATH"),
                    k8HvaultToken,
                )

                # Block when secret is retrieved from vault
                if secretFromHvault:

                    log.debug("Secret from vault: " + str(secretFromHvault))

                    if os.path.exists(i_secret.get("TO_FILE_NAME")):

                        temp_secrets_file = (
                            "/tmp/" + i_secret.get("TO_FILE_NAME").split("/")[-1]
                        )

                        writeToFile(
                            secretFromHvault.get("data"),
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
                        writeToFile(secretFromHvault["data"], i_secret, namespace)

        # Exit gracefully if RUN_ONCE flag is set to true
        if userEnvConfig.get("RUN_ONCE") in ["true", "yes", "1"]:
            log.info("RUN_ONCE:{} flag was set in environment".format(userEnvConfig.get("RUN_ONCE")))
            log.info("Secrets creation completed")
            log.info("Gracefully exciting")
            sys.exit(0)

        # Refresh Kubernetes secrets 
        refresh_time = vault_configmap_contents.get("VAULT_SECRETS_REFRESH_SECONDS", 3600)
        log.info(
            "Waiting for {} seconds before connecting to vault".format(
                refresh_time
            )
        )

        time.sleep(int(refresh_time))


if __name__ == "__main__":
    main()