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
import shutil
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from kubernetes import config, client
from openshift.dynamic import DynamicClient
import jinja2


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
    try:
        config["CONTROLLER_CONFIGMAP_NAME"] = os.environ["CONTROLLER_CONFIGMAP_NAME"]
    except KeyError as key:
        log.error("Environment Variable {} not found".format(key))
        sys.exit(1)

    return config


# Function to read the service account token
def getSAToken():

    tokenFile = open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r")
    saToken = tokenFile.read().replace("\n", "")
    tokenFile.close()

    return saToken


# Function to get the KubeAuthToken from HashiVault
def getKubeHvaultAuthToken(vaultURL, loginEP, roleName, saToken, vaultLoginNamespace=None):

    authTokenUrl = vaultURL + loginEP

    try:
        if vaultLoginNamespace:
            resp = requests.post(authTokenUrl, headers={"x-vault-namespace": vaultLoginNamespace}, data=json.dumps({"jwt": saToken, "role": roleName}),
            verify=False)
        else:
            resp = requests.post(authTokenUrl, data=json.dumps({"jwt": saToken, "role": roleName}), verify=False)

        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error(
            "Error retriving Kubernetes Auth Token from Hashi Vault: {}".format(e)
        )
        log.error(resp.json())
        sys.exit(1)

    return resp.json().get("auth").get("client_token")


# Function to read the secrets from HashiVault path
def getSecretFromHvault(vaultURL, secretPath, k8HvaultToken):

    secretRetrivalurl = vaultURL + secretPath
    headers = {"X-Vault-Token": k8HvaultToken}
    try:
        resp = requests.get(secretRetrivalurl, headers=headers, verify=False)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error("Error retriving secret from Hashi Vault: {}".format(e))

    # secretFromHvault=resp.json().get('data')
    return resp.json().get("data")


# Function to read data from from OpenShift ConfigMap
def readDataFromConfigMap(configMapName, namespace):
    try:
        v1_cm = dyn_client.resources.get(api_version="v1", kind="ConfigMap")
    except Exception as error:
        log.error("An exception occurred: {}".format(error))
        sys.exit(1)

    try:
        configMapData = v1_cm.get(namespace=namespace,name=configMapName)
    except Exception as error:
        log.error("An exception occurred while reading configmap: {}".format(configMapName))
        log.error(error)
        sys.exit(1)

    configMapData = dict(configMapData["data"])
    configMapDataKeys = list(configMapData.keys())

    if len(configMapDataKeys) > 1:
        log.error("ConfigMap: {} has more than one configuration file mentioned".format(configMapName))
        log.error("Only one configuration file in ConfigMap is allowed")
        log.error("Please correct ConfigMap: {}".format(configMapName))


    return configMapData[configMapDataKeys[0]]


# Function to read the configuration values from OpenShift ConfigMap
def getControllerConfig(configMapName, namespace):

    try:
        configMapData = readDataFromConfigMap(configMapName, namespace)
        controllerConfig = yaml.full_load(configMapData)

        # Validate the yml for required key
        vaultKeys = ["hashi-vault-url", "vault-login-url-endpoint", "vault-secrets-refresh-seconds", "vault-kube-auth-role-name"]
        for key in vaultKeys:
            if key not in controllerConfig.keys():
                log.error("{} not found!!.Please check configuration.".format(key))
                sys.exit(1)

            # Validation for kube-secrets and file-secrets keys in configMap
        if "kube-secrets" in controllerConfig.keys() and "file-secrets" in controllerConfig.keys():
            log.error("Both kube-secerts and file-secrets cannot be used!!.Please check configuration.")
            sys.exit(1)
        elif "kube-secrets" not in controllerConfig.keys() and "file-secrets" not in controllerConfig.keys():
            log.error("Either kube-secerts or file-secrets needs to be available!!.Please check configuration.")
            sys.exit(1)

        return controllerConfig

    except Exception as e:
        log.error("Error while parsing  controller configmap: {}".format(e))
        sys.exit(1)


# Function to get namespace
def getNamespaceName():

    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as file:
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
        log.error("Error while conevrting a string to base64")
        log.error(e)


# Function to create image pull secret definition
def createImagePullSecretBody(data, secretName):

    # Block to validate if all necessary fields to create image pull secrets are received from vault
    log.info("Validating if all necessary fields to create image pull secrets are received from vault")
    try:
        if "registry-server" in data["data"] and "username" in data["data"] and "password" in data["data"]:
            log.info("All necessary fields to create image pull secrets are received from vault")
        else:
            log.error("All necessary fields to create image pull secrets are not received from vault")
            log.error("Need registry-server, username and password to proceed")
            log.error("Data received from vault: {}".format(data["data"]))
            log.error("Please check secret definition in vault")
            sys.exit(1)
    except Exception as error:
        log.error("Error while validating for all necessary fields to create image pull secrets")
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

    dockerConfigString = { ".dockerconfigjson": toBase64(json.dumps(cred_payload)) }

    secretBody = {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {"name": secretName},
            "type": "kubernetes.io/dockerconfigjson",
            "data": dockerConfigString,
            }

    log.debug("Json definition for image pull secret: {}".format(secretName))
    log.debug(secretBody)

    return secretBody


# Function to create opaque secret definition
def createOpaqueSecretBody(data, secretName):

    log.info("Creating definition for opaque secret: {}".format(secretName))

    sec_data = {}

    for d in data["data"]:
        sec_data[d] = toBase64(data["data"][d])

    secretBody = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secretName},
        "data": sec_data,
        "type": "Opaque"
    }

    log.debug("Json definition for opaque secert: {}".format(secretName))
    log.debug(secretBody)

    return secretBody


# Function to create TLS secret definition
def createTLSSecretBody(data, secretName):

    # Block to validate if all necessary fields to create image pull secrets are received from vault
    log.info("Validating if all necessary fields to create TLS secrets are received from vault")
    try:
        if "tls.crt" in data["data"] and "tls.key" in data["data"]:
            log.info("All necessary fields to create TLS secrets are received from vault")
        else:
            log.error("All necessary fields to create TLS secrets are not received from vault")
            log.error("Need both tls.crt and tls.key to proceed")
            log.error("Data received from vault: {}".format(data["data"]))
            log.error("Please check secret definition in vault")
            sys.exit(1)
    except Exception as error:
        log.error("Error while validating for all necessary fields to create TLS secrets")
        log.error(error)
        sys.exit(1)

    log.info("Creating definition for TLS secret: {}".format(secretName))

    # Check if the data is already encoded to base64 or not
    if isBase64(data["data"]["tls.crt"]) and isBase64(data["data"]["tls.crt"]):
        tlsCrt = data["data"]["tls.crt"]
        tlsKey = data["data"]["tls.key"]
    else:
        tlsCrt = toBase64(data["data"]["tls.crt"])
        tlsKey = toBase64(data["data"]["tls.key"])

    secretBody = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": secretName},     
        "type": "SecretTypeTLS",
        "data": {
            "tls.crt": tlsCrt,
            "tls.key": tlsKey
        }
    }

    log.debug("Json definition for TLS secret: {}".format(secretName))
    log.debug(secretBody)

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
        log.info("Secret: {} exists in Openshift namespace: {}".format(secretName, namespace))
        log.info(
            "Checking if the secret: {} is modified in vault".format(
                secretName
            )
        )
        log.info(
            "Get secret: {} definition from OpenShift Container Platform".format(
                secretName
            )
        )

        if secretType == "opaque":

            secretFromVault = dict(secretBody["data"])
            secretFromOCP = v1_sec.get(
                namespace=namespace, name=secretName
            )
            secretFromOCP = dict(secretFromOCP.data)

        elif secretType == "dockercfg":

            secretFromVault = secretBody["data"][".dockerconfigjson"]
            secretFromOCP = v1_sec.get(
                namespace=namespace, name=secretName
            )
            secretFromOCP = secretFromOCP.data[".dockerconfigjson"]

        elif secretType == "tls":
            secretFromVault = dict(secretBody["data"])
            secretFromOCP = v1_sec.get(
                namespace=namespace, name=secretName
            )
            secretFromOCP = dict(secretFromOCP.data)

        log.debug("Secret from Vault: {}".format(secretFromVault))
        log.debug(
            "Secret from OpenShift Container Platform: {}".format(
                secretFromOCP
            )
        )

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

            log.info("Secret: {} updated in OpenShift namespace: {}".format(secretName, namespace))
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

        log.info("Secret: {} created in OpenShift namespace: {}".format(secretName, namespace))


# Function to write secrets to file
def writeToFile(secret, configData, namespace, tempFile=None):

    try:
        if tempFile:
            file = tempFile
        else:
            file = configData["to-file-name"]

        if "file-format" in configData.keys():
            fileType = configData["file-format"]

            if "key" in configData.keys() and fileType == "key":
                key = configData["key"]

        if "template-as-configmap" in configData.keys():
            fileType = "template"


            configMapData = readDataFromConfigMap(configData["template-as-configmap"], namespace=namespace)

            # Display undefined variables as WARNING
            LoggingUndefined = jinja2.make_logging_undefined(logger=log,base=jinja2.Undefined)

            templateEnv = jinja2.Environment(undefined=LoggingUndefined)

            #configTemplate = Template(configMapData)
            configTemplate = templateEnv.from_string(configMapData)
            renderedTemplate = configTemplate.render(secret)


    except Exception as error:
        log.error("Invalid configuration recieved")
        log.error("Missing required field: {}".format(error))
        sys.exit(1)

    log.info("Requested file format: {}".format(fileType))

    try:
        with open(file, 'w') as f:
            if fileType.lower() == "json":
                json.dump(secret, f)

            elif fileType.lower() == "yaml":
                yaml.dump(secret, f)

            elif fileType.lower() == "ini":
                iniConfig = configparser.ConfigParser()
                if "ini-section-name" in configData.keys():
                    sectionName = configData["ini-section-name"]
                else:
                    sectionName = "Secrets"
                     
                iniConfig.add_section(sectionName)

                for sKey in secret:
                    iniConfig.set(sectionName, sKey, secret[sKey]) 
                iniConfig.write(f)

            elif fileType.lower() == "key":
                f.write(secret[key])

            elif fileType.lower() == "template":
                f.write(renderedTemplate)

            elif fileType.lower() == "env":
                for key in secret.keys():
                    f.write('{}={}\n'.format(key, secret[key]))

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


#Main function
def main():

    # Print ASCII Art Banner
    print(logo.logo)

    # Print effective log level
    log.info("Log Level: {}".format(logging.getLevelName(log.getEffectiveLevel())))

    log.info("Get controller configmap from environment variable")

    # Load configurations from environment
    userEnvConfig = getFromEnv()
    
    log.info("Get OpenShift namespace")
    namespace = getNamespaceName().strip('\n')
    log.debug("Default Namespace: {}".format(namespace))

    # Call function to get service account token
    log.info("Get OpenShift service account token")

    saToken = getSAToken()

    log.debug("OpenShift Service Account Token: " + saToken)

    initContainer = False

    while True:

        log.info(
            "Reading configurations from : {}".format(userEnvConfig["CONTROLLER_CONFIGMAP_NAME"])
        )

        vault_configmap_contents = getControllerConfig(userEnvConfig["CONTROLLER_CONFIGMAP_NAME"], namespace)

        log.debug("Configuration values:")

        for key in vault_configmap_contents:
            log.debug("{}: {}".format(key, vault_configmap_contents[key]))

        # Add trailing '/' is to hashi_vault_url and mount_path_to_write_secrets
        if not vault_configmap_contents["hashi-vault-url"].endswith("/"):
            vault_configmap_contents["hashi-vault-url"] = (
                vault_configmap_contents["hashi-vault-url"] + "/"
            )

        # Call function to get KubeAuth token 
        log.info("Get the Kubernetes auth token from vault")

        if "vault-login-namespace" in vault_configmap_contents.keys():

            k8HvaultToken = getKubeHvaultAuthToken(
                vault_configmap_contents["hashi-vault-url"],
                vault_configmap_contents["vault-login-url-endpoint"],
                vault_configmap_contents["vault-kube-auth-role-name"],
                saToken,
                vault_configmap_contents["vault-login-namespace"]
            )

        else: 

                k8HvaultToken = getKubeHvaultAuthToken(
                vault_configmap_contents["hashi-vault-url"],
                vault_configmap_contents["vault-login-url-endpoint"],
                vault_configmap_contents["vault-kube-auth-role-name"],
                saToken
            )

        log.debug("Hashicorp Vault Kube Auth Token: " + k8HvaultToken)

        # When kube-secret key in ConfigMap
        if "kube-secrets" in vault_configmap_contents.keys():
            for i_secret in vault_configmap_contents["kube-secrets"]:

                # Call function to retrieve secrets from vault
                log.info(
                    "Retrieving secret from vault path: {}".format(
                        i_secret["vault-secret-path"]
                    )
                )

                # get namespace if namespace is defined as tag, 
                # if tag not mentioned, use the namespace (as default) this process is running 
                try:
                    namespace = i_secret["namespace"]
                except:
                    pass

                secretFromHvault = getSecretFromHvault(
                    vault_configmap_contents["hashi-vault-url"],
                    i_secret["vault-secret-path"],
                    k8HvaultToken,
                )

                if secretFromHvault:

                    log.debug("Secret from Hashi Vault: " + str(secretFromHvault))

                    if i_secret["secret-type"].lower() == "dockercfg":

                        log.info("Secret type to create is: dockercfg")

                        secretBody = createImagePullSecretBody(secretFromHvault, i_secret["kubernetes-secret"])

                        createSecret(secretBody,i_secret["kubernetes-secret"], "dockercfg", namespace )

                    elif i_secret["secret-type"].lower() == "opaque":

                        log.info("Secret type to create is: opaque")

                        secretBody = createOpaqueSecretBody(secretFromHvault,i_secret["kubernetes-secret"])

                        createSecret(secretBody,i_secret["kubernetes-secret"], "opaque", namespace )

                    elif i_secret["secret-type"].lower() == "tls":

                        log.info("Secret type to create is: tls")

                        secretBody = createTLSSecretBody(secretFromHvault,i_secret["kubernetes-secret"])

                        createSecret(secretBody,i_secret["kubernetes-secret"], "tls" , namespace)

                else:
                    log.error("Secret could not be retrieved from vault path: {}".format(i_secret["vault-secret-path"]))

        # When file-secret key in ConfigMap
        elif "file-secrets" in vault_configmap_contents.keys():

            if "run-as-app-init-container" in vault_configmap_contents.keys() and vault_configmap_contents["run-as-app-init-container"] == True:
                initContainer = True
                log.info("Running as Application Init container")
            else: 
                initContainer = False
                log.info("Running as Application Side car container")
        
            for i_secret in vault_configmap_contents["file-secrets"]:
                
                # Call function to retrieve secrets from vault
                log.info(
                    "Retrieve secret from vault path: {}".format(
                        i_secret["vault-secret-path"]
                    )
                )

                secretFromHvault = getSecretFromHvault(
                    vault_configmap_contents["hashi-vault-url"],
                    i_secret["vault-secret-path"],
                    k8HvaultToken,
                )

                if secretFromHvault:

                    log.debug("Secret from Hashi Vault: " + str(secretFromHvault))                                     

                    if os.path.exists(i_secret["to-file-name"]):

                        temp_secrets_file = "/tmp/" + i_secret["to-file-name"].split("/")[-1]

                        writeToFile(secretFromHvault["data"], i_secret, namespace,temp_secrets_file)

                        log.info("Comparing two secret files, file: {} and file: {}".format(
                                temp_secrets_file, i_secret["to-file-name"]))

                        if not filecmp.cmp(
                        temp_secrets_file, i_secret["to-file-name"], shallow=False):

                            log.info(
                                "Secrets are different!!, so rendering new secret to file: {}".format(
                                i_secret["to-file-name"]
                                )
                            )
                            shutil.move(temp_secrets_file, i_secret["to-file-name"])

                        else:

                            log.info(
                             "Two secrets in file: {} and file: {} are same. So skipping creating again".format(
                                temp_secrets_file, i_secret["to-file-name"]
                                )
                            )
                            log.info(
                            "Deleting temp file created: {}".format(temp_secrets_file)
                            )
                            os.remove(temp_secrets_file)

                    # when actual secret (i_secret["to-file-name"]) file does not exist
                    else:

                        log.info("Writing secret to {}".format(i_secret["to-file-name"]))
                        writeToFile(secretFromHvault["data"], i_secret, namespace)
                    

        #If initContainer flag is true exit the process gracefully
        if initContainer:
            log.info("Secrets creation completed")
            log.info("Gracefully exciting")
            sys.exit(0)
        log.info(
            "Waiting for {} seconds before connecting to vault".format(
                vault_configmap_contents["vault-secrets-refresh-seconds"]
            )
        )

        time.sleep(int(vault_configmap_contents["vault-secrets-refresh-seconds"]))


if __name__ == "__main__":
 
    main()