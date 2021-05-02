# secrets-sync-agent

The secrets-sync-agent can be used to create and update/refresh secrets in OpenShift Container Platform with Hashicorp vault secrets. This can also be used as an init or a sidecar container to provide secrets to an application container.


## Motivation 

There are usecases where we would need secrets from Hashi vault but those secrets needs to be available in OpenShift Container Platform<br>

* ImagePullSecrets <br>
     *  The secrets that are required to connect to artifactory to pull images <br>
* Operator secrets <br>
     *   Some vendor provided operators require Openshift/K8 secrets to function and do not provide an alternative mechansim for injecting 
            confidential data <br>
* Application secrets <br>
     *   Some legacy applications that can not be modified to use/connect to Hashi vault <br>
     *   Based on architecture if the applictaions needs to be Hashi vault agnostic
        

## What type of secrets this agent supports ?

This agent can be used to<br>
* Create secrets within a namespace as soon as namespace is created
* Peridically update/sync namespace secrets from Hashi vault 

For now, supported secret types are
* ImagePullSecrets
* TLS
* Opaque
* Opaque based on template (Jinja2)
* Ssh-Auth


## How does it work?

For deploying the Secrets Sync Agent, as a pre requirement two configMaps are needed - which controls how it functions.

*  The first configMap (secrets-config) contains details of vault instance and configuration used for kubeAuth

    An example 

    ```yaml
    ---
    kind: ConfigMap
    apiVersion: v1
    metadata:
      name: secrets-config
    data:
      vault_connection_info.yaml: |
        ---
        VAULT_ADDR: http://52.116.136.244:8200/
        VAULT_LOGIN_ENDPOINT: v1/auth/kubernetes/login
        VAULT_ROLE: suman-test
    ```

*  The second configMap (secrets-data) contains details of which secrets to retrieve from vault, name of the secret to create and type of secrets to create
    An example

    ```yaml
    ---
    kind: ConfigMap
    apiVersion: v1
    metadata:
      name: secrets-data
    data:
      vault_secrets_info.yaml: |
        ---
        KUBE_SECRETS:
           - VAULT_SECRET_PATH: v1/secret/data/appsecrets
             KUBERNETES_SECRET: demo-appsecrets
             SECRET_TYPE: opaque

           - VAULT_SECRET_PATH: v1/secret/data/appsecrets
             KUBERNETES_SECRET: demo-appsecrets-template
             SECRET_TYPE: opaque
             TEMPLATE_AS_CONFIGMAP: template-testing

           - VAULT_SECRET_PATH: v1/secret/data/nonprod-registry
             KUBERNETES_SECRET: suman-test-template
             SECRET_TYPE: dockercfg

           - VAULT_SECRET_PATH: v1/secret/data/certs
             KUBERNETES_SECRET: demo-appcerts
             SECRET_TYPE: tls

           - VAULT_SECRET_PATH: v1/secret/data/auth
             KUBERNETES_SECRET: demo-ssh-auth
             SECRET_TYPE: ssh-auth
    ```    
 
We can provide connection and secret retrieval information in multiple ways


| Name              | Default Value | Description |
| :--- | :---  | :---  |
| DEFAULT_CONNECTION_INFO_FILE | /etc/secrets_sync_agent/connection_info/vault_connection_info.yaml | Users need to mount the connection information configuration file in this location and program will automatically pick this file|
| DEFAULT_SECRETS_RETRIEVAL_INFO_FILE | /etc/secrets_sync_agent/secrets_info/vault_secrets_info.yaml | Users need to mount the secrets retrieval information configuration file in this location and program will automatically pick this file|
| VAULT_CONNECTION_INFO_CONFIG_FILE | - | User can mount connection information configuration file to any location and provide absolute file location|
| VAULT_SECRETS_RETRIEVAL_INFO_CONFIG_FILE | - | User can mount secrets retrieval information configuration file to any location and provide absolute file location
| VAULT_CONNECTION_INFO_CONFIGMAP_NAME | - | Name of a configmap with connection information. This requires API access to read configmap |
| VAULT_SECRETS_RETRIEVAL_INFO_CONFIGMAP_NAME | - | Name of a configmap with secrets retrieval information.. This requires API access to read configmap|


###### Variable Definition Precendence

The above mechanisms for providing configuration values can be used together in any combination. If the same configuration is assigned multiple values, agent uses the configuration with highest precedence

Agent loads configuration in the following order, with later sources taking precedence over earlier ones
* Default configuration (DEFAULT_CONNECTION_INFO_FILE and DEFAULT_SECRETS_RETRIEVAL_INFO_FILE)
* User explictly provided configuration (VAULT_CONNECTION_INFO_CONFIG_FILE and VAULT_SECRETS_RETRIEVAL_INFO_CONFIG_FILE)
* ConfigMap (VAULT_CONNECTION_INFO_CONFIGMAP_NAME and VAULT_SECRETS_RETRIEVAL_INFO_CONFIGMAP_NAME) 


##### OpenShift secrets with in a Namespace

This agent can be used to create/refresh OpenShift/K8 platform secrets in the sanem namespace. Aformentioned two configMaps are to create/refresh secrets in a namespace where this agent is running.

<<Insert image here>>>


![Alt text](Images/create-namespace-secrets.png?raw=true "Create secret in a namespace")



##### OpenShift secrets with in a different Namespace

This agent can also be used to create secrets in a different namespace as well, provided serviceaccount used with appropriate rbac policy.


**Recommeded to use a namespace scoped , unless for specific reasons or for automations


![Alt text](Images/create-secrets-in-different-namespace.png?raw=true "Create secret in a different namespace ")


```yaml
---
KUBE_SECRETS:
  - VAULT_SECRET_PATH: v1/secret/data/nonprod-registry
    KUBERNETES_SECRET: demo-nonprod-registry
    SECRET_TYPE: dockercfg
    NAMESPACE: splunk-connect


  - VAULT_SECRET_PATH: v1/secret/data/splunk-hec-token
    KUBERNETES_SECRET: splunk-hec-token
    SECRET_TYPE: opaque
    NAMESPACE: splunk-connect
```

##### Init/Sidecar container

This agent can also be used as an init or sidecar conatiner, which will connect to Hashi vault, retrieve secrets and creates file based secrets.  Agent will be 
injected with a configmap which will give it instructions on - hashi vault connection details, what secrets to get from Hashi vault (path), type of file format and where to place them. The agent will closely emulate the functionality of hashi vault agent. The most common pattern is to use this agent as a init-container for an application, at startup this agent will grab secrets from vault and place them in a emptyDir (suggested: memory medium) which is mounted to both the containers. If the secrets needs to be updated when they chnage in thevault without restarting an application conatienr, then this agent can also be used a side car, which will keep the secrets in the emptyDir mount point upto date. However, its application responsibility to act when the secrets are changed in emptyDir mount point.


![Alt text](Images/init-or-sidecar-container.png?raw=true "Init or side car container")


**Recommneded to used emptyDir with medium memory to avoid writing secrets to host disk

```yaml
volumes:
  - name: application-secrets
    emptyDir:
      medium: Memory
```

Agent can provide scerets in various file formats such as
*  Json 
*  Yaml
*  Ini
*  env(KV pairs)
*  a single value to file based on selected key
*  Jinja2 template

```yaml
---
FILE_SECRETS:
   -   VAULT_SECRET_PATH: v1/secret/data/appsecrets
       TO_FILE_NAME: /root/suman/working/test_dir/appsecrets.ini
       FILE_FORMAT: ini
       INI_SECTION_NAME: app-secrets

   -   VAULT_SECRET_PATH: v1/secret/data/appsecrets
       TO_FILE_NAME: /root/suman/working/test_dir/appsecrets.json
       FILE_FORMAT: json

   -   VAULT_SECRET_PATH: v1/secret/data/appsecrets
       TO_FILE_NAME: /root/suman/working/test_dir/appsecrets.yml
       FILE_FORMAT: yaml

   -   VAULT_SECRET_PATH: v1/secret/data/appsecrets
       TO_FILE_NAME: /root/suman/working/test_dir/appsecrets.env
       FILE_FORMAT: env

   -   VAULT_SECRET_PATH: v1/secret/data/appsecrets
       TO_FILE_NAME: /root/suman/working/test_dir/appsecrets.txt
       FILE_FORMAT: key
       KEY: key1

   -   VAULT_SECRET_PATH: v1/secret/data/appsecrets
       TO_FILE_NAME: /root/suman/working/test_dir/properties.ini
       TEMPLATE_AS_CONFIGMAP: template-testing
```

##### Jinja2 templating ConfigMap
```
spring.datasource.url=jdbc:mysql://{{ mysql_host }}:3306/{{ mysql_db }}
spring.datasource.username={{ mysql_user }}
spring.datasource.password={{ mysql_password }}
```
