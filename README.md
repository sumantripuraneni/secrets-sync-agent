# hvault-ocp-secrets-sync

The hvault-ocp-secrets-sync can be used to create and update/sync secrets in OpenShift from Hashicorp vault. This can also be used as an init/sidecar container to provide secrets to application container.


## Motivation 

There are usecases where we would need secrets from Hashi vault but those secrets needs to be available in OpenShift<br>

* ImagePullSecrets <br>
     *  The secrets that are required to connect to artifactory to pull images <br>
* Operator secrets <br>
     *   Some vendor provided operators require Openshift/K8 secrets to function and do not provide an alternative mechansim for injecting 
            confidential data <br>
* Application secrets <br>
     *   Some legacy applications that can not be modified to use/connect to Hashi vault <br>
     *   Based on architecture if the applictaions needs to be Hashi vault agnostic
        

## How does it work?
##### OpenShift secrets with in a Namespace

This agent will perform the action of connecting to vault and retrieving secrets. It will be injected with a configmap which will give it instructions on - 
hashi vault connection details, what secrets to get from Hashi vault, type of secret to create and name of the secret in OpenShift.

This agent can be used to<br>
* Create secrets within a namespace as soon as namespace is created
* Peridically update/sync namespace secrets from Hashi vault 

For now, supported secret types are
* ImagePullSecrets
* TLS
* Opaque 


![Alt text](Images/create-namespace-secrets.png?raw=true "Create secret in a namespace")


```yaml
---

kube-secrets:
  - vault-secret-path: v1/secret/data/appsecrets
    kubernetes-secret: demo-appsecrets
    secret-type: opaque

  - vault-secret-path: v1/secret/data/nonprod-registry
    kubernetes-secret: demo-nonprod-registry
    secret-type: dockercfg

  - vault-secret-path: v1/secret/data/prod-registry
    kubernetes-secret: demo-nonprod-registry
    secret-type: dockercfg    

  - vault-secret-path: v1/secret/data/appcerts
    kubernetes-secret: demo-appcerts
    secret-type: tls


##########################
# Vault connection details
###########################

hashi-vault-url: http://10.24.0.1:8200/
vault-login-url-endpoint: v1/auth/suman-hvault-01/login
vault-secrets-refresh-seconds: 3000
vault-kube-auth-role-name: suman-hvault-01
```

##### OpenShift secrets with in a different Namespace

This agent can also be used to create secrets in a different namespace as well, provided serviceaccount used with appropriate rbac policy.

**Recommeded to use a namespace scoped , unless for specirfic reasons or for automations


![Alt text](Images/create-secrets-in-different-namespace.png?raw=true "Create secret in a different namespace ")


```yaml
---

kube-secrets:

  - vault-secret-path: v1/secret/data/nonprod-registry
    kubernetes-secret: demo-nonprod-registry
    secret-type: dockercfg
    namespace: splunk-connect


  - vault-secret-path: v1/secret/data/splunk-hec-token
    kubernetes-secret: splunk-hec-token
    secret-type: opaque
    namespace: splunk-connect


##########################
# Vault connection details
###########################

hashi-vault-url: http://10.24.0.1:8200/
vault-login-url-endpoint: v1/auth/suman-hvault-01/login
vault-secrets-refresh-seconds: 3000
vault-kube-auth-role-name: suman-hvault-01
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
file-secrets:

   -   vault-secret-path: v1/secret/data/appsecrets
       to-file-name: /root/suman/working/test_dir/appsecrets.ini
       file-format: ini
       ini-section-name: app-secrets

   -   vault-secret-path: v1/secret/data/appsecrets
       to-file-name: /root/suman/working/test_dir/appsecrets.json
       file-format: json

   -   vault-secret-path: v1/secret/data/appsecrets
       to-file-name: /root/suman/working/test_dir/appsecrets.yml
       file-format: yaml

   -   vault-secret-path: v1/secret/data/appsecrets
       to-file-name: /root/suman/working/test_dir/appsecrets.env
       file-format: env

   -   vault-secret-path: v1/secret/data/appsecrets
       to-file-name: /root/suman/working/test_dir/appsecrets.txt
       file-format: key
       key: key1

   -   vault-secret-path: v1/secret/data/appsecrets
       to-file-name: /root/suman/working/test_dir/properties.ini
       template-as-configmap: template-testing
       
##########################
# Vault connection details
###########################

hashi-vault-url: http://10.24.0.1:8200/
vault-login-url-endpoint: v1/auth/suman-hvault-01/login
vault-secrets-refresh-seconds: 3000
vault-kube-auth-role-name: suman-hvault-01
```

##### Jinja2 templating ConfigMap
```
spring.datasource.url=jdbc:mysql://{{ mysql_host }}:3306/{{ mysql_db }}
spring.datasource.username={{ mysql_user }}
spring.datasource.password={{ mysql_password }}
```
