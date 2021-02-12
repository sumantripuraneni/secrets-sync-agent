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


![Alt text](Images/create-namespace-secrets.png?raw=true "Title")


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

