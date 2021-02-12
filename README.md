# hvault-ocp-secrets-sync

The hvault-ocp-secrets-sync can be used to create and sync secrets from Hashicorp vault to OpenShift. This can also be used as an init/sidecar container to provide secrets to application container.


## Motivation 

There are usecases where we would need secrets from Hashi vault but those secrets needs to be in OpenShift<br>

* ImagePullSecrets <br>
     *  The secrets that are required to connect to artifactory to pull images <br>
* Operator secrets <br>
     *   Some vendor provided operators require Openshift/K8 secrets to function and do not provide an alternative mechansim for injecting 
            confidential data <br>
* Application secrets <br>
     *   Some legacy applications that can not be modified to use/connect to vault applciations <br>
     *   Based on architecture if the applictaions needs to be Hashi vault agnostic
        

## How does it work?
##### OpenShift secrets with in a Namespace

This agent will perform the action of actually connecting to vault and retrieving secrets. It will be injected with a configmap which will give it instructions on - 
hashi vault connection details, what secrets to get from Hashi vault, type of secret to create and name of the secret in OpenShift.

This agent can be used to
    * Create secrets within a namespace as soon as namespace is created
    * Peridically update/sync namespace secrets from Hashi vault 

For now, supported secret types are
    * ImagePullSecrets
    * TLS
    * Opaque 

* Bullet list <br>
     * Nested bullet <br>
           * Sub-nested bullet etc <br>
* Bullet list item 2
