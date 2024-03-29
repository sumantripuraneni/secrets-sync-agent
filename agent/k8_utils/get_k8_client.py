from kubernetes import config, client
from openshift.dynamic import DynamicClient
import sys
import os

def get_client():

    # Check if code is running in OpenShift
    if "KUBERNETES_SERVICE_HOST" in os.environ and "KUBERNETES_SERVICE_PORT" in os.environ:
        config.load_incluster_config()
    else:
        config.load_kube_config()


    # Create a client config
    # Enable TLS communication, use SA CA certificate
    k8s_config = client.Configuration()
    k8s_config.verify_ssl = True
    k8s_config.ssl_ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"   

    # Create K8 and dynamic client instances
    try:
        k8s_client = client.api_client.ApiClient(configuration=k8s_config)
        dyn_client = DynamicClient(k8s_client)
    except Exception as error:
        print("An exception occurred: {}".format(error))
        sys.exit(1)
    
    return dyn_client