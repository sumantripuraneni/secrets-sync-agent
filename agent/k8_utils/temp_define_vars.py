import os
import sys
import logging

K8S_API_ENDPOINT = "https://api.cluster2.XXXXX.com:6443"
ca_cert = "ca.crt"
vault_url = "http://52.116.136.244:8200/"
secret_path = "v1/secret/data/vadim-test"
#k8_hvault_token = ""

# Global Log settings
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    stream=sys.stdout, format="[%(asctime)s] [%(levelname)s] - %(message)s"
)
log = logging.getLogger()
level = logging.getLevelName(log_level)
log.setLevel(log_level)
