import urllib3
import requests
from requests_oauthlib import OAuth2Session
from six.moves.urllib_parse import parse_qs, urlencode, urlparse
from agent.hvault.get_secrets_from_hvault_path import get_secret

from agent.utils.define_vars import *

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)


def discover() -> dict:
    
    """Get info to access to authorization APIs"""

    url = f"{K8S_API_ENDPOINT}/.well-known/oauth-authorization-server"
    oauth_server_info = requests.get(url, verify=k8s_ca_cert)

    if oauth_server_info.status_code != 200:
        raise SystemExit("Could not find OpenShift Oauth API")

    return oauth_server_info.json()


def validate_existing_token(token: str) -> bool:

    """Validate if token exist and working. Return True if it works"""

    ocp_access_token = token

    try:
        if ocp_access_token is not None:
            ocp_healthz_url = K8S_API_ENDPOINT + "/healthz"
            ocp_healthz_headers = {
                "Authorization": "Bearer " + ocp_access_token,
                "content-type": "application/json",
            }
            ocp_healthz_query = requests.get(
                ocp_healthz_url, verify=k8s_ca_cert, headers=ocp_healthz_headers
            )
        else:
            log.debug("Token is not defined, need to generate it")
            return False

        if ocp_healthz_query.status_code == 200:
            log.info("Existing token is valid, no need to regenerate it")
            return True
        else:
            log.info("Existing token is not valid, need to regenerate it")
            return False

    except NameError:

        return False


def get_access_token(token: str = None) -> str:

    """Function to get OpenShift Session Token"""

    ocp_custom_creds = get_secret(
        vault_url=vault_configmap_contents.get("VAULT_ADDR"),
        secret_path=secret_path,
        k8_hvault_token=k8_hvault_token,
    )

    if ocp_custom_creds is None:
        log.info(
            "Credentials to work with OCP cluster are not found in Vault, path "
            + secret_path
        )
        log.info("Continue working with OCP cluster using service account token...")
        return
    else:
        ocp_username = ocp_custom_creds["data"]["username"]
        ocp_password = ocp_custom_creds["data"]["password"]

    token_valid = validate_existing_token(token)

    if not token_valid:

        log.info(
            "Existing token is not defined or doesn't work, need to regenerate a new one"
        )

        oauth_server_info = discover()

        log.info(
            "Using following endpoint to get the token - "
            + oauth_server_info["token_endpoint"]
        )

        openshift_token_endpoint = oauth_server_info["token_endpoint"]
        openshift_oauth = OAuth2Session(client_id="openshift-challenging-client")
        authorization_url, state = openshift_oauth.authorization_url(
            oauth_server_info["authorization_endpoint"],
            state="1",
            code_challenge_method="s256",
        )

        auth_headers = urllib3.make_headers(basic_auth=f"{ocp_username}:{ocp_password}")

        # Request authorization code using basic credentials
        challenge_response = openshift_oauth.get(
            authorization_url,
            headers={
                "X-Csrf-Token": state,
                "authorization": auth_headers.get("authorization"),
            },
            verify=k8s_ca_cert,
            allow_redirects=False,
        )

        if challenge_response.status_code != 302:
            raise SystemExit("Authorization failed (Wrong credentials?)")

        qwargs = {
            k: v[0]
            for k, v in parse_qs(
                urlparse(challenge_response.headers["Location"]).query
            ).items()
        }
        qwargs["grant_type"] = "authorization_code"

        # Using authorization code in the Location header of the previous request, request a token
        auth = openshift_oauth.post(
            openshift_token_endpoint,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                # base64 encoded 'openshift-challenging-client:'
                "Authorization": "Basic b3BlbnNoaWZ0LWNoYWxsZW5naW5nLWNsaWVudDo=",
            },
            data=urlencode(qwargs),
            verify=k8s_ca_cert,
        )

        if auth.status_code != 200:
            raise SystemExit("Failed to obtain authorization token")

        log.info(
            "Authorization token to work with OpenShift cluster was successfully obtained"
        )

        return auth.json()["access_token"]


if __name__ == '__main__':

    get_access_token()