import os
import logging
from agent.k8_utils.get_session_token import get_access_token
from agent.k8_utils.temp_define_vars import *
from agent.hvault.get_secrets_from_hvault_path import get_secret



def main():

#    global ocp_access_token = "wrong"

    ocp_access_token = None
    ocp_access_token = get_access_token(ocp_access_token)
    print(ocp_access_token)

    ocp_access_token = get_access_token(ocp_access_token)
    print(ocp_access_token)    

main()