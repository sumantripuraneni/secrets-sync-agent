import json
# import logging
# import logging.config
import jinja2
import configparser

from agent.utils.base64_conversions import toBase64
from agent.k8_utils.render_jinja2_template import render_jinja2_template

from agent.utils.define_vars import *

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)
# logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
# log = logging.getLogger("agent")


# Function to create opaque secret definition based on temmplate
def create_opaque_secret_body_from_template(
    secret_data: dict, secret_name: str, secret_file_name: str, namespace: str,
    config_map: str = None, template_file: str = None
) -> dict:

    '''Function to create opaque secret definition based on temmplate '''

    if config_map:
        renderedTemplate = render_jinja2_template(
                            secret_data["data"],
                            namespace,
                            config_map=config_map
                        )

    if template_file: 
        renderedTemplate = render_jinja2_template(
                                secret_data["data"],
                                namespace,
                                template_file=template_file
                            )

    if renderedTemplate:
        secret_body = {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {"name": secret_name, "annotations": {"createdBy": "secrets-sync-agent"}},
            "data": {
                secret_file_name: toBase64(renderedTemplate)
            },
            "type": "Opaque",
        }

        log.debug("Json definition for opaque secert: {}".format(secret_name))
        log.debug(json.dumps(secret_body, indent=4))

        return secret_body
