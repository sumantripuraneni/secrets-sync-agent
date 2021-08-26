# import logging
# import logging.config
import jinja2
import sys

from agent.k8_utils.read_from_configmap import read_data_from_configmap
from agent.utils.define_vars import *
# logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
# log = logging.getLogger("agent")

from agent.utils.get_logger import get_module_logger

log = get_module_logger(__name__)

# Function to render Jinja2 template
def render_jinja2_template(secret_data: dict, namespace: str,
    config_map: str = None, template_file: str = None) -> str:

    '''Function to render provided Jinja2 template'''

    if config_map:
        templateData = read_data_from_configmap(config_map, namespace=namespace)
    elif template_file:
        log.info("Reading jinja2 template from: {}".format(template_file))
        with open(template_file, "r") as file:
            templateData = file.read()

    # Display undefined variables as WARNING
    LoggingUndefined = jinja2.make_logging_undefined(logger=log, base=jinja2.Undefined)

    templateEnv = jinja2.Environment(undefined=LoggingUndefined)

    configTemplate = templateEnv.from_string(templateData)

    try:
        rendered_template = configTemplate.render(values=secret_data)
        return rendered_template
    except Exception as error:
        log.error("Error while rendering template")
        log.error(error)
        log.error("Please check your jinja2 templating variables in configmap: {}".format(config_map))
        sys.exit(1)