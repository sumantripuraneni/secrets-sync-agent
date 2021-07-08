import logging
import logging.config
import jinja2
import configparser

from agent.k8_utils.read_from_configmap import read_data_from_configmap

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
log = logging.getLogger("agent")


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
        log.error("Please avoid to use characters other than \"[a-zA-Z0-9_]\" in jinja2 template variables")
        log.error("Or convert your jinja2 template variables to wrap it with \"values\"")
        log.error("For example - instead of {{ user-name }}, wrap it as {{ values['user-name'] }}")
        sys.exit(1)