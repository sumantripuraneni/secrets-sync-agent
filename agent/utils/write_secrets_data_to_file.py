import logging
import logging.config
import configparser
import sys
import json
import yaml
from agent.k8_utils.render_jinja2_template import render_jinja2_template

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)
log = logging.getLogger("agent")


# Function to write secrets to a file
def write_to_file(secret_data, config_data, namespace, temp_file=None):

    try:
        if temp_file:
            file = temp_file
        else:
            file = config_data.get("TO_FILE_NAME", "secrets.json")

        if "FILE_FORMAT" in config_data.keys():

            fileType = config_data.get("FILE_FORMAT")

            if "KEY" in config_data.keys() and fileType == "key":
                key = config_data["KEY"]

        elif (
            "FILE_FORMAT" not in config_data.keys()
            and "TEMPLATE_AS_CONFIGMAP" not in config_data.keys()
            and "TEMPLATE_AS_FILE" not in config_data.keys()
        ):
            log.error("Missing required field: file-format")
            sys.exit(1)

        if "TEMPLATE_AS_CONFIGMAP" in config_data.keys():

            fileType = "template"
            rendered_template = render_jinja2_template(
                secret_data,
                namespace,
                config_map = config_data.get("TEMPLATE_AS_CONFIGMAP")             
            )

        if "TEMPLATE_AS_FILE" in config_data.keys():

            fileType = "template"
            rendered_template = render_jinja2_template(
                secret_data,
                namespace,
                template_file = config_data.get("TEMPLATE_AS_FILE")            
            )

    except Exception as error:
        log.error("Invalid configuration recieved")
        log.error("Missing required field: {}".format(error))
        sys.exit(1)

    log.info("Requested file format: {}".format(fileType))

    try:
        
        with open(file, "w") as f:

            if fileType.lower() == "json":
                json.dump(secret_data, f)

            elif fileType.lower() == "yaml":
                yaml.dump(secret_data, f)

            elif fileType.lower() == "ini":
                iniConfig = configparser.ConfigParser()
                sectionName = config_data.get("INI_SECTION_NAME", "Secrets")

                iniConfig.add_section(sectionName)

                for sKey in secret_data:
                    iniConfig.set(sectionName, sKey, secret_data[sKey])
                iniConfig.write(f)

            elif fileType.lower() == "key":
                f.write(secret_data[key])

            elif fileType.lower() == "template":
                f.write(rendered_template)

            elif fileType.lower() == "env":
                for key in secret_data.keys():
                    f.write("{}={}\n".format(key, secret_data[key]))

            else:
                log.error("Unsupported file format: {}".format(fileType))
                log.error("Please check the configuration")
                sys.exit(1)

        log.info("Secrets written to file: {}".format(file))
        f.close()

    except OSError as e:
        log.error("Error writing to file: {}".format(file))
        log.error(e)
        sys.exit(1)
