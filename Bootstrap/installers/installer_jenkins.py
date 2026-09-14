# Imports
import os
import sys

# Local imports
import constants
from joybox import settings
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Docker compose template
docker_compose_template = """
services:
  jenkins:
    image: ${JENKINS_IMAGE}
    container_name: jenkins
    restart: always
    ports:
      - "${JENKINS_PORT_HTTP}:8080"
      - "${JENKINS_PORT_AGENT}:50000"
    volumes:
      - ${JENKINS_HOME_DIR}:/var/jenkins_home
"""

# .env template
env_template = """
JENKINS_PORT_HTTP={port_http}
JENKINS_PORT_AGENT={port_agent}
JENKINS_HOME_DIR={home_dir}
"""

class Jenkins(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "jenkins"
        self.nginx_config_values = {
            "domain": settings.get_value("UserData.Servers", "domain_name"),
            "subdomain": settings.get_value("UserData.Jenkins", "jenkins_subdomain"),
            "port_http": settings.get_value("UserData.Jenkins", "jenkins_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.Jenkins", "jenkins_port_http"),
            "port_agent": settings.get_value("UserData.Jenkins", "jenkins_port_agent"),
            "home_dir": settings.get_value("UserData.Jenkins", "jenkins_home_dir")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "port_agent", "home_dir"]

        # Backup
        # JENKINS_HOME_DIR points at /mnt/repositories, which also holds every
        # git repo on the box - archiving it to the storage box would be tens
        # of GB. Left unconfigured until it has a dedicated home.
        self.backup_label = "Jenkins"
