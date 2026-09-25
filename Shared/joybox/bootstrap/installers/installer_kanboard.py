# Imports
import os
import sys

# Local imports
import joybox.bootstrap.constants as constants
from joybox import settings
from joybox import serverinfo
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Docker compose template
docker_compose_template = """
services:
  kanboard:
    image: ${KANBOARD_IMAGE}
    container_name: kanboard
    restart: always
    ports:
      - "127.0.0.1:${KANBOARD_PORT_HTTP}:80"
    volumes:
      - ./data:/var/www/app/data
      - ./plugins:/var/www/app/plugins
      - ./config:/var/www/app/config
"""

# .env template
env_template = """
KANBOARD_PORT_HTTP={port_http}
"""

# Kanboard Installer
class Kanboard(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "kanboard"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.Kanboard", "kanboard_subdomain"),
            "port_http": settings.get_value("UserData.Kanboard", "kanboard_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.Kanboard", "kanboard_port_http")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template
        self.app_subdirs = ["data", "plugins", "config"]

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http"]

        # Backup
        self.backup_label = "Kanboard"
        self.backup_dirs = ["data", "plugins", "config"]
