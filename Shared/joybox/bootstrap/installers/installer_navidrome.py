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
  navidrome:
    image: ${NAVIDROME_IMAGE}
    container_name: navidrome
    restart: always
    ports:
      - "127.0.0.1:${NAVIDROME_PORT_HTTP}:4533"
    volumes:
      - ${NAVIDROME_MUSIC_DIR}:/music:ro
      - config_data:/data
    environment:
      - ND_HTTP_PORT=4533
      - ND_BASE_URL=
volumes:
  config_data: {}
"""

# .env template
env_template = """
NAVIDROME_PORT_HTTP={port_http}
NAVIDROME_MUSIC_DIR={music_dir}
"""

# Navidrome Installer
class Navidrome(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "navidrome"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.Navidrome", "navidrome_subdomain"),
            "port_http": settings.get_value("UserData.Navidrome", "navidrome_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.Navidrome", "navidrome_port_http"),
            "music_dir": settings.get_value("UserData.Navidrome", "navidrome_music_dir")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "music_dir"]

        # Backup
        # Only the config volume: the music library is mounted read-only from
        # storage and is not this app's data.
        self.backup_label = "Navidrome"
        self.backup_volumes = ["config_data"]
