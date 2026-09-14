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
  audiobookshelf:
    image: ${AUDIOBOOKSHELF_IMAGE}
    container_name: audiobookshelf
    restart: always
    ports:
      - "${AUDIOBOOKSHELF_PORT_HTTP}:80"
    volumes:
      - ${AUDIOBOOKSHELF_AUDIO_DIR}:/audiobooks:ro
      - config_data:/config
      - metadata_data:/metadata
volumes:
  config_data: {}
  metadata_data: {}
"""

# .env template
env_template = """
AUDIOBOOKSHELF_PORT_HTTP={port_http}
AUDIOBOOKSHELF_AUDIO_DIR={audio_dir}
"""

# Audiobookshelf Installer
class Audiobookshelf(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "audiobookshelf"
        self.nginx_config_values = {
            "domain": settings.get_value("UserData.Servers", "domain_name"),
            "subdomain": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_subdomain"),
            "port_http": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_port_http"),
            "audio_dir": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_audio_dir")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template
        self.nginx_config_template = installer_dockerapp.nginx_http_websocket_config_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "audio_dir"]

        # Backup
        # metadata_data is regenerable cached artwork and can be many GB, so
        # it is deliberately not archived.
        self.backup_label = "Audiobookshelf"
        self.backup_volumes = ["config_data"]
