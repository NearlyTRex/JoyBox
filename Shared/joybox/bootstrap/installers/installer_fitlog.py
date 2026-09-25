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
#
# Compose builds straight from the git tag, so FitLog's own Dockerfile is the
# one that runs. Named volumes rather than bind mounts: with userns-remap the
# container cannot write host directories, while a new volume takes the
# ownership the image gives its mount point. On first start the app clones the
# catalog into its volume, then pulls it on a timer.
docker_compose_template = """
services:
  fitlog:
    build:
      context: ${FITLOG_REPOSITORY}#${FITLOG_VERSION}
    image: fitlog:${FITLOG_VERSION}
    container_name: fitlog
    restart: always
    ports:
      - "127.0.0.1:${FITLOG_PORT_HTTP}:8000"
    volumes:
      - fitlog_state:/data
      - fitlog_catalog:/catalog
    environment:
      FITLOG_CATALOG_URL: ${FITLOG_REPOSITORY}
      FITLOG_CATALOG_BRANCH: ${FITLOG_CATALOG_BRANCH}
      FITLOG_TIMEZONE: ${FITLOG_TIMEZONE}
      FITLOG_PULL_MINUTES: ${FITLOG_PULL_MINUTES}

      # nginx sets X-Real-IP, which the login rate limit keys on.
      FITLOG_TRUST_PROXY: "1"

volumes:
  fitlog_state:
  fitlog_catalog:
"""

# Env template
env_template = """
FITLOG_REPOSITORY={repository}
FITLOG_CATALOG_BRANCH={catalog_branch}
FITLOG_PORT_HTTP={port_http}
FITLOG_TIMEZONE={timezone}
FITLOG_PULL_MINUTES={pull_minutes}
"""

# FitLog Installer
class FitLog(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "fitlog"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.FitLog", "fitlog_subdomain"),
            "port_http": settings.get_value("UserData.FitLog", "fitlog_port_http")
        }
        self.env_values = {
            "repository": "https://github.com/NearlyTRex/FitLog.git",
            "catalog_branch": settings.get_value("UserData.FitLog", "fitlog_catalog_branch",
                default_value = "main", throw_exception = False),
            "port_http": settings.get_value("UserData.FitLog", "fitlog_port_http"),
            "timezone": settings.get_value("UserData.FitLog", "fitlog_timezone",
                default_value = "Etc/UTC", throw_exception = False),
            "pull_minutes": settings.get_value("UserData.FitLog", "fitlog_pull_minutes",
                default_value = "10", throw_exception = False)
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "timezone"]

        # Backup
        # The SQLite database: food log, workout plans, settings and the login.
        # The catalog volume is a clone of the repo, so it is not backed up.
        self.backup_label = "FitLog"
        self.backup_volumes = ["fitlog_state"]

    def post_install(self):

        # The login is created interactively: it prompts for a password and
        # shows the authenticator QR code.
        logger.log_info("FitLog is running. Create the login once, on the server:")
        logger.log_info(f"  cd {self.get_app_dir()} && docker compose exec fitlog fitlog user create <name>")
        return True
