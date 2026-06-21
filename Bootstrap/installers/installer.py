# Imports
import os
import sys
import copy

# Local imports
from joybox import systemtools as tools
from joybox import connection
import constants
import joyboxshared
from joybox import runoptions
from joybox import logger
from joybox import platform_info
from joybox import programs
from joybox import settings

# Installer
class Installer:
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):

        # Copy inputs
        self.connection = connection.copy()
        self.flags = flags.copy()
        self.options = options.copy()

        # Setup tools
        if platform_info.is_windows_platform():
            self.winget_tool = tools.get_winget_tool()
        else:
            self.aptget_tool = tools.get_aptget_tool()
            self.aptgetinstall_tool = tools.get_aptget_install_tool()
            self.flatpak_tool = tools.get_flatpak_tool()
        self.python_tool = tools.get_python_tool()
        self.python_venv_pip_tool = tools.get_python_venv_pip_tool()
        self.gpg_tool = programs.get_tool_program("Gpg")
        self.docker_tool = tools.get_docker_tool()
        self.docker_compose_tool = tools.get_docker_compose_tool()
        self.nginx_manager_tool = "/usr/local/bin/manager_nginx.sh"
        self.cert_manager_tool = "/usr/local/bin/manager_certbot.sh"
        self.cockpit_manager_tool = "/usr/local/bin/manager_cockpit.sh"
        self.ghidra_manager_tool = "/usr/local/bin/manager_ghidra.sh"

    def set_environment_type(self, environment_type):
        settings.set_value("UserData.General", "environment_type", environment_type)

    def get_environment_type(self):
        return settings.get_value("UserData.General", "environment_type")

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.LOCAL_WINDOWS,
            constants.EnvironmentType.REMOTE_UBUNTU,
            constants.EnvironmentType.REMOTE_WINDOWS,
        ]

    def supports_environment(self, env_type=None):
        if env_type is None:
            env_type = self.get_environment_type()
        return env_type in self.get_supported_environments()

    def is_installed(self):
        return False

    def get_package_status(self):
        return None

    def install(self):
        return False

    def uninstall(self):
        return False

    def backup(self):
        return True

    def install_from_script(self, url, tmp_name, runner = "sh"):
        tmp_path = f"/tmp/{tmp_name}"
        logger.log_info(f"Downloading installer from {url}")
        self.connection.download_file(url, tmp_path)
        logger.log_info("Running installer script")
        code = self.connection.run_blocking([runner, tmp_path])
        self.connection.remove_file_or_directory(tmp_path)
        if code != 0:
            logger.log_error(f"Installer script failed (exit {code}): {url}")
            return False
        return True
