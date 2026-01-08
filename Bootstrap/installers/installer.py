# Imports
import os
import sys
import copy

# Local imports
import util
import tools
import connection
import constants

# Installer
class Installer:
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):

        # Copy inputs
        self.config = config.copy()
        self.connection = connection.copy()
        self.flags = flags.copy()
        self.options = options.copy()

        # Setup tools
        if util.is_windows_platform():
            self.winget_tool = tools.get_winget_tool(self.config)
        else:
            self.aptget_tool = tools.get_aptget_tool(self.config)
            self.aptgetinstall_tool = tools.get_aptget_install_tool(self.config)
            self.flatpak_tool = tools.get_flatpak_tool(self.config)
        self.python_tool = tools.get_python_tool(self.config)
        self.python_venv_pip_tool = tools.get_python_venv_pip_tool(self.config)
        self.gpg_tool = tools.get_gpg_tool(self.config)
        self.docker_tool = tools.get_docker_tool(self.config)
        self.docker_compose_tool = tools.get_docker_compose_tool(self.config)
        self.nginx_manager_tool = "/usr/local/bin/manager_nginx.sh"
        self.cert_manager_tool = "/usr/local/bin/manager_certbot.sh"
        self.cockpit_manager_tool = "/usr/local/bin/manager_cockpit.sh"
        self.ghidra_manager_tool = "/usr/local/bin/manager_ghidra.sh"

    def set_environment_type(self, environment_type):
        self.config.set_value("UserData.General", "environment_type", environment_type)

    def get_environment_type(self):
        return self.config.get_value("UserData.General", "environment_type")

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
