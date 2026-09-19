# Imports
import os
import sys
import copy
import datetime

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

        # Compose v2 is invoked as "docker compose" (two words). The v1
        # "docker-compose" binary that get_docker_compose_tool() resolves has
        # been end-of-life since July 2023; docker-compose-v2 is already
        # installed by serverpackages.txt.
        self.docker_compose_command = [self.docker_tool, "compose"]
        self.remote_home = None
        self.nginx_manager_tool = "/usr/local/bin/manager_nginx.sh"
        self.cert_manager_tool = "/usr/local/bin/manager_certbot.sh"
        self.cockpit_manager_tool = "/usr/local/bin/manager_cockpit.sh"

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

    def get_remote_home(self):

        # Resolve the remote home directory once and cache it.
        # Command lists are shlex-quoted, so a literal "$HOME" in a path
        # argument is never expanded by the remote shell.
        if not self.remote_home:
            resolved = self.connection.run_output('printf %s "$HOME"').strip()
            if not resolved:
                logger.log_warning("Unable to resolve remote home, falling back to $HOME")
                resolved = "$HOME"
            self.remote_home = resolved
        return self.remote_home

    def get_app_dir(self):
        return "%s/apps/%s" % (self.get_remote_home(), self.app_name)

    def install_nginx_snippet(self, snippet_name, contents):

        # Snippets are included by server blocks owned by other components,
        # so ownership of the included file can change hands without two
        # server blocks ever claiming the same server_name.
        snippet_tmp_path = f"/tmp/{snippet_name}"
        if self.connection.write_file(snippet_tmp_path, contents):
            self.connection.run_checked([self.nginx_manager_tool, "install_snippet", snippet_tmp_path], sudo = True)
            self.connection.remove_file_or_directory(snippet_tmp_path)
        return True

    def compose_down(self):

        # Stop the compose project. Volumes are preserved unless --purge-data
        # was passed; "down -v" destroys databases and app data.
        app_dir = self.get_app_dir()
        down_command = self.docker_compose_command + ["--env-file", f"{app_dir}/.env", "down"]
        if self.flags.purge_data:
            logger.log_warning(f"Purging data: deleting container volumes for {self.app_name}")
            down_command += ["-v"]
        else:
            logger.log_info(f"Keeping container volumes for {self.app_name} (use --purge-data to delete)")
        self.connection.set_current_working_directory(app_dir)
        self.connection.run_checked(down_command)
        self.connection.set_current_working_directory(None)
        return True

    def retire_app_dir(self):

        # Bind-mounted app data lives inside the app directory, so removing it
        # destroys that data even when the volumes were kept. Rename instead.
        app_dir = self.get_app_dir()
        if self.flags.purge_data:
            logger.log_warning(f"Purging data: removing {app_dir}")
            self.connection.remove_file_or_directory(app_dir)
            return True
        retired_dir = "%s.removed-%s" % (app_dir, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        logger.log_info(f"Preserving app directory, moving to {retired_dir}")
        self.connection.move_file_or_directory(app_dir, retired_dir)
        return True

    def is_installed(self):
        return False

    def get_package_status(self):
        return None

    def install(self):
        return False

    def uninstall(self):
        return False

    def backup(self, tag = ""):
        return True

    def restore(self):
        logger.log_info(f"No restore implemented for {self.__class__.__name__}")
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
