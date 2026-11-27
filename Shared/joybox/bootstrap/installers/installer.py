# Local imports
from joybox import systemtools as tools
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from joybox import platform_info
from joybox import programs
from joybox import settings

# Base for a bootstrap component: holds the connection and tool paths and
# defines the install, uninstall and status contract subclasses override
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
        self.git_tool = programs.get_tool_program("Git")
        self.tar_tool = programs.get_tool_program("Tar")
        self.cmake_tool = programs.get_tool_program("Cmake")
        self.unzip_tool = programs.get_tool_program("Unzip")
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

    # Record the environment type in the UserData.General settings
    def set_environment_type(self, environment_type):
        settings.set_value("UserData.General", "environment_type", environment_type)

    # The environment type recorded in the UserData.General settings
    def get_environment_type(self):
        return settings.get_value("UserData.General", "environment_type")

    # The environment types the component runs on; the base allows every local and remote type
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.LOCAL_WINDOWS,
            constants.EnvironmentType.REMOTE_UBUNTU,
            constants.EnvironmentType.REMOTE_WINDOWS,
        ]

    # Whether the component runs on the given environment type, the recorded one when None
    def supports_environment(self, env_type=None):
        if env_type is None:
            env_type = self.get_environment_type()
        return env_type in self.get_supported_environments()

    # The target's home directory, asked of its shell once and cached; a literal $HOME when it cannot say
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

    # Write a file only its owner can read, created that way before anything is
    # in it so the contents are never readable by anyone else
    def write_secret_file(self, path, contents):
        if self.connection.run_return_code(["install", "-m", "600", "/dev/null", path]) != 0:
            return False
        return self.connection.write_file(path, contents)

    # Hand a snippet to the nginx manager to install, by way of a file in /tmp
    def install_nginx_snippet(self, snippet_name, contents):

        # Snippets are included by server blocks owned by other components,
        # so ownership of the included file can change hands without two
        # server blocks ever claiming the same server_name.
        snippet_tmp_path = f"/tmp/{snippet_name}"
        if self.connection.write_file(snippet_tmp_path, contents):
            self.connection.run_checked([self.nginx_manager_tool, "install_snippet", snippet_tmp_path], sudo = True)
            self.connection.remove_file_or_directory(snippet_tmp_path)
        return True

    # Whether the component is present on the target; the base says False
    def is_installed(self):
        return False

    # A status detail for the status report; the base has None
    def get_package_status(self):
        return None

    # Put the component on the target; the base does nothing and returns False
    def install(self):
        return False

    # Take the component off the target; the base does nothing and returns False
    def uninstall(self):
        return False

    # Save the component's data; the base has nothing to save and returns True
    def backup(self, tag = ""):
        del tag
        return True

    # Bring back the component's data; the base only logs that it has none
    def restore(self):
        logger.log_info(f"No restore implemented for {self.__class__.__name__}")
        return True

    # Download an installer script to /tmp, run it with the given runner and
    # arguments, then delete it; False on a nonzero exit
    def install_from_script(self, url, tmp_name, runner = "sh", args = None):
        tmp_path = f"/tmp/{tmp_name}"
        logger.log_info(f"Downloading installer from {url}")
        self.connection.download_file(url, tmp_path)
        logger.log_info("Running installer script")
        code = self.connection.run_blocking([runner, tmp_path] + list(args or []))
        self.connection.remove_file_or_directory(tmp_path)
        if code != 0:
            logger.log_error(f"Installer script failed (exit {code}): {url}")
            return False
        return True
