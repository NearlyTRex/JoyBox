# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import settings

# Hermes Agent
#
# Nous Research's agent CLI. Upstream refuses to build wheels, because it finds
# its skills, locales and TUI through the source tree, and its install.sh edits
# shell rc files and apt-installs packages. So it runs from a checkout of a
# pinned release, installed editable into a venv of its own, with the command
# linked into ~/.local/bin. Its data in ~/.hermes is not touched.
class HermesAgent(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.repository_url = "https://github.com/NousResearch/hermes-agent.git"
        self.release = settings.get_value("Tools.HermesAgent", "hermes_agent_release")
        self.install_dir = os.path.expandvars(settings.get_value("Tools.HermesAgent", "hermes_agent_dir"))
        self.source_dir = os.path.join(self.install_dir, "src")
        self.venv_dir = os.path.join(self.install_dir, "venv")
        self.command_path = os.path.join(self.venv_dir, "bin", "hermes")
        self.link_path = os.path.join(os.path.expanduser("~"), ".local", "bin", "hermes")

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.command_path)

    def get_package_status(self):
        if self.is_installed():
            return {"installed": ["hermes-agent"], "missing": []}
        return {"installed": [], "missing": ["hermes-agent"]}

    def fetch_release(self):
        if self.connection.does_file_or_directory_exist(os.path.join(self.source_dir, ".git")):
            logger.log_info(f"Updating Hermes Agent checkout to {self.release}")
            tag = f"refs/tags/{self.release}"
            code = self.connection.run_blocking(
                [self.git_tool, "-C", self.source_dir, "fetch", "--depth", "1", "origin", f"{tag}:{tag}"])
            if code != 0:
                return False
            code = self.connection.run_blocking(
                [self.git_tool, "-C", self.source_dir, "checkout", "--detach", self.release])
            return code == 0
        logger.log_info(f"Cloning Hermes Agent {self.release} into {self.source_dir}")
        self.connection.make_directory(self.install_dir)
        code = self.connection.run_blocking(
            [self.git_tool, "clone", "--depth", "1", "--branch", self.release,
             self.repository_url, self.source_dir])
        return code == 0

    def install(self):

        # Start install
        logger.log_info(f"Installing Hermes Agent {self.release}")

        # Fetch the pinned release
        if not self.fetch_release():
            logger.log_error("Failed to fetch Hermes Agent source")
            return False

        # Create its venv
        if not self.connection.does_file_or_directory_exist(self.venv_dir):
            logger.log_info(f"Creating Python virtual environment at {self.venv_dir}")
            code = self.connection.run_blocking([self.python_tool, "-m", "venv", self.venv_dir])
            if code != 0:
                logger.log_error("Failed to create the Hermes Agent venv")
                return False

        # Install it editable, which is the one build upstream allows
        logger.log_info("Installing Hermes Agent into its venv")
        pip_tool = os.path.join(self.venv_dir, "bin", "pip")
        code = self.connection.run_blocking([pip_tool, "install", "--upgrade", "--editable", self.source_dir])
        if code != 0:
            logger.log_error("Failed to install Hermes Agent")
            return False

        # Verify installation
        logger.log_info("Verifying installation")
        if not self.is_installed():
            logger.log_error("Hermes Agent installation verification failed")
            return False

        # Put the command on the PATH
        if not self.connection.link_file_or_directory(self.command_path, self.link_path):
            logger.log_error(f"Failed to link {self.link_path}")
            return False

        # All done
        logger.log_info("Hermes Agent installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling Hermes Agent")

        # Remove the command and the checkout with its venv
        if self.connection.does_file_or_directory_exist(self.link_path):
            self.connection.remove_file_or_directory(self.link_path)
        if self.connection.does_file_or_directory_exist(self.install_dir):
            if not self.connection.remove_file_or_directory(self.install_dir):
                logger.log_error(f"Failed to remove {self.install_dir}")
                return False

        # Its memory, skills and sessions are the user's, not the install's
        logger.log_info("Hermes Agent data left at ~/.hermes")

        # All done
        logger.log_info("Hermes Agent uninstalled")
        return True
