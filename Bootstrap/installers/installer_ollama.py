# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Ollama
class Ollama(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.ollama_binary_path = "/usr/local/bin/ollama"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.ollama_binary_path)

    def get_package_status(self):
        installed = []
        missing = []
        if self.connection.does_file_or_directory_exist(self.ollama_binary_path):
            installed.append("ollama")
        else:
            missing.append("ollama")
        return {"installed": installed, "missing": missing}

    def install(self):

        # Start install
        util.log_info("Installing Ollama")

        # Download + run the official installer
        if not self.install_from_script("https://ollama.com/install.sh", "ollama_install.sh", runner = "bash"):
            return False

        # Verify installation
        util.log_info("Verifying installation")
        if not self.is_installed():
            util.log_error("Ollama installation verification failed")
            return False

        # All done
        util.log_info("Ollama installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling Ollama")

        # Stop ollama service if running
        self.connection.run_blocking(["systemctl", "stop", "ollama"], sudo=True)
        self.connection.run_blocking(["systemctl", "disable", "ollama"], sudo=True)

        # Remove binary
        if self.connection.does_file_or_directory_exist(self.ollama_binary_path):
            util.log_info("Removing Ollama binary")
            self.connection.remove_file_or_directory(self.ollama_binary_path, sudo=True)

        # Remove service file
        service_path = "/etc/systemd/system/ollama.service"
        if self.connection.does_file_or_directory_exist(service_path):
            util.log_info("Removing Ollama service")
            self.connection.remove_file_or_directory(service_path, sudo=True)
            self.connection.run_blocking(["systemctl", "daemon-reload"], sudo=True)

        # Remove ollama user and group
        self.connection.run_blocking(["userdel", "ollama"], sudo=True)
        self.connection.run_blocking(["groupdel", "ollama"], sudo=True)

        # All done
        util.log_info("Ollama uninstalled")
        return True
