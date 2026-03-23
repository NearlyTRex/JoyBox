# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# GitHub CLI
class Gh(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.url = "https://cli.github.com/packages"
        self.archive_key = "githubcli-archive-keyring.gpg"
        self.sources_list = "github-cli.list"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/gh")

    def get_package_status(self):
        installed = []
        missing = []
        if self.connection.does_file_or_directory_exist("/usr/bin/gh"):
            installed.append("gh")
        else:
            missing.append("gh")
        return {"installed": installed, "missing": missing}

    def install(self):

        # Start install
        util.log_info("Installing GitHub CLI")

        # Download GPG key
        util.log_info("Adding GitHub CLI GPG key")
        self.connection.download_file(f"{self.url}/{self.archive_key}", self.archive_key_path, sudo=True)

        # Add apt repository
        util.log_info("Adding GitHub CLI apt repository")
        self.connection.write_file(
            f"/tmp/{self.sources_list}",
            f"deb [arch=amd64 signed-by={self.archive_key_path}] {self.url} stable main\n"
        )
        self.connection.move_file_or_directory(f"/tmp/{self.sources_list}", self.sources_list_path, sudo=True)

        # Update and install
        util.log_info("Installing gh package")
        self.connection.run_checked([self.aptget_tool, "update"], sudo=True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "gh"], sudo=True)

        # Verify installation
        if not self.is_installed():
            util.log_error("GitHub CLI installation verification failed")
            return False

        # All done
        util.log_info("GitHub CLI installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling GitHub CLI")

        # Remove package
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "gh"], sudo=True)

        # Remove apt sources and key
        self.connection.remove_file_or_directory(self.sources_list_path, sudo=True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo=True)

        # All done
        util.log_info("GitHub CLI uninstalled")
        return True
