# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger

# Claude Code CLI
class Claude(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.claude_binary_path = "/usr/local/bin/claude"
        self.claude_local_bin_path = os.path.expanduser("~/.local/bin/claude")
        self.claude_home_binary_path = os.path.expanduser("~/.claude/local/bin/claude")

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        return (self.connection.does_file_or_directory_exist(self.claude_binary_path) or
                self.connection.does_file_or_directory_exist(self.claude_local_bin_path) or
                self.connection.does_file_or_directory_exist(self.claude_home_binary_path))

    def get_package_status(self):
        installed = []
        missing = []
        if (self.connection.does_file_or_directory_exist(self.claude_binary_path) or
            self.connection.does_file_or_directory_exist(self.claude_local_bin_path) or
            self.connection.does_file_or_directory_exist(self.claude_home_binary_path)):
            installed.append("claude-code")
        else:
            missing.append("claude-code")
        return {"installed": installed, "missing": missing}

    def install(self):

        # Start install
        logger.log_info("Installing Claude Code CLI")

        # Download installer script
        logger.log_info("Downloading Claude Code installer")
        installer_path = "/tmp/claude_install.sh"
        self.connection.download_file("https://claude.ai/install.sh", installer_path)

        # Run installer
        logger.log_info("Running Claude Code installer")
        code = self.connection.run_blocking(["bash", installer_path])
        if code != 0:
            self.connection.remove_file_or_directory(installer_path)
            logger.log_error("Failed to run Claude Code installer")
            return False
        self.connection.remove_file_or_directory(installer_path)

        # Verify installation
        logger.log_info("Verifying installation")
        if not self.is_installed():
            logger.log_error("Claude Code installation verification failed")
            return False

        # All done
        logger.log_info("Claude Code CLI installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling Claude Code CLI")

        # Remove global binary if exists
        if self.connection.does_file_or_directory_exist(self.claude_binary_path):
            logger.log_info("Removing Claude Code global binary")
            self.connection.remove_file_or_directory(self.claude_binary_path, sudo=True)

        # Remove ~/.local/bin binary if exists
        if self.connection.does_file_or_directory_exist(self.claude_local_bin_path):
            logger.log_info("Removing Claude Code local bin binary")
            self.connection.remove_file_or_directory(self.claude_local_bin_path)

        # Remove ~/.claude/local installation directory
        claude_local_dir = os.path.expanduser("~/.claude/local")
        if self.connection.does_file_or_directory_exist(claude_local_dir):
            logger.log_info("Removing Claude Code local installation")
            self.connection.remove_file_or_directory(claude_local_dir)

        # All done
        logger.log_info("Claude Code CLI uninstalled")
        return True
