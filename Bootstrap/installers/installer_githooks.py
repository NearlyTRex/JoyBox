# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import environment

# GitHooks
class GitHooks(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

        # JoyBox path
        self.joybox_root = environment.get_repo_root(expand = True)

        # Hooks paths
        self.hooks_path = ".githooks"
        self.hooks_dir = os.path.join(self.joybox_root, self.hooks_path)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def _get_hooks_path(self):
        return (self.connection.run_output(
            ["git", "-C", self.joybox_root, "config", "--local", "--get", "core.hooksPath"]
        ) or "").strip()

    def is_installed(self):
        return self._get_hooks_path() == self.hooks_path

    def get_package_status(self):
        ok = self.is_installed()
        return {
            "installed": ["core.hooksPath"] if ok else [],
            "missing": [] if ok else ["core.hooksPath"],
        }

    def install(self):

        # Start install
        logger.log_info("Configuring git hooks for the JoyBox repo")

        # The hooks directory must exist in the repo
        if not self.connection.does_file_or_directory_exist(self.hooks_dir):
            logger.log_error(f"Hooks directory not found: {self.hooks_dir}")
            return False

        # Point git at the version-controlled hooks (lives in .git/config, not cloned)
        self.connection.run_checked(
            ["git", "-C", self.joybox_root, "config", "core.hooksPath", self.hooks_path])

        # Verify
        if not self.flags.pretend_run and not self.is_installed():
            logger.log_error("Failed to set core.hooksPath")
            return False

        # All done
        logger.log_info(f"git hooks active (core.hooksPath = {self.hooks_path})")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Unconfiguring git hooks for the JoyBox repo")

        # Remove the setting if present
        if self._get_hooks_path():
            self.connection.run_blocking(
                ["git", "-C", self.joybox_root, "config", "--unset", "core.hooksPath"])

        # All done
        logger.log_info("git hooks deactivated")
        return True
