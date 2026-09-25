# Imports
import os
import sys

# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger

# Vale (prose linter -- rule-based, no model involved)
#
# Used by promptc for the vocabulary-consistency and banned-phrase checks
# that back PC104. Deterministic and CI-friendly, which is the whole point.
class Vale(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.vale_version = "3.9.1"
        self.vale_binary_path = "/usr/local/bin/vale"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.vale_binary_path)

    def get_package_status(self):
        installed = []
        missing = []
        if self.is_installed():
            installed.append("vale")
        else:
            missing.append("vale")
        return {"installed": installed, "missing": missing}

    def get_release_url(self):
        return (
            f"https://github.com/errata-ai/vale/releases/download/"
            f"v{self.vale_version}/vale_{self.vale_version}_Linux_64-bit.tar.gz")

    def install(self):

        # Start install
        logger.log_info(f"Installing Vale {self.vale_version}")

        # Download the release tarball
        archive_path = "/tmp/vale.tar.gz"
        extract_dir = "/tmp/vale_extract"
        self.connection.download_file(self.get_release_url(), archive_path)

        # Extract
        self.connection.make_directory(extract_dir)
        code = self.connection.run_blocking(
            ["tar", "-xzf", archive_path, "-C", extract_dir])
        if code != 0:
            logger.log_error("Failed to extract Vale archive")
            self.connection.remove_file_or_directory(archive_path)
            return False

        # Move the binary into place
        self.connection.move_file_or_directory(
            os.path.join(extract_dir, "vale"), self.vale_binary_path, sudo = True)
        self.connection.change_permission(self.vale_binary_path, "755", sudo = True)

        # Clean up
        self.connection.remove_file_or_directory(archive_path)
        self.connection.remove_file_or_directory(extract_dir)

        # Verify installation
        logger.log_info("Verifying installation")
        if not self.is_installed():
            logger.log_error("Vale installation verification failed")
            return False

        # All done
        logger.log_info("Vale installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling Vale")

        # Remove binary
        if self.is_installed():
            self.connection.remove_file_or_directory(self.vale_binary_path, sudo = True)

        # All done
        logger.log_info("Vale uninstalled")
        return True
