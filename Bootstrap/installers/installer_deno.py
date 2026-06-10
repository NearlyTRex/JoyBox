# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Deno
class Deno(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.deno_install_dir = os.path.expanduser("~/.deno")
        self.deno_binary_path = os.path.expanduser("~/.deno/bin/deno")

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.deno_binary_path)

    def get_package_status(self):
        installed = []
        missing = []
        if self.connection.does_file_or_directory_exist(self.deno_binary_path):
            installed.append("deno")
        else:
            missing.append("deno")
        return {"installed": installed, "missing": missing}

    def install(self):

        # Start install
        util.log_info("Installing Deno")

        # Download + run the official installer (installs to ~/.deno, adds it to PATH)
        if not self.install_from_script("https://deno.land/install.sh", "deno_install.sh"):
            return False

        # Verify installation
        util.log_info("Verifying installation")
        if not self.is_installed():
            util.log_error("Deno installation verification failed")
            return False

        # All done
        util.log_info("Deno installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling Deno")

        # Remove deno directory (binary + shell rc backups)
        if self.connection.does_file_or_directory_exist(self.deno_install_dir):
            util.log_info("Removing Deno directory")
            self.connection.remove_file_or_directory(self.deno_install_dir)

        # All done
        util.log_info("Deno uninstalled")
        return True
