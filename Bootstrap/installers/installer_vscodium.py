# Imports
import os
import sys

# Local imports
import util
from . import installer

# VSCodium
class VSCodium(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.gpg_url = "https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/-/raw/master/pub.gpg"
        self.repo_url = "https://paulcarroty.gitlab.io/vscodium-deb-rpm-repo/debs"
        self.archive_key = "vscodium-archive-keyring.gpg"
        self.sources_list = "vscodium.list"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/codium")

    def install(self):
        util.log_info("Installing VSCodium")
        self.connection.download_file(self.gpg_url, "/tmp/vscodium.gpg")
        self.connection.run_checked([self.gpg_tool, "--dearmor", "-o", self.archive_key_path, "/tmp/vscodium.gpg"], sudo = True)
        self.connection.remove_file_or_directory("/tmp/vscodium.gpg")
        self.connection.write_file(f"/tmp/{self.sources_list}", f"deb [signed-by={self.archive_key_path}] {self.repo_url} vscodium main\n")
        self.connection.move_file_or_directory(f"/tmp/{self.sources_list}", self.sources_list_path, sudo = True)
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "codium"], sudo = True)
        return True

    def uninstall(self):
        util.log_info("Uninstalling VSCodium")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "codium"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return True
