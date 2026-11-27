# Imports
import os

# Local imports
from joybox import bootstrap
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from joybox import serialization
from . import installer

# User files kept in the repo, under Bootstrap/vscodium; captured by backup and
# deployed by setup, so every machine's editor matches
USER_FILES = [
    "settings.json",
    "keybindings.json",
]

# The extensions, one id per line, as codium --list-extensions prints them
EXTENSIONS_FILE = "extensions.txt"

# Installs VSCodium from its apt repository, then the repo's captured user files and extensions
class VSCodium(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.gpg_url = "https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/-/raw/master/pub.gpg"
        self.repo_url = "https://paulcarroty.gitlab.io/vscodium-deb-rpm-repo/debs"
        self.archive_key = "vscodium-archive-keyring.gpg"
        self.sources_list = "vscodium.list"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"
        self.program_path = "/usr/bin/codium"
        self.captured_dir = os.path.join(bootstrap.get_data_dir(), "vscodium")
        self.user_dir = os.path.join(os.path.expanduser("~"), ".config", "VSCodium", "User")

    # Local Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # A captured file's text from the bootstrap vscodium data dir; None when absent
    def get_captured_file(self, name):
        return serialization.read_text_file(os.path.join(self.captured_dir, name))

    # The extension ids the captured extensions.txt lists
    def get_wanted_extensions(self):
        text = self.get_captured_file(EXTENSIONS_FILE) or ""
        return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]

    # Lowercased ids codium --list-extensions prints
    def get_installed_extensions(self):
        output = self.connection.run_output([self.program_path, "--list-extensions"]) or ""
        return {line.strip().lower() for line in output.splitlines() if line.strip()}

    # The listed extensions codium does not have
    def get_missing_extensions(self):
        installed = self.get_installed_extensions()
        return [extension for extension in self.get_wanted_extensions() if extension.lower() not in installed]

    # A file's text from the VSCodium User dir; None when absent
    def get_user_file(self, name):
        path = os.path.join(self.user_dir, name)
        if not self.connection.does_file_or_directory_exist(path):
            return None
        return self.connection.read_file(path)

    # Names of the user files whose captured copy differs from the one in the User dir
    def get_outdated_user_files(self):
        outdated = []
        for name in USER_FILES:
            captured = self.get_captured_file(name)
            if captured is not None and self.get_user_file(name) != captured:
                outdated.append(name)
        return outdated

    # Whether codium exists with the captured user files and every listed extension
    def is_installed(self):
        if not self.connection.does_file_or_directory_exist(self.program_path):
            return False
        return not self.get_outdated_user_files() and not self.get_missing_extensions()

    # Add the VSCodium apt keyring and source, then apt-get install codium
    def install_program(self):
        logger.log_info("Installing VSCodium")
        self.connection.download_file(self.gpg_url, "/tmp/vscodium.gpg")
        self.connection.run_checked([self.gpg_tool, "--dearmor", "-o", self.archive_key_path, "/tmp/vscodium.gpg"], sudo = True)
        self.connection.remove_file_or_directory("/tmp/vscodium.gpg")
        self.connection.write_file(f"/tmp/{self.sources_list}", f"deb [signed-by={self.archive_key_path}] {self.repo_url} vscodium main\n")
        self.connection.move_file_or_directory(f"/tmp/{self.sources_list}", self.sources_list_path, sudo = True)
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "codium"], sudo = True)

    # Write each outdated captured file into the User dir, saving the first
    # original as .joybox.backup; False when a write fails
    def deploy_user_files(self):
        self.connection.make_directory(self.user_dir)
        for name in self.get_outdated_user_files():
            path = os.path.join(self.user_dir, name)
            backup_path = f"{path}.joybox.backup"
            if self.connection.does_file_or_directory_exist(path) and not self.connection.does_file_or_directory_exist(backup_path):
                self.connection.copy_file_or_directory(path, backup_path)
            logger.log_info(f"Deploying VSCodium {name}")
            if not self.connection.write_file(path, self.get_captured_file(name)):
                logger.log_error(f"Failed to write {path}")
                return False
        return True

    # codium --install-extension each missing extension; False at the first failure
    def install_extensions(self):
        for extension in self.get_missing_extensions():
            logger.log_info(f"Installing VSCodium extension {extension}")
            if self.connection.run_blocking([self.program_path, "--install-extension", extension]) != 0:
                logger.log_error(f"Failed to install VSCodium extension {extension}")
                return False
        return True

    # Install codium when absent, then deploy the user files and missing extensions
    def install(self):
        if not self.connection.does_file_or_directory_exist(self.program_path):
            self.install_program()
        if not self.deploy_user_files():
            return False
        return self.install_extensions()

    # apt-get remove codium and delete its apt source and keyring
    def uninstall(self):
        logger.log_info("Uninstalling VSCodium")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "codium"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return True

    # Capture the User dir files and the installed extension list into the repo's vscodium dir
    def backup(self, tag = ""):
        logger.log_info("Capturing VSCodium settings into the repo")
        self.connection.make_directory(self.captured_dir)
        for name in USER_FILES:
            contents = self.get_user_file(name)
            if contents is None:
                continue
            logger.log_info(f"Capturing VSCodium {name}")
            if not self.connection.write_file(os.path.join(self.captured_dir, name), contents):
                logger.log_error(f"Failed to capture VSCodium {name}")
                return False
        extensions = sorted(self.get_installed_extensions())
        if not self.connection.write_file(
                os.path.join(self.captured_dir, EXTENSIONS_FILE), "".join(extension + "\n" for extension in extensions)):
            logger.log_error("Failed to capture the VSCodium extensions")
            return False
        logger.log_info("Review and commit Bootstrap/vscodium/ to version them")
        return True
