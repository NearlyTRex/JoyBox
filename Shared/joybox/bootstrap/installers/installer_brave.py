# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger

# Brave
class Brave(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.url = "https://brave-browser-apt-release.s3.brave.com"
        self.archive_key = "brave-browser-archive-keyring.gpg"
        self.sources_file = "brave-browser.sources"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_path = "/etc/apt/sources.list.d/brave-browser-release.sources"

        # Where earlier installs wrote a one-line source for the same repository
        self.legacy_sources_list_path = "/etc/apt/sources.list.d/brave-browser-release.list"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/brave-browser")

    def install(self):
        logger.log_info("Installing Brave")

        # Brave publishes both the keyring and the deb822 source that names it
        for name, path in [(self.archive_key, self.archive_key_path), (self.sources_file, self.sources_path)]:
            if not self.connection.download_file(f"{self.url}/{name}", path, sudo = True):
                logger.log_error(f"Unable to download {name} from {self.url}")
                return False

        # A second definition of the repository makes apt warn on every update
        self.connection.remove_file_or_directory(self.legacy_sources_list_path, sudo = True)
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "brave-browser"], sudo = True)
        return True

    def uninstall(self):
        logger.log_info("Uninstalling Brave")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "brave-browser"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_path, sudo = True)
        self.connection.remove_file_or_directory(self.legacy_sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return True
