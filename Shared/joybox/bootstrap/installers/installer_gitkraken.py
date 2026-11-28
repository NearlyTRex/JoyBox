# Local imports
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from . import installer

# Installs GitKraken from its amd64 .deb
class GitKraken(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.download_url = "https://release.gitkraken.com/linux/gitkraken-amd64.deb"
        self.deb_path = "/tmp/gitkraken-amd64.deb"

    # Local Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Whether /usr/bin/gitkraken exists
    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/gitkraken")

    # Download the release .deb to /tmp and apt-get install it
    def install(self):
        logger.log_info("Installing GitKraken")
        self.connection.download_file(self.download_url, self.deb_path)
        self.connection.run_checked([self.aptget_tool, "install", "-y", self.deb_path], sudo = True)
        self.connection.remove_file_or_directory(self.deb_path)
        return True

    # apt-get remove gitkraken
    def uninstall(self):
        logger.log_info("Uninstalling GitKraken")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "gitkraken"], sudo = True)
        return True
