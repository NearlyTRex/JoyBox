# Local imports
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from joybox import platform_info
from . import installer

# VirtualBox (Oracle repo)
class VirtualBox(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.url = "https://download.virtualbox.org/virtualbox/debian"
        self.key_url = "https://www.virtualbox.org/download/oracle_vbox_2016.asc"
        self.archive_key = "oracle-virtualbox-2016.gpg"
        self.sources_list = "oracle-virtualbox.list"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"
        self.package_name = "virtualbox-7.1"

    # Local Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Whether /usr/bin/virtualbox exists
    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/virtualbox")

    # virtualbox-7.1 as installed or missing, by /usr/bin/virtualbox
    def get_package_status(self):
        installed = []
        missing = []
        if self.connection.does_file_or_directory_exist("/usr/bin/virtualbox"):
            installed.append(self.package_name)
        else:
            missing.append(self.package_name)
        return {"installed": installed, "missing": missing}

    # Add Oracle's keyring and apt source for the Ubuntu codename, apt-get install
    # virtualbox-7.1, then check /usr/bin/virtualbox
    def install(self):

        # Start install
        logger.log_info("Installing VirtualBox from Oracle repository")

        # Download and dearmor GPG key
        logger.log_info("Adding Oracle VirtualBox GPG key")
        tmp_key = "/tmp/oracle_vbox_2016.asc"
        self.connection.download_file(self.key_url, tmp_key)
        self.connection.run_checked(
            [self.gpg_tool, "--yes", "--output", self.archive_key_path, "--dearmor", tmp_key],
            sudo=True
        )
        self.connection.remove_file_or_directory(tmp_key)

        # Get Ubuntu codename (uses UBUNTU_CODENAME to handle Mint/derivatives)
        codename = platform_info.get_ubuntu_codename()
        logger.log_info(f"Detected Ubuntu codename: {codename}")

        # Add apt repository
        logger.log_info("Adding Oracle VirtualBox apt repository")
        if not self.connection.write_file(
                f"/tmp/{self.sources_list}",
                f"deb [arch=amd64 signed-by={self.archive_key_path}] {self.url} {codename} contrib\n"):
            logger.log_error(f"Unable to write /tmp/{self.sources_list}")
            return False
        self.connection.move_file_or_directory(f"/tmp/{self.sources_list}", self.sources_list_path, sudo=True)

        # Update and install
        logger.log_info(f"Installing {self.package_name}")
        self.connection.run_checked([self.aptget_tool, "update"], sudo=True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", self.package_name], sudo=True)

        # Verify installation
        if not self.is_installed():
            logger.log_error("VirtualBox installation verification failed")
            return False

        # All done
        logger.log_info("VirtualBox installed successfully")
        return True

    # apt-get remove virtualbox-7.1 and delete its apt source and keyring
    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling VirtualBox")

        # Remove package
        self.connection.run_checked([self.aptget_tool, "remove", "-y", self.package_name], sudo=True)

        # Remove apt sources and key
        self.connection.remove_file_or_directory(self.sources_list_path, sudo=True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo=True)

        # All done
        logger.log_info("VirtualBox uninstalled")
        return True
