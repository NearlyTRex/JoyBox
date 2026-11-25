# Local imports
import joybox.bootstrap.constants as constants
from joybox import runoptions
from joybox import logger
from . import installer

# Zram generator settings for the compressed in-RAM swap device
# Each setting has: key, value, description
ZRAM_SETTINGS = [
    {
        "key": "zram-size",
        "value": "ram / 2",
        "description": "Half of RAM, holding roughly three times that once compressed",
    },
    {
        "key": "compression-algorithm",
        "value": "zstd",
        "description": "Best ratio for the speed",
    },
    {
        "key": "swap-priority",
        "value": "100",
        "description": "Filled before the disk swap file",
    },
]

# Compressed swap in RAM, set up by systemd's zram generator at every boot
class Zram(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.package = "systemd-zram-generator"
        self.generator_path = "/usr/lib/systemd/system-generators/zram-generator"
        self.conf_path = "/etc/systemd/zram-generator.conf"
        self.device = "zram0"
        self.service = f"systemd-zram-setup@{self.device}"

    # Desktop-only: servers keep their own swap layout
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # The generator config, one [zram0] section built from ZRAM_SETTINGS
    def get_contents(self):
        lines = ["# Managed by JoyBox - do not edit by hand", f"[{self.device}]"]
        for setting in ZRAM_SETTINGS:
            lines.append(f"# {setting['description']}")
            lines.append(f"{setting['key']} = {setting['value']}")
        return "\n".join(lines) + "\n"

    # Present when the generator is installed and the config matches exactly
    def is_installed(self):
        if not self.connection.does_file_or_directory_exist(self.generator_path):
            return False
        if not self.connection.does_file_or_directory_exist(self.conf_path):
            return False
        return self.connection.read_file(self.conf_path, sudo=True) == self.get_contents()

    # Install the generator, write its config and bring the device up
    def install(self):

        # Start install
        logger.log_info("Installing zram swap")

        # Install the generator
        code = self.connection.run_blocking([self.aptget_tool, "install", "-y", self.package], sudo=True)
        if code != 0:
            logger.log_error(f"Failed to install {self.package}")
            return False

        # Write the generator config
        for setting in ZRAM_SETTINGS:
            logger.log_info(f"Setting {setting['key']} = {setting['value']}: {setting['description']}")
        if not self.connection.write_file(self.conf_path, self.get_contents(), sudo=True):
            logger.log_error(f"Failed to write {self.conf_path}")
            return False

        # Bring the device up (an already running device picks up changes at next boot)
        code = self.connection.run_blocking(["systemctl", "daemon-reload"], sudo=True)
        if code != 0:
            logger.log_error("Failed to reload systemd")
            return False
        code = self.connection.run_blocking(["systemctl", "start", self.service], sudo=True)
        if code != 0:
            logger.log_error(f"Failed to start {self.service}")
            return False

        # All done
        logger.log_info("Zram swap installed successfully")
        return True

    # Stop the device and remove both the config and the generator
    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling zram swap")

        # Stop the device, moving its pages back to RAM or the swap file
        self.connection.run_blocking(["systemctl", "stop", self.service], sudo=True)

        # Remove the config and generator
        if self.connection.does_file_or_directory_exist(self.conf_path):
            logger.log_info(f"Removing {self.conf_path}")
            self.connection.remove_file_or_directory(self.conf_path, sudo=True)
        self.connection.run_blocking([self.aptget_tool, "remove", "-y", self.package], sudo=True)
        self.connection.run_blocking(["systemctl", "daemon-reload"], sudo=True)

        # All done
        logger.log_info("Zram swap uninstalled")
        return True
