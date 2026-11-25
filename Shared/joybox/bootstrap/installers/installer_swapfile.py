# Local imports
import joybox.bootstrap.constants as constants
from joybox import runoptions
from joybox import logger
from . import installer

# Disk swap file, the slower fallback behind zram
SWAPFILE_PATH = "/swapfile"
SWAPFILE_SIZE_GB = 16

# A fixed-size swap file on the root disk, mounted from fstab
class Swapfile(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.path = SWAPFILE_PATH
        self.size_bytes = SWAPFILE_SIZE_GB * 1024 ** 3
        self.fstab_path = "/etc/fstab"
        self.fstab_entry = f"{self.path} none swap sw 0 0"

    # Desktop-only: servers keep their own swap layout
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Size in bytes, or None when the file is missing
    def get_size(self):
        output = self.connection.run_output(["stat", "-c", "%s", self.path]).strip()
        return int(output) if output.isdigit() else None

    # Whether the kernel is swapping to this file right now
    def is_active(self):
        output = self.connection.run_output(["swapon", "--show=NAME", "--noheadings"])
        return self.path in output.split()

    # Current fstab text, or None when it cannot be read (always under pretend)
    def get_fstab(self):
        return self.connection.read_file(self.fstab_path)

    # Whether an uncommented fstab line mounts this file
    def is_in_fstab(self):
        for line in (self.get_fstab() or "").splitlines():
            fields = line.split()
            if fields and fields[0] == self.path:
                return True
        return False

    # Present when the file has the target size and is mounted at boot
    def is_installed(self):
        return self.get_size() == self.size_bytes and self.is_in_fstab()

    # Swap the old file off, then recreate and enable it at the target size
    def resize(self):

        # Release the old file first; its pages move to RAM or zram
        if self.is_active():
            logger.log_info(f"Disabling {self.path}")
            if self.connection.run_blocking(["swapoff", self.path], sudo=True) != 0:
                logger.log_error(f"Failed to disable {self.path}, not enough free memory to take its pages")
                return False

        # Recreate it at the new size
        logger.log_info(f"Creating {SWAPFILE_SIZE_GB} GB swap file at {self.path}")
        commands = [
            ["truncate", "-s", "0", self.path],
            ["fallocate", "-l", f"{SWAPFILE_SIZE_GB}G", self.path],
            ["chmod", "600", self.path],
            ["mkswap", self.path],
            ["swapon", self.path],
        ]
        for command in commands:
            if self.connection.run_blocking(command, sudo=True) != 0:
                logger.log_error(f"Failed to set up {self.path}: {' '.join(command)}")
                return False
        return True

    # Resize the file if needed, then add its fstab line if missing
    def install(self):

        # Start install
        logger.log_info("Installing swap file")

        # Resize the file
        if self.get_size() != self.size_bytes:
            if not self.resize():
                return False

        # Mount it at boot
        if not self.is_in_fstab():
            logger.log_info(f"Adding {self.path} to {self.fstab_path}")
            contents = self.get_fstab()
            if contents is None:
                if not self.flags.pretend_run:
                    logger.log_error(f"Failed to read {self.fstab_path}")
                    return False
                contents = ""
            if contents and not contents.endswith("\n"):
                contents += "\n"
            if not self.connection.write_file(self.fstab_path, contents + self.fstab_entry + "\n", sudo=True):
                logger.log_error(f"Failed to write {self.fstab_path}")
                return False

        # All done
        logger.log_info("Swap file installed successfully")
        return True

    # Keep the file, since the system needs swap without JoyBox too
    def uninstall(self):

        # The system needs swap, so the file stays
        logger.log_info(f"Leaving {self.path} in place")
        return True
