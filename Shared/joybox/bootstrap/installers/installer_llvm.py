# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import platform_info

# The LLVM release to install from apt.llvm.org, beside the distribution's own clang
LLVM_VERSION = 23

# The LLVM toolchain from LLVM's own apt repository, for a newer clang and libc++ than the
# release ships; its packages carry the version, so they never replace the system clang
class Llvm(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.codename = platform_info.get_ubuntu_codename()
        self.version = LLVM_VERSION
        self.url = "https://apt.llvm.org"
        self.archive_key = "apt.llvm.org.asc"
        self.sources_list = f"llvm-toolchain-{self.codename}-{self.version}.list"
        self.archive_key_path = f"/etc/apt/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"
        self.clang_path = f"/usr/bin/clang++-{self.version}"
        self.packages = [
            f"clang-{self.version}",
            f"clang-format-{self.version}",
            f"clang-tidy-{self.version}",
            f"clang-tools-{self.version}",
            f"lld-{self.version}",
            f"llvm-{self.version}",
            f"libclang-rt-{self.version}-dev",
            f"libc++-{self.version}-dev",
            f"libc++abi-{self.version}-dev",
        ]

    # A development desktop only; servers build nothing with it
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Judged by the versioned clang++, which only this repository provides
    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.clang_path)

    # Adds the signed repository for this Ubuntu release and LLVM version, then the packages
    def install(self):

        # Start install
        logger.log_info(f"Installing LLVM {self.version}")

        # Download GPG key
        logger.log_info("Adding LLVM GPG key")
        self.connection.download_file(f"{self.url}/llvm-snapshot.gpg.key", self.archive_key_path, sudo = True)

        # Add apt repository
        logger.log_info("Adding LLVM apt repository")
        self.connection.write_file(
            f"/tmp/{self.sources_list}",
            f"deb [signed-by={self.archive_key_path}] {self.url}/{self.codename}/ "
            f"llvm-toolchain-{self.codename}-{self.version} main\n"
        )
        self.connection.move_file_or_directory(f"/tmp/{self.sources_list}", self.sources_list_path, sudo = True)

        # Update and install
        logger.log_info("Installing LLVM packages")
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y"] + self.packages, sudo = True)

        # Verify installation
        if not self.is_installed():
            logger.log_error(f"LLVM {self.version} installation verification failed")
            return False

        # All done
        logger.log_info(f"LLVM {self.version} installed successfully")
        return True

    # Removes the packages, then the repository and its key
    def uninstall(self):

        # Start uninstall
        logger.log_info(f"Uninstalling LLVM {self.version}")

        # Remove packages
        self.connection.run_checked([self.aptget_tool, "remove", "-y"] + self.packages, sudo = True)

        # Remove apt sources and key
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)

        # All done
        logger.log_info(f"LLVM {self.version} uninstalled")
        return True
