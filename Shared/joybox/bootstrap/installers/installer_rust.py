# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.packages as packages
from . import installer
from joybox import runoptions
from joybox import logger

# Extract package identifier from dict
def get_cargo_package_id(pkg):
    return pkg.get("id", pkg.get("name", ""))

# Get display info for a package
def get_cargo_package_info(pkg):
    pkg_id = get_cargo_package_id(pkg)
    return {
        "id": pkg_id,
        "name": pkg.get("name", pkg_id),
        "description": pkg.get("description", ""),
        "category": pkg.get("category", ""),
        "binary": pkg.get("binary", pkg_id),
    }

# Rust (rustup toolchain, targets and cargo-installed crates)
class Rust(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.cargo_bin_dir = os.path.expanduser("~/.cargo/bin")
        self.rustup_tool = os.path.join(self.cargo_bin_dir, "rustup")
        self.cargo_tool = os.path.join(self.cargo_bin_dir, "cargo")

    # Only the local Ubuntu workstation builds Rust
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Crates to cargo install for this environment
    def get_packages(self):
        return packages.cargo.get(self.get_environment_type(), [])

    # Extra rustup compile targets, like x86_64-pc-windows-msvc for cargo-xwin
    def get_targets(self):
        return packages.rust_targets.get(self.get_environment_type(), [])

    # Whether rustup has put cargo in ~/.cargo/bin
    def is_toolchain_installed(self):
        return self.connection.does_file_or_directory_exist(self.cargo_tool)

    # Whether a crate's binary is in ~/.cargo/bin
    def is_package_installed(self, binary):
        return self.connection.does_file_or_directory_exist(os.path.join(self.cargo_bin_dir, binary))

    # Target triples rustup reports as installed
    def get_installed_targets(self):
        return self.connection.run_output([self.rustup_tool, "target", "list", "--installed"]).split()

    # Installed only once the toolchain, every target and every crate are present
    def is_installed(self):
        if not self.is_toolchain_installed():
            return False
        installed_targets = self.get_installed_targets()
        for target in self.get_targets():
            if get_cargo_package_id(target) not in installed_targets:
                return False
        for pkg in self.get_packages():
            if not self.is_package_installed(get_cargo_package_info(pkg)["binary"]):
                return False
        return True

    # The toolchain, targets and crates, split into installed and missing names
    def get_package_status(self):
        installed = []
        missing = []
        installed_targets = []
        if self.is_toolchain_installed():
            installed.append("rust")
            installed_targets = self.get_installed_targets()
        else:
            missing.append("rust")
        for target in self.get_targets():
            target_info = get_cargo_package_info(target)
            if target_info["id"] in installed_targets:
                installed.append(target_info["name"])
            else:
                missing.append(target_info["name"])
        for pkg in self.get_packages():
            pkg_info = get_cargo_package_info(pkg)
            if self.is_package_installed(pkg_info["binary"]):
                installed.append(pkg_info["name"])
            else:
                missing.append(pkg_info["name"])
        return {"installed": installed, "missing": missing}

    # Install or update the stable toolchain, then add missing targets and crates
    def install(self):

        # Install the stable toolchain from rustup (installs to ~/.cargo, adds it to PATH)
        if self.is_toolchain_installed():
            logger.log_info("Updating Rust toolchain")
            if self.connection.run_blocking([self.rustup_tool, "update", "stable"]) != 0:
                logger.log_error("Unable to update Rust toolchain")
                return False
        else:
            logger.log_info("Installing Rust")
            if not self.install_from_script("https://sh.rustup.rs", "rustup_install.sh", args = ["-y"]):
                return False
            if not self.is_toolchain_installed():
                logger.log_error("Rust installation verification failed")
                return False

        # Add targets
        installed_targets = self.get_installed_targets()
        for target in self.get_targets():
            target_info = get_cargo_package_info(target)
            if target_info["id"] in installed_targets:
                continue
            logger.log_info(f"Adding Rust target {target_info['name']}")
            if self.connection.run_blocking([self.rustup_tool, "target", "add", target_info["id"]]) != 0:
                logger.log_error(f"Unable to add Rust target {target_info['name']}")
                return False

        # Install crates
        for pkg in self.get_packages():
            pkg_info = get_cargo_package_info(pkg)
            if self.is_package_installed(pkg_info["binary"]):
                continue
            logger.log_info(f"Installing {pkg_info['name']} via cargo")
            if self.connection.run_blocking([self.cargo_tool, "install", "--locked", pkg_info["id"]]) != 0:
                logger.log_error(f"Unable to install package {pkg_info['name']}")
                return False

        # All done
        logger.log_info("Rust installed successfully")
        return True

    # Remove the toolchain with rustup self uninstall, taking its crates with it
    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling Rust")

        # Removes ~/.cargo (with every crate in it), ~/.rustup and the PATH lines
        if self.connection.does_file_or_directory_exist(self.rustup_tool):
            if self.connection.run_blocking([self.rustup_tool, "self", "uninstall", "-y"]) != 0:
                logger.log_error("Unable to uninstall Rust")
                return False

        # All done
        logger.log_info("Rust uninstalled")
        return True
