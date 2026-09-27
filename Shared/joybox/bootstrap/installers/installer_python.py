# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.packages as packages
from joybox import settings
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import environment
from joybox import systemtools as tools

# Extract package identifier from string or dict
# This is the distribution name, used to query install state with pip show
def get_python_package_id(pkg):
    if isinstance(pkg, str):
        return pkg
    return pkg.get("id", "")

# Extract the arguments pip install should receive for a package
# Defaults to the id, which is right for anything on PyPI. A package with a
# "spec" installs from that instead, so a git URL or a local checkout can be
# used while pip show still queries by the plain distribution name.
def get_package_spec(pkg):
    if isinstance(pkg, str):
        return [pkg]
    spec = pkg.get("spec")
    if not spec:
        return [pkg.get("id", "")]
    if isinstance(spec, str):
        return [spec]
    return [str(part) for part in spec]

# Get display info for a package
def get_python_package_info(pkg):
    if isinstance(pkg, str):
        return {"id": pkg, "name": pkg, "description": "", "category": ""}
    return {
        "id": pkg.get("id", ""),
        "name": pkg.get("name", pkg.get("id", "")),
        "description": pkg.get("description", ""),
        "category": pkg.get("category", "")
    }

# Python
class Python(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.LOCAL_WINDOWS,
        ]

    def get_packages(self):
        return packages.python.get(self.get_environment_type(), [])

    def get_shared_dir(self):
        return os.path.join(environment.get_repo_root(expand = True), "Shared")

    def get_path_file(self):
        site_packages = self.connection.run_output([
            tools.get_python_venv_python_tool(), "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))"]).strip()
        return os.path.join(site_packages, "joybox.pth") if site_packages else None

    def is_path_file_installed(self):
        path_file = self.get_path_file()
        if not path_file or not self.connection.does_file_or_directory_exist(path_file):
            return False
        return (self.connection.read_file(path_file) or "").strip() == self.get_shared_dir()

    def install_path_file(self):
        path_file = self.get_path_file()
        if not path_file:
            logger.log_error("Unable to find the virtual environment's site-packages")
            return False
        logger.log_info(f"Adding {self.get_shared_dir()} to the virtual environment's path")
        return self.connection.write_file(path_file, self.get_shared_dir() + "\n")

    def is_installed(self):
        if not self.is_path_file_installed():
            return False
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            if not self.is_package_installed(pkg_id):
                return False
        return True

    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            pkg_info = get_python_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if self.is_package_installed(pkg_id):
                installed.append(display_name)
            else:
                missing.append(display_name)
        return {"installed": installed, "missing": missing}

    def install(self):
        logger.log_info("Installing Python packages")

        # Get venv directory from config
        venv_dir = settings.get_value("Tools.Python", "python_venv_dir")
        if not venv_dir:
            venv_dir = os.path.expandvars("$HOME/.venv")
        else:
            venv_dir = os.path.expandvars(venv_dir)

        # Create venv if it doesn't exist
        if not self.connection.does_file_or_directory_exist(venv_dir):
            logger.log_info(f"Creating Python virtual environment at {venv_dir}")
            if not self.create_virtual_environment(venv_dir):
                logger.log_error(f"Unable to create virtual environment at {venv_dir}")
                return False
        if not self.install_path_file():
            return False

        # Install packages
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            pkg_info = get_python_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.install_package(get_package_spec(pkg)):
                logger.log_error(f"Unable to install package {display_name}")
                return False
        return True

    def uninstall(self):
        logger.log_info("Uninstalling Python packages")
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            pkg_info = get_python_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.uninstall_package(pkg_id):
                logger.log_error(f"Unable to uninstall package {display_name}")
                return False
        path_file = self.get_path_file()
        if path_file:
            self.connection.remove_file_or_directory(path_file)
        return True

    def create_virtual_environment(self, venv_dir):
        code = self.connection.run_blocking([self.python_tool, "-m", "venv", venv_dir])
        return code == 0

    def is_package_installed(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "show", package])
        return code == 0

    def install_package(self, package):
        spec = package if isinstance(package, list) else [package]
        code = self.connection.run_blocking([self.python_venv_pip_tool, "install", "--upgrade"] + spec)
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "uninstall", "-y", package])
        return code == 0
