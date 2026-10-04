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
from joybox import platform_info

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

# Check whether a package gets a virtual environment of its own
# A tool that pins its dependencies exactly would otherwise move the shared
# venv's packages to the versions it wants.
def is_isolated_package(pkg):
    return isinstance(pkg, dict) and bool(pkg.get("isolated"))

# Get the commands an isolated package puts on the PATH
def get_package_commands(pkg):
    if isinstance(pkg, dict):
        return list(pkg.get("commands", []))
    return []

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

    def get_tools_dir(self):
        tools_dir = settings.get_value("Tools.Python", "python_tools_dir")
        if not tools_dir:
            tools_dir = os.path.join("$HOME", ".local", "share", "joybox", "pytools")
        return os.path.expandvars(tools_dir)

    def get_isolated_venv_dir(self, pkg):
        return os.path.join(self.get_tools_dir(), get_python_package_id(pkg))

    def get_isolated_scripts_dir(self, pkg):
        if platform_info.is_windows_platform():
            return os.path.join(self.get_isolated_venv_dir(pkg), "Scripts")
        return os.path.join(self.get_isolated_venv_dir(pkg), "bin")

    def get_isolated_pip_tool(self, pkg):
        return os.path.join(self.get_isolated_scripts_dir(pkg), settings.get_value("Tools.Python", "python_pip_exe"))

    def get_command_link_dir(self):
        return os.path.join(os.path.expanduser("~"), ".local", "bin")

    def get_pip_tool(self, pkg):
        if is_isolated_package(pkg):
            return self.get_isolated_pip_tool(pkg)
        return self.python_venv_pip_tool

    def get_repo_dir(self):
        return os.path.normpath(environment.get_repo_root(expand = True))

    def is_joybox_installed(self):
        output = self.connection.run_output([self.python_venv_pip_tool, "show", "joybox"]) or ""
        for line in output.splitlines():
            if line.startswith("Editable project location:"):
                location = line.split(":", 1)[1].strip()
                return os.path.normpath(location) == self.get_repo_dir()
        return False

    def install_joybox(self):
        logger.log_info(f"Installing joybox from {self.get_repo_dir()}")
        code = self.connection.run_blocking([
            self.python_venv_pip_tool, "install", "--editable", self.get_repo_dir() + "[dev,decompiler]"])
        return code == 0

    def is_installed(self):
        if not self.is_joybox_installed():
            return False
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            if not self.is_package_installed(pkg_id, self.get_pip_tool(pkg)):
                return False
        return True

    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            pkg_info = get_python_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if self.is_package_installed(pkg_id, self.get_pip_tool(pkg)):
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
        if not self.install_joybox():
            logger.log_error("Unable to install joybox")
            return False

        # Install packages
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            pkg_info = get_python_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if is_isolated_package(pkg):
                installed = self.install_isolated_package(pkg)
            else:
                installed = self.install_package(get_package_spec(pkg))
            if not installed:
                logger.log_error(f"Unable to install package {display_name}")
                return False
        return True

    def uninstall(self):
        logger.log_info("Uninstalling Python packages")
        for pkg in self.get_packages():
            pkg_id = get_python_package_id(pkg)
            pkg_info = get_python_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if is_isolated_package(pkg):
                uninstalled = self.uninstall_isolated_package(pkg)
            else:
                uninstalled = self.uninstall_package(pkg_id)
            if not uninstalled:
                logger.log_error(f"Unable to uninstall package {display_name}")
                return False
        return self.uninstall_package("joybox")

    def create_virtual_environment(self, venv_dir):
        code = self.connection.run_blocking([self.python_tool, "-m", "venv", venv_dir])
        return code == 0

    def is_package_installed(self, package, pip_tool = None):
        code = self.connection.run_blocking([pip_tool or self.python_venv_pip_tool, "show", package])
        return code == 0

    def install_package(self, package):
        spec = package if isinstance(package, list) else [package]
        code = self.connection.run_blocking([self.python_venv_pip_tool, "install", "--upgrade"] + spec)
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "uninstall", "-y", package])
        return code == 0

    def install_isolated_package(self, pkg):
        venv_dir = self.get_isolated_venv_dir(pkg)
        if not self.connection.does_file_or_directory_exist(venv_dir):
            logger.log_info(f"Creating Python virtual environment at {venv_dir}")
            if not self.create_virtual_environment(venv_dir):
                return False
        code = self.connection.run_blocking(
            [self.get_isolated_pip_tool(pkg), "install", "--upgrade"] + get_package_spec(pkg))
        if code != 0:
            return False
        scripts_dir = self.get_isolated_scripts_dir(pkg)
        if platform_info.is_windows_platform():
            return self.connection.add_to_path(scripts_dir)
        link_dir = self.get_command_link_dir()
        for name in get_package_commands(pkg):
            if not self.connection.link_file_or_directory(
                os.path.join(scripts_dir, name), os.path.join(link_dir, name)):
                return False
        return True

    def uninstall_isolated_package(self, pkg):
        if not platform_info.is_windows_platform():
            link_dir = self.get_command_link_dir()
            for name in get_package_commands(pkg):
                link = os.path.join(link_dir, name)
                if self.connection.does_file_or_directory_exist(link):
                    self.connection.remove_file_or_directory(link)
        venv_dir = self.get_isolated_venv_dir(pkg)
        if not self.connection.does_file_or_directory_exist(venv_dir):
            return True
        return self.connection.remove_file_or_directory(venv_dir)
