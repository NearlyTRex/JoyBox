# Imports
import os
import re
import tomllib

# Local imports
from joybox.bootstrap import constants
from joybox.bootstrap import packages
from joybox import settings
from joybox import runoptions
from joybox import logger
from joybox import environment
from joybox import platform_info
from joybox import serialization
from joybox import systemtools as tools
from . import installer

# Extras of joybox the venv gets
JOYBOX_EXTRAS = ["dev", "decompiler"]

# Prints the requirements recorded in the installed joybox metadata, one per line
INSTALLED_REQUIREMENTS_SCRIPT = "import importlib.metadata as m; print(chr(10).join(m.requires('joybox') or []))"

# Prints the commands recorded in the installed joybox metadata, as name=target
# lines. pip only writes a command when it installs the package, so one added
# to pyproject.toml since is missing until joybox is installed again.
INSTALLED_COMMANDS_SCRIPT = (
    "import importlib.metadata as m; print(chr(10).join('%s=%s' % (e.name, e.value) "
    "for e in m.distribution('joybox').entry_points if e.group == 'console_scripts'))")

# Get the normalized distribution name of a requirement line
def get_requirement_name(line):
    name = re.split(r"[\s;<>=!~\[@(]", line.strip(), maxsplit = 1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()

# Get the requirement names in a block of requirement lines, ignoring comments
def get_requirement_names(lines):
    names = set()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            names.add(get_requirement_name(line))
    return names

# Extract what pip install receives for a package: its "spec" when it has one,
# such as a git URL or local checkout, else its id; pip show still uses the id
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

# Installs joybox editable into the main venv, then the environment's pip list,
# isolated packages each in their own venv with commands linked into ~/.local/bin
class Python(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

    # Local Ubuntu and local Windows
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.LOCAL_WINDOWS,
        ]

    # The pip entries packages lists for this environment type
    def get_packages(self):
        return packages.python.get(self.get_environment_type(), [])

    # Where isolated venvs live, from Tools.Python, ~/.local/share/joybox/pytools by default
    def get_tools_dir(self):
        tools_dir = settings.get_value("Tools.Python", "python_tools_dir")
        if not tools_dir:
            tools_dir = os.path.join("$HOME", ".local", "share", "joybox", "pytools")
        return os.path.expandvars(tools_dir)

    # The isolated package's own venv under the tools dir, named by its id
    def get_isolated_venv_dir(self, pkg):
        return os.path.join(self.get_tools_dir(), installer.get_package_id(pkg))

    # The isolated venv's bin dir, Scripts on Windows
    def get_isolated_scripts_dir(self, pkg):
        if platform_info.is_windows_platform():
            return os.path.join(self.get_isolated_venv_dir(pkg), "Scripts")
        return os.path.join(self.get_isolated_venv_dir(pkg), "bin")

    # The pip executable in the isolated package's venv
    def get_isolated_pip_tool(self, pkg):
        return os.path.join(self.get_isolated_scripts_dir(pkg), settings.get_value("Tools.Python", "python_pip_exe"))

    # Where isolated package commands are linked, ~/.local/bin
    def get_command_link_dir(self):
        return os.path.join(os.path.expanduser("~"), ".local", "bin")

    # The pip that manages a package: its own venv's when isolated, else the main venv's
    def get_pip_tool(self, pkg):
        if is_isolated_package(pkg):
            return self.get_isolated_pip_tool(pkg)
        return self.python_venv_pip_tool

    # The normalized path of the JoyBox checkout
    def get_repo_dir(self):
        return os.path.normpath(environment.get_repo_root(expand = True))

    # Whether pip show lists joybox as an editable install of this checkout
    def is_joybox_installed(self):
        output = self.connection.run_output([self.python_venv_pip_tool, "show", "joybox"]) or ""
        for line in output.splitlines():
            if line.startswith("Editable project location:"):
                location = line.split(":", 1)[1].strip()
                return os.path.normpath(location) == self.get_repo_dir()
        return False

    # The checkout's pyproject.toml, parsed
    def get_pyproject(self):
        return tomllib.loads(serialization.read_text_file(os.path.join(self.get_repo_dir(), "pyproject.toml")) or "")

    # Requirement names from requirements.in plus the joybox extras the venv gets
    def get_declared_requirement_names(self):
        repo_dir = self.get_repo_dir()
        requirements = serialization.read_text_file(os.path.join(repo_dir, "requirements.in")) or ""
        extras = self.get_pyproject().get("project", {}).get("optional-dependencies", {})
        lines = requirements.splitlines()
        for extra in JOYBOX_EXTRAS:
            lines += extras.get(extra, [])
        return get_requirement_names(lines)

    # Requirement names the installed joybox metadata records
    def get_installed_requirement_names(self):
        output = self.connection.run_output([tools.get_python_venv_python_tool(), "-c", INSTALLED_REQUIREMENTS_SCRIPT]) or ""
        return get_requirement_names(output.splitlines())

    # name=target lines for the console scripts pyproject.toml declares
    def get_declared_commands(self):
        scripts = self.get_pyproject().get("project", {}).get("scripts", {})
        return {"%s=%s" % (name, target) for name, target in scripts.items()}

    # name=target lines for the console scripts the installed joybox metadata records
    def get_installed_commands(self):
        output = self.connection.run_output([tools.get_python_venv_python_tool(), "-c", INSTALLED_COMMANDS_SCRIPT]) or ""
        return {line.strip() for line in output.splitlines() if line.strip()}

    # Whether the installed joybox records the requirements and commands the checkout declares
    def is_joybox_current(self):
        if self.get_installed_requirement_names() != self.get_declared_requirement_names():
            return False
        return self.get_installed_commands() == self.get_declared_commands()

    # pip install the checkout editable with its extras into the main venv; False on failure
    def install_joybox(self):
        logger.log_info(f"Installing joybox from {self.get_repo_dir()}")
        code = self.connection.run_blocking([
            self.python_venv_pip_tool, "install", "--editable",
            self.get_repo_dir() + "[%s]" % ",".join(JOYBOX_EXTRAS)])
        return code == 0

    # Whether joybox is an up-to-date editable install and pip show finds every
    # listed package in the venv that manages it
    def is_installed(self):
        if not self.is_joybox_installed():
            return False
        if not self.is_joybox_current():
            return False
        for pkg in self.get_packages():
            pkg_id = installer.get_package_id(pkg)
            if not self.is_package_installed(pkg_id, self.get_pip_tool(pkg)):
                return False
        return True

    # The listed packages split into installed and missing display names
    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            pkg_id = installer.get_package_id(pkg)
            pkg_info = installer.get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if self.is_package_installed(pkg_id, self.get_pip_tool(pkg)):
                installed.append(display_name)
            else:
                missing.append(display_name)
        return {"installed": installed, "missing": missing}

    # Create the main venv when absent, install joybox into it, then each listed
    # package, isolated ones in their own venv; False at the first failure
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
            pkg_id = installer.get_package_id(pkg)
            pkg_info = installer.get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if is_isolated_package(pkg):
                installed = self.install_isolated_package(pkg)
            else:
                installed = self.install_package(get_package_spec(pkg))
            if not installed:
                logger.log_error(f"Unable to install package {display_name}")
                return False
        return True

    # Uninstall each listed package, deleting isolated venvs and links, then joybox itself
    def uninstall(self):
        logger.log_info("Uninstalling Python packages")
        for pkg in self.get_packages():
            pkg_id = installer.get_package_id(pkg)
            pkg_info = installer.get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if is_isolated_package(pkg):
                uninstalled = self.uninstall_isolated_package(pkg)
            else:
                uninstalled = self.uninstall_package(pkg_id)
            if not uninstalled:
                logger.log_error(f"Unable to uninstall package {display_name}")
                return False
        return self.uninstall_package("joybox")

    # Create a venv at the path with the configured python; False on failure
    def create_virtual_environment(self, venv_dir):
        code = self.connection.run_blocking([self.python_tool, "-m", "venv", venv_dir])
        return code == 0

    # Whether pip show finds the package, using the main venv's pip unless given another
    def is_package_installed(self, package, pip_tool = None):
        code = self.connection.run_blocking([pip_tool or self.python_venv_pip_tool, "show", package])
        return code == 0

    # pip install --upgrade a spec, or spec list, into the main venv; False on failure
    def install_package(self, package):
        spec = package if isinstance(package, list) else [package]
        code = self.connection.run_blocking([self.python_venv_pip_tool, "install", "--upgrade"] + spec)
        return code == 0

    # pip uninstall a package from the main venv; False on failure
    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "uninstall", "-y", package])
        return code == 0

    # Install a package into its own venv and expose its commands: linked into
    # ~/.local/bin, or its Scripts dir added to PATH on Windows; False when a step fails
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

    # Remove an isolated package's command links and delete its venv
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
