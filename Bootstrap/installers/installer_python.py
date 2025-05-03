# Imports
import os
import sys

# Local imports
import util
import packages
from . import installer

# Python
class Python(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(config, connection, flags, options)
        self.env = self.config.get("env")
        self.python_packages = packages.python.get(self.env, [])
        self.python_exe = self.config["Tools.Python"]["python_exe"]
        self.python_pip_exe = self.config["Tools.Python"]["python_pip_exe"]
        self.python_install_dir = os.path.expandvars(self.config["Tools.Python"]["python_install_dir"])
        self.python_tool = os.path.join(self.python_install_dir, self.python_exe)
        self.python_venv_dir = os.path.expandvars(self.config["Tools.Python"]["python_venv_dir"])
        self.python_venv_pip_tool = os.path.join(self.python_venv_dir, "bin", self.python_pip_exe)
        if util.IsWindowsPlatform():
            self.python_venv_pip_tool = os.path.join(self.python_venv_dir, "Scripts", self.python_pip_exe)

    def IsInstalled(self):
        for pkg in self.python_packages:
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def Install(self):
        util.LogInfo("Creating virtual environment")
        if not self.CreateVirtualEnvironment(self.python_venv_dir):
            util.LogError("Unable to create virtual environment")
            return False
        util.LogInfo("Installing Python packages")
        for pkg in self.python_packages:
            if not self.InstallPackage(pkg):
                util.LogError(f"Unable to install package {pkg}")
                return False
        return True

    def Uninstall(self):
        util.LogInfo("Removing virtual environment")
        return self.connection.RemoveDirectory(self.python_venv_dir)

    def CreateVirtualEnvironment(self, venv_dir):
        code = self.connection.RunReturncode([self.python_tool, "-m", "venv", venv_dir])
        return code == 0

    def IsPackageInstalled(self, package):
        code = self.connection.RunReturncode([self.python_venv_pip_tool, "show", package])
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.RunReturncode([self.python_venv_pip_tool, "install", "--upgrade", package])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.RunReturncode([self.python_venv_pip_tool, "uninstall", "-y", package])
        return code == 0
