# Imports
import os
import sys

# Local imports
import util
from . import installer

# Azuracast
class Azuracast(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(config, connection, flags, options)
        self.app_name = "azuracast"
        self.app_dir = f"/var/{self.app_name}"

    def IsInstalled(self):
        if self.connection.DoesFileOrDirectoryExist(f"{self.app_dir}/docker.sh"):
            return True
        elif self.connection.DoesFileOrDirectoryExist(f"{self.app_dir}/docker-compose.yml"):
            return True
        return False

    def Install(self):
        util.LogInfo("Installing Azuracast")
        self.connection.RunChecked(f"sudo mkdir -p {self.app_dir}")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked("curl -fsSL https://raw.githubusercontent.com/AzuraCast/AzuraCast/main/docker.sh > docker.sh")
        self.connection.RunChecked("chmod a+x docker.sh")
        self.connection.RunChecked("./docker.sh install")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Azuracast")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked("sudo ./docker.sh uninstall")
        self.connection.RunChecked(f"sudo rm -rf {self.app_dir}")
        return False
