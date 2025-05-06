# Imports
import os
import sys
import copy

# Local imports
import util
import connection

# Installer
class Installer:
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        self.config = config.Copy()
        self.connection = connection.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()

    def SetEnvironmentType(self, environment_type):
        self.config.SetValue("UserData.General", "environment_type", environment_type)

    def GetEnvironmentType(self):
        return self.config.GetValue("UserData.General", "environment_type")

    def IsInstalled(self):
        return False

    def Install(self):
        return False

    def Uninstall(self):
        return False
