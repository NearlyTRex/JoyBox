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
        self.config = copy.deepcopy(config)
        self.connection = connection.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()

    def IsInstalled(self):
        return False

    def Install(self):
        return False

    def Uninstall(self):
        return False
