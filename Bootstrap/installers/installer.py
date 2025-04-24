# Imports
import os
import sys

# Local imports
import util
import connection

# Installer
class Installer:
    def __init__(
        self,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        self.connection = connection.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()

    def IsInstalled(self):
        return False

    def Install(self):
        return False
