# Imports
import os
import sys

# Local imports
import util
from . import installer

# Nextcloud
class Nextcloud(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(config, connection, flags, options)

    def IsInstalled(self):
        return False

    def Install(self):
        return False

    def Uninstall(self):
        return False
