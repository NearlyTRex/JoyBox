# Imports
import os
import sys

# Local imports
import util
from . import env

# Remote Ubuntu
class RemoteUbuntu(env.Environment):
    def __init__(
        self,
        config,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, flags, options)

        # Set environment type
        self.SetEnvironmentType(constants.EnvironmentType.REMOTE_UBUNTU)

    def Setup(self):
        return True

    def Teardown(self):
        return True
