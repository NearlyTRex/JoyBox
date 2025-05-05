# Imports
import os
import sys
import copy

# Local imports
import util

# Environment
class Environment:
    def __init__(
        self,
        config,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        self.config = config.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()

    def SetEnvironmentType(self, environment_type):
        self.config.SetValue("UserData.General", "environment_type", environment_type)

    def GetEnvironmentType(self):
        return self.config.GetValue("UserData.General", "environment_type")

    def Setup(self):
        return False

    def Teardown(self):
        return False
