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
        self.config = copy.deepcopy(config)
        self.flags = flags.Copy()
        self.options = options.Copy()

    def SetEnvironmentType(self, environment_type):
        self.config["env"] = environment_type

    def Setup(self):
        return False

    def Teardown(self):
        return False
