# Imports
import os
import sys

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

    def Setup(self):
        return False

    def Teardown(self):
        return False
