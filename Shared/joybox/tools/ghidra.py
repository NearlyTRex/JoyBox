# Local imports
from joybox import toolbase

# Ghidra tool
class Ghidra(toolbase.ToolBase):

    NAME = "Ghidra"

    # Write its config files under the tools root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)
