# Local imports
from joybox import toolbase


# Ludusavi tool
class Ludusavi(toolbase.ToolBase):

    NAME = "Ludusavi"

    # Write its config files under the tools root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)
