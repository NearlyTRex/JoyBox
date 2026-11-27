# Local imports
from joybox import programcatalog

# Base tool
class ToolBase:

    # Get name
    def get_name(self):
        return ""

    # Get config, from the tool's program data
    def get_config(self):
        return programcatalog.get_tool_config(self.get_name())

    # Get the files setup writes, by path, with their contents
    def get_config_files(self):
        return programcatalog.get_config_files(programcatalog.FAMILY_TOOLS, self.get_name())

    # Setup
    def setup(self, setup_params = None):
        del setup_params
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        del setup_params
        return True

    # Configure
    def configure(self, setup_params = None):
        del setup_params
        return True
