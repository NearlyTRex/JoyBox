# Local imports
from joybox import programcatalog

# Base tool
class ToolBase:

    # The name the tool is registered under, which also files its program data
    NAME = ""

    # The tool's registered name
    def get_name(self):
        return self.NAME

    # Get config, from the tool's program data
    def get_config(self):
        return programcatalog.get_tool_config(self.get_name())

    # Get the files setup writes, by path, with their contents
    def get_config_files(self):
        return programcatalog.get_config_files(programcatalog.FAMILY_TOOLS, self.get_name())

    # Download and install the tool; the base has nothing to install and succeeds
    def setup(self, setup_params = None):
        del setup_params
        return True

    # Install the tool from local copies without downloading; succeeds in the base
    def setup_offline(self, setup_params = None):
        del setup_params
        return True

    # Write the tool's config files after install; succeeds in the base
    def configure(self, setup_params = None):
        del setup_params
        return True
