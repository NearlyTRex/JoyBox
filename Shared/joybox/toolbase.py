# Local imports
from joybox import programcatalog
from joybox import programsetup

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

    # Download and install the tool by the [[setup]] steps in its program data; succeeds when it has none
    def setup(self, setup_params = None):
        return programsetup.run_setup_steps(programcatalog.FAMILY_TOOLS, self.get_name(), setup_params = setup_params)

    # Install the tool from its stored backups by the [[setup_offline]] steps in its program data
    def setup_offline(self, setup_params = None):
        return programsetup.run_setup_steps(programcatalog.FAMILY_TOOLS, self.get_name(), offline = True, setup_params = setup_params)

    # Write the tool's config files after install; succeeds in the base
    def configure(self, setup_params = None):
        del setup_params
        return True
