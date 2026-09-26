# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Unzip tool
class Unzip(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Unzip"

    # Get config
    def get_config(self):

        # Get unzip info
        unzip_exe = settings.get_value("Tools.Unzip", "unzip_exe")
        unzip_install_dir = settings.get_path_value("Tools.Unzip", "unzip_install_dir")

        # Return config
        return {
            "Unzip": {
                "program": paths.join_paths(unzip_install_dir, unzip_exe)
            }
        }
