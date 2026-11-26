# Local imports
from joybox import toolbase
from joybox import settings
from joybox import paths

# Config files
config_files = {}

# Brave tool
class Brave(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Brave"

    # Get config
    def get_config(self):

        # Get brave info
        brave_exe = settings.get_value("Tools.Brave", "brave_exe")
        brave_install_dir = settings.get_path_value("Tools.Brave", "brave_install_dir")
        brave_download_dir = settings.get_path_value("Tools.Brave", "brave_download_dir")

        # Return config
        return {
            "Brave": {
                "program": paths.join_paths(brave_install_dir, brave_exe),
                "download_dir": brave_download_dir
            }
        }
