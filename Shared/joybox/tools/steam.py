# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Steam tool
class Steam(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Steam"

    # Get config
    def get_config(self):

        # Get steam info
        steam_exe = settings.get_value("Tools.Steam", "steam_exe")
        steam_install_dir = settings.get_path_value("Tools.Steam", "steam_install_dir")

        # Return config
        return {

            # Steam
            "Steam": {
                "program": paths.join_paths(steam_install_dir, steam_exe)
            }
        }
