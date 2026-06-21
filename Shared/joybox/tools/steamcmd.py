# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# SteamCMD tool
class SteamCMD(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "SteamCMD"

    # Get config
    def get_config(self):

        # Get steamcmd info
        steamcmd_exe = settings.get_value("Tools.Steam", "steamcmd_exe")
        steamcmd_install_dir = settings.get_path_value("Tools.Steam", "steamcmd_install_dir")

        # Return config
        return {

            # SteamCMD
            "SteamCMD": {
                "program": paths.join_paths(steamcmd_install_dir, steamcmd_exe)
            }
        }
