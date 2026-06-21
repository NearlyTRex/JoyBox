# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# 7-Zip tool
class SevenZip(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "7-Zip"

    # Get config
    def get_config(self):

        # Get sevenzip info
        sevenzip_exe = settings.get_value("Tools.7Zip", "7z_exe")
        sevenzip_install_dir = settings.get_path_value("Tools.7Zip", "7z_install_dir")

        # Return config
        return {
            "7-Zip": {
                "program": paths.join_paths(sevenzip_install_dir, sevenzip_exe)
            }
        }
