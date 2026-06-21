# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Gpg tool
class Gpg(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Gpg"

    # Get config
    def get_config(self):

        # Get gpg info
        gpg_exe = settings.get_value("Tools.Gpg", "gpg_exe")
        gpg_install_dir = settings.get_path_value("Tools.Gpg", "gpg_install_dir")

        # Return config
        return {
            "Gpg": {
                "program": paths.join_paths(gpg_install_dir, gpg_exe)
            }
        }
