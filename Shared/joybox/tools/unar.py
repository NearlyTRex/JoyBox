# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Unar tool
class Unar(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Unar"

    # Get config
    def get_config(self):

        # Get unar info
        unar_exe = settings.get_value("Tools.Unar", "unar_exe")
        unar_install_dir = settings.get_path_value("Tools.Unar", "unar_install_dir")

        # Return config
        return {
            "Unar": {
                "program": paths.join_paths(unar_install_dir, unar_exe)
            }
        }
