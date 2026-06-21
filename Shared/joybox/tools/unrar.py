# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Unrar tool
class Unrar(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Unrar"

    # Get config
    def get_config(self):

        # Get unrar info
        unrar_exe = settings.get_value("Tools.Unrar", "unrar_exe")
        unrar_install_dir = settings.get_path_value("Tools.Unrar", "unrar_install_dir")

        # Return config
        return {
            "Unrar": {
                "program": paths.join_paths(unrar_install_dir, unrar_exe)
            }
        }
