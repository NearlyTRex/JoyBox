# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Bchunk tool
class Bchunk(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Bchunk"

    # Get config
    def get_config(self):

        # Get bchunk info
        bchunk_exe = settings.get_value("Tools.Bchunk", "bchunk_exe")
        bchunk_install_dir = settings.get_path_value("Tools.Bchunk", "bchunk_install_dir")

        # Return config
        return {
            "Bchunk": {
                "program": paths.join_paths(bchunk_install_dir, bchunk_exe)
            }
        }
