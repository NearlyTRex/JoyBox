# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Tar tool
class Tar(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Tar"

    # Get config
    def get_config(self):

        # Get tar info
        tar_exe = settings.get_value("Tools.Tar", "tar_exe")
        tar_install_dir = settings.get_path_value("Tools.Tar", "tar_install_dir")

        # Return config
        return {
            "Tar": {
                "program": paths.join_paths(tar_install_dir, tar_exe)
            }
        }
