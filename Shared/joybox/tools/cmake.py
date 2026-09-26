# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Cmake tool
class Cmake(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Cmake"

    # Get config
    def get_config(self):

        # Get cmake info
        cmake_exe = settings.get_value("Tools.Cmake", "cmake_exe")
        cmake_install_dir = settings.get_path_value("Tools.Cmake", "cmake_install_dir")

        # Return config
        return {
            "Cmake": {
                "program": paths.join_paths(cmake_install_dir, cmake_exe)
            }
        }
