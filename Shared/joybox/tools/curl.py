# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Curl tool
class Curl(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Curl"

    # Get config
    def get_config(self):

        # Get curl info
        curl_exe = settings.get_value("Tools.Curl", "curl_exe")
        curl_install_dir = settings.get_path_value("Tools.Curl", "curl_install_dir")

        # Return config
        return {
            "Curl": {
                "program": paths.join_paths(curl_install_dir, curl_exe)
            }
        }
