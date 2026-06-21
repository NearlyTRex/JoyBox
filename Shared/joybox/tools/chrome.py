# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Chrome tool
class Chrome(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Chrome"

    # Get config
    def get_config(self):

        # Get chrome info
        chrome_exe = settings.get_value("Tools.Chrome", "chrome_exe")
        chrome_install_dir = settings.get_path_value("Tools.Chrome", "chrome_install_dir")
        chrome_download_dir = settings.get_path_value("Tools.Chrome", "chrome_download_dir")

        # Return config
        return {
            "Chrome": {
                "program": paths.join_paths(chrome_install_dir, chrome_exe),
                "download_dir": chrome_download_dir
            }
        }
