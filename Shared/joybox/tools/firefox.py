# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Firefox tool
class Firefox(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Firefox"

    # Get config
    def get_config(self):

        # Get firefox info
        firefox_exe = settings.get_value("Tools.Firefox", "firefox_exe")
        firefox_install_dir = settings.get_path_value("Tools.Firefox", "firefox_install_dir")
        firefox_download_dir = settings.get_path_value("Tools.Firefox", "firefox_download_dir")
        firefox_profile_dir = settings.get_path_value("Tools.Firefox", "firefox_profile_dir", default_value = "", throw_exception = False)

        # Return config
        return {
            "Firefox": {
                "program": paths.join_paths(firefox_install_dir, firefox_exe),
                "download_dir": firefox_download_dir,
                "profile_dir": firefox_profile_dir
            }
        }
