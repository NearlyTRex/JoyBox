# Local imports
import joybox.toolbase as toolbase
import joybox.settings as ini
import joybox.paths as paths

# Config files
config_files = {}

# Git tool
class Git(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Git"

    # Get config
    def get_config(self):

        # Get git info
        git_exe = ini.get_ini_value("Tools.Git", "git_exe")
        git_install_dir = ini.get_ini_path_value("Tools.Git", "git_install_dir")

        # Return config
        return {
            "Git": {
                "program": paths.join_paths(git_install_dir, git_exe)
            }
        }
