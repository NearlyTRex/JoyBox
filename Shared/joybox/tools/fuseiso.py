# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# FuseISO tool
class FuseISO(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "FuseISO"

    # Get config
    def get_config(self):

        # Get python info
        fuseiso_exe = settings.get_value("Tools.FuseISO", "fuseiso_exe")
        fusermount_exe = settings.get_value("Tools.FuseISO", "fusermount_exe")
        fuseiso_install_dir = settings.get_value("Tools.FuseISO", "fuseiso_install_dir")
        fusermount_install_dir = settings.get_value("Tools.FuseISO", "fusermount_install_dir")

        # Return config
        return {

            # FuseISO
            "FuseISO": {
                "program": {
                    "windows": None,
                    "linux": paths.join_paths(fuseiso_install_dir, fuseiso_exe)
                }
            },

            # FUserMount
            "FUserMount": {
                "program": {
                    "windows": None,
                    "linux": paths.join_paths(fusermount_install_dir, fusermount_exe)
                }
            }
        }
