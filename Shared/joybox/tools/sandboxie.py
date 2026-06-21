# Local imports
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths
from joybox import platform_info

# Config files
config_files = {}

# Sandboxie tool
class Sandboxie(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Sandboxie"

    # Get config
    def get_config(self):

        # Check platform
        if not platform_info.is_sandboxie_platform():
            return {}

        # Get sandboxie info
        sandboxie_exe = settings.get_value("Tools.Sandboxie", "sandboxie_exe")
        sandboxie_ini_exe = settings.get_value("Tools.Sandboxie", "sandboxie_ini_exe")
        sandboxie_rpcss_exe = settings.get_value("Tools.Sandboxie", "sandboxie_rpcss_exe")
        sandboxie_dcomlaunch_exe = settings.get_value("Tools.Sandboxie", "sandboxie_dcomlaunch_exe")
        sandboxie_install_dir = settings.get_path_value("Tools.Sandboxie", "sandboxie_install_dir")
        sandboxie_sandbox_dir = settings.get_path_value("Tools.Sandboxie", "sandboxie_sandbox_dir")

        # Return config
        return {

            # Sandboxie
            "Sandboxie": {
                "program": paths.join_paths(sandboxie_install_dir, sandboxie_exe),
                "sandbox_dir": sandboxie_sandbox_dir
            },

            # SandboxieIni
            "SandboxieIni": {
                "program": paths.join_paths(sandboxie_install_dir, sandboxie_ini_exe)
            },

            # SandboxieRpcss
            "SandboxieRpcss": {
                "program": paths.join_paths(sandboxie_install_dir, sandboxie_rpcss_exe)
            },

            # SandboxieDcomlaunch
            "SandboxieDcomlaunch": {
                "program": paths.join_paths(sandboxie_install_dir, sandboxie_dcomlaunch_exe)
            }
        }
