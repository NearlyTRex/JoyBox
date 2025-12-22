# Imports
import os, os.path
import sys

# Local imports
import system
import environment
import toolbase
import ini
import paths

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
        if not environment.is_sandboxie_platform():
            return {}

        # Get sandboxie info
        sandboxie_exe = ini.get_ini_value("Tools.Sandboxie", "sandboxie_exe")
        sandboxie_ini_exe = ini.get_ini_value("Tools.Sandboxie", "sandboxie_ini_exe")
        sandboxie_rpcss_exe = ini.get_ini_value("Tools.Sandboxie", "sandboxie_rpcss_exe")
        sandboxie_dcomlaunch_exe = ini.get_ini_value("Tools.Sandboxie", "sandboxie_dcomlaunch_exe")
        sandboxie_install_dir = ini.get_ini_path_value("Tools.Sandboxie", "sandboxie_install_dir")
        sandboxie_sandbox_dir = ini.get_ini_path_value("Tools.Sandboxie", "sandboxie_sandbox_dir")

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
