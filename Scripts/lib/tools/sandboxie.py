# Imports
import os, os.path
import sys

# Local imports
import system
import environment
import toolbase
import ini

# Config files
config_files = {}

# Sandboxie tool
class Sandboxie(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Sandboxie"

    # Get config
    def GetConfig(self):

        # Check platform
        if not environment.IsSandboxiePlatform():
            return {}

        # Get sandboxie info
        sandboxie_exe = ini.GetIniValue("Tools.Sandboxie", "sandboxie_exe")
        sandboxie_ini_exe = ini.GetIniValue("Tools.Sandboxie", "sandboxie_ini_exe")
        sandboxie_rpcss_exe = ini.GetIniValue("Tools.Sandboxie", "sandboxie_rpcss_exe")
        sandboxie_dcomlaunch_exe = ini.GetIniValue("Tools.Sandboxie", "sandboxie_dcomlaunch_exe")
        sandboxie_install_dir = ini.GetIniPathValue("Tools.Sandboxie", "sandboxie_install_dir")
        sandboxie_sandbox_dir = ini.GetIniPathValue("Tools.Sandboxie", "sandboxie_sandbox_dir")

        # Return config
        return {

            # Sandboxie
            "Sandboxie": {
                "program": system.JoinPaths(sandboxie_install_dir, sandboxie_exe),
                "sandbox_dir": sandboxie_sandbox_dir
            },

            # SandboxieIni
            "SandboxieIni": {
                "program": system.JoinPaths(sandboxie_install_dir, sandboxie_ini_exe)
            },

            # SandboxieRpcss
            "SandboxieRpcss": {
                "program": system.JoinPaths(sandboxie_install_dir, sandboxie_rpcss_exe)
            },

            # SandboxieDcomlaunch
            "SandboxieDcomlaunch": {
                "program": system.JoinPaths(sandboxie_install_dir, sandboxie_dcomlaunch_exe)
            }
        }
