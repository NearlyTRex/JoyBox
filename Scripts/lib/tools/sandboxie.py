# Imports
import os, os.path
import sys

# Local imports
import environment
import ini
import toolbase

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
        sandboxie_install_dir = ini.GetIniValue("Tools.Sandboxie", "sandboxie_install_dir")
        sandboxie_sandbox_dir = ini.GetIniValue("Tools.Sandboxie", "sandboxie_sandbox_dir")

        # Return config
        return {

            # Sandboxie
            "Sandboxie": {
                "program": os.path.join(sandboxie_install_dir, sandboxie_exe),
                "sandbox_dir": sandboxie_sandbox_dir
            },

            # SandboxieIni
            "SandboxieIni": {
                "program": os.path.join(sandboxie_install_dir, sandboxie_ini_exe)
            },

            # SandboxieRpcss
            "SandboxieRpcss": {
                "program": os.path.join(sandboxie_install_dir, sandboxie_rpcss_exe)
            },

            # SandboxieDcomlaunch
            "SandboxieDcomlaunch": {
                "program": os.path.join(sandboxie_install_dir, sandboxie_dcomlaunch_exe)
            }
        }
