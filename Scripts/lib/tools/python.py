# Imports
import os, os.path
import sys

# Local imports
import ini
import toolbase

# Python tool
class Python(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Python"

    # Get config
    def GetConfig(self):

        # Get git info
        python_exe = ini.GetIniValue("Tools.Python", "python_exe")
        python_pip_exe = ini.GetIniValue("Tools.Python", "python_pip_exe")
        python_install_dir = ini.GetIniPathValue("Tools.Python", "python_install_dir")
        python_venv_dir = ini.GetIniPathValue("Tools.Python", "python_venv_dir")

        # Return config
        return {

            # Python
            "Python": {
                "program": os.path.join(python_install_dir, python_exe),
                "venv_dir": python_venv_dir
            },

            # PythonVenvPython
            "PythonVenvPython": {
                "program": {
                    "windows": os.path.join(python_venv_dir, "Scripts", python_exe),
                    "linux": os.path.join(python_venv_dir, "bin", python_exe)
                }
            },

            # PythonVenvPip
            "PythonVenvPip": {
                "program": {
                    "windows": os.path.join(python_venv_dir, "Scripts", python_pip_exe),
                    "linux": os.path.join(python_venv_dir, "bin", python_pip_exe)
                }
            }
        }
