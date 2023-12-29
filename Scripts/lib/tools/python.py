# Imports
import os, os.path
import sys

# Local imports
import config
import ini
import system
import environment
import programs
import toolbase

# Wrapper scripts
wrapper_script_windows = """
@echo off
$PYTHON_BIN "%~dp0%~n0.py" %*
"""
wrapper_script_unix = """
#!/bin/bash
exec $PYTHON_BIN "$0.py" "$@"
"""

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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create wrapper scripts
        for obj in system.GetDirectoryContents(environment.GetScriptsBinDir()):
            if obj.endswith(".py"):

                # Get script info
                script_basename = system.GetFilenameBasename(obj)
                script_path_orig = os.path.join(environment.GetScriptsBinDir(), obj)
                script_path_windows = os.path.join(environment.GetScriptsBinDir(), script_basename + ".bat")
                script_path_unix = os.path.join(environment.GetScriptsBinDir(), script_basename)

                # Create windows wrapper script
                if environment.IsWindowsPlatform():
                    success = system.TouchFile(
                        src = script_path_windows,
                        contents = wrapper_script_windows.strip().replace(config.token_python_bin, programs.GetToolProgram("PythonVenvPython")),
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not setup Python wrapper scripts")

                # Create unix wrapper script
                if environment.IsUnixPlatform():
                    success = system.TouchFile(
                        src = script_path_unix,
                        contents = wrapper_script_unix.strip().replace(config.token_python_bin, programs.GetToolProgram("PythonVenvPython")),
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not setup Python wrapper scripts")
                    success = system.MarkAsExecutable(
                        src = script_path_unix,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not setup Python wrapper scripts")
