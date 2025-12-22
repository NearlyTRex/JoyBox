# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import programs
import toolbase
import ini

# Config files
config_files = {}

# Wrapper scripts
wrapper_script_windows = """
@echo off
PYTHON_BIN "%~dp0%~n0.py" %*
"""
wrapper_script_unix = """
#!/bin/bash
exec PYTHON_BIN "$0.py" "$@"
"""

# Python tool
class Python(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Python"

    # Get config
    def get_config(self):

        # Get python info
        python_exe = ini.get_ini_value("Tools.Python", "python_exe")
        python_pip_exe = ini.get_ini_value("Tools.Python", "python_pip_exe")
        python_install_dir = ini.get_ini_path_value("Tools.Python", "python_install_dir")
        python_venv_dir = ini.get_ini_path_value("Tools.Python", "python_venv_dir")

        # Return config
        return {

            # Python
            "Python": {
                "program": paths.join_paths(python_install_dir, python_exe),
                "venv_dir": python_venv_dir
            },

            # PythonVenvPython
            "PythonVenvPython": {
                "program": {
                    "windows": paths.join_paths(python_venv_dir, "Scripts", python_exe),
                    "linux": paths.join_paths(python_venv_dir, "bin", python_exe)
                }
            },

            # PythonVenvPip
            "PythonVenvPip": {
                "program": {
                    "windows": paths.join_paths(python_venv_dir, "Scripts", python_pip_exe),
                    "linux": paths.join_paths(python_venv_dir, "bin", python_pip_exe)
                }
            }
        }

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create wrapper scripts
        for obj in paths.get_directory_contents(environment.get_scripts_bin_dir()):
            if obj.endswith(".py"):

                # Get script info
                script_basename = paths.get_filename_basename(obj)
                script_path_orig = paths.join_paths(environment.get_scripts_bin_dir(), obj)
                script_path_windows = paths.join_paths(environment.get_scripts_bin_dir(), script_basename + config.WindowsProgramFileType.BAT.cval())
                script_path_unix = paths.join_paths(environment.get_scripts_bin_dir(), script_basename)

                # Create windows wrapper script
                if environment.is_windows_platform():
                    success = fileops.touch_file(
                        src = script_path_windows,
                        contents = wrapper_script_windows.strip().replace(config.token_python_bin, programs.get_tool_program("PythonVenvPython")),
                        verbose = setup_params.verbose,
                        pretend_run = setup_params.pretend_run,
                        exit_on_failure = setup_params.exit_on_failure)
                    if not success:
                        logger.log_error("Could not setup Python wrapper scripts")
                        return False

                # Create unix wrapper script
                if environment.is_unix_platform():
                    success = fileops.touch_file(
                        src = script_path_unix,
                        contents = wrapper_script_unix.strip().replace(config.token_python_bin, programs.get_tool_program("PythonVenvPython")),
                        verbose = setup_params.verbose,
                        pretend_run = setup_params.pretend_run,
                        exit_on_failure = setup_params.exit_on_failure)
                    if not success:
                        logger.log_error("Could not setup Python wrapper scripts")
                        return False
                    success = fileops.mark_as_executable(
                        src = script_path_unix,
                        verbose = setup_params.verbose,
                        pretend_run = setup_params.pretend_run,
                        exit_on_failure = setup_params.exit_on_failure)
                    if not success:
                        logger.log_error("Could not setup Python wrapper scripts")
                        return False
        return True
