# Imports
import os, os.path
import sys
import importlib

# Local imports
import command
import environment
import programs

# Setup python environment
def SetupPythonEnvironment(verbose = False, exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("Python"):
        python_tool = programs.GetToolProgram("Python")
    if not python_tool:
        return False

    # Get setup command
    setup_cmd = [
        python_tool,
        "-m",
        "venv",
        programs.GetToolPathConfigValue("Python", "venv_dir")
    ]

    # Run setup command
    code = command.RunBlockingCommand(
        cmd = setup_cmd,
        options = command.CommandOptions(
            allow_processing = False),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)

# Install python module
def InstallPythonModule(module, verbose = False, exit_on_failure = False):

    # Get tool
    pip_tool = None
    if programs.IsToolInstalled("PythonVenvPip"):
        pip_tool = programs.GetToolProgram("PythonVenvPip")
    if not pip_tool:
        return False

    # Get install command
    install_cmd = [
        pip_tool,
        "install",
        "--upgrade",
        module
    ]

    # Run install command
    code = command.RunBlockingCommand(
        cmd = install_cmd,
        options = command.CommandOptions(
            allow_processing = False),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)

# Import python module
def ImportPythonModule(module_path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
