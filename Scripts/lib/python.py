# Imports
import os, os.path
import sys
import importlib

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import command
import environment
import userdata

# Get python program
def GetPythonProgram():
    python_exe = userdata.GetIniValue("Tools.Python", "python_exe")
    python_install_dir = userdata.GetIniValue("Tools.Python", "python_install_dir")
    return command.GetRunnableCommandPath(
        cmd = python_exe,
        search_dirs = [python_install_dir])

# Get python virtual environment program
def GetPythonVirtualEnvProgram(program):
    python_venv_dir = userdata.GetIniValue("Tools.Python", "python_venv_dir")
    if environment.IsWindowsPlatform():
        return os.path.join(python_venv_dir, "Scripts", program)
    else:
        return os.path.join(python_venv_dir, "bin", program)

# Get python virtual environment interpreter
def GetPythonVirtualEnvInterpreter():
    python_exe = userdata.GetIniValue("Tools.Python", "python_exe")
    return GetPythonVirtualEnvProgram(python_exe)

# Setup python environment
def SetupPythonEnvironment(verbose = False, exit_on_failure = False):

    # Get setup command
    setup_cmd = [
        GetPythonProgram(),
        "-m",
        "venv",
        userdata.GetIniValue("Tools.Python", "python_venv_dir")
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

    # Get install command
    install_cmd = [
        GetPythonVirtualEnvInterpreter(),
        "-m",
        userdata.GetIniValue("Tools.Python", "python_pip_exe"),
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
