# Imports
import configparser
import os
import tomllib

# Local imports
import joybox.command as command
import joybox.logger as logger
import joybox.programs as programs

###########################################################
# Declared requirements of a downloaded Python tool
#
# JoyBox runs these tools from their own directory with the venv's python, so
# what they import has to be in the venv. The tool's own declaration is used,
# not a copy kept here, so a change in the tool carries through. Only the
# dependencies are installed; the tool itself stays where it was downloaded.
###########################################################

# Get the requirements a tool directory declares, as pip arguments. The first
# of requirements.txt, pyproject.toml and setup.cfg that declares any wins.
def get_declared_requirements(tool_dir):
    requirements_file = os.path.join(tool_dir, "requirements.txt")
    if os.path.isfile(requirements_file):
        return ["-r", requirements_file]
    pyproject_file = os.path.join(tool_dir, "pyproject.toml")
    if os.path.isfile(pyproject_file):
        with open(pyproject_file, "rb") as pyproject:
            dependencies = tomllib.load(pyproject).get("project", {}).get("dependencies", [])
        if dependencies:
            return list(dependencies)
    setup_cfg_file = os.path.join(tool_dir, "setup.cfg")
    if os.path.isfile(setup_cfg_file):
        parser = configparser.ConfigParser(interpolation = None)
        parser.read(setup_cfg_file)
        declared = parser.get("options", "install_requires", fallback = "")
        dependencies = [line.strip() for line in declared.splitlines() if line.strip()]
        if dependencies:
            return dependencies
    return []

# Install the requirements a tool directory declares into the venv
def install_declared_requirements(
    tool_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    requirements = get_declared_requirements(tool_dir)
    if not requirements:
        return True
    pip_tool = None
    if programs.is_tool_installed("PythonVenvPip"):
        pip_tool = programs.get_tool_program("PythonVenvPip")
    if not pip_tool:
        logger.log_error("PythonVenvPip was not found")
        return False
    code = command.run_returncode_command(
        cmd = [pip_tool, "install"] + requirements,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to install the requirements of %s" % tool_dir)
        return False
    return True
