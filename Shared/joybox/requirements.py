# Imports
import configparser
import os
import tomllib

# Local imports
import joybox.command as command
import joybox.fileops as fileops
import joybox.logger as logger
import joybox.programs as programs

###########################################################
# Declared requirements of a downloaded Python tool
#
# JoyBox runs these tools, or imports them, from their own directory with the
# venv's python, so what they import has to be in the venv. The tool's own
# declaration is used, not a copy kept here, so a change in the tool carries
# through. Only the dependencies are installed; the tool itself stays where it
# was downloaded. Online setup also keeps them as wheels beside the tool's
# backup, which is what an offline setup installs from.
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

# Get where a tool's requirement wheels are kept, beside its backup
def get_wheels_dir(tool_name):
    return programs.get_library_backup_dir(tool_name, "wheels")

# Run the venv's pip
def run_pip(
    pip_args,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    pip_tool = None
    if programs.is_tool_installed("PythonVenvPip"):
        pip_tool = programs.get_tool_program("PythonVenvPip")
    if not pip_tool:
        logger.log_error("PythonVenvPip was not found")
        return False
    code = command.run_returncode_command(
        cmd = [pip_tool] + pip_args,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Install a downloaded tool's requirements into the venv, without upgrading
# anything the venv already has, and keep them as wheels for offline setup
def setup_tool_requirements(
    tool_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    requirements = get_declared_requirements(programs.get_library_install_dir(tool_name, "lib"))
    if not requirements:
        return True
    flags = {"verbose": verbose, "pretend_run": pretend_run, "exit_on_failure": exit_on_failure}
    if not run_pip(["install"] + requirements, **flags):
        logger.log_error("Unable to install the requirements of %s" % tool_name)
        return False
    wheels_dir = get_wheels_dir(tool_name)
    fileops.remove_directory(src = wheels_dir, **flags)
    if not run_pip(["wheel", "--wheel-dir", wheels_dir] + requirements, **flags):
        logger.log_error("Unable to keep the requirements of %s for offline setup" % tool_name)
        return False
    return True

# Install a restored tool's requirements from the wheels kept by online setup,
# with no network access
def setup_tool_requirements_offline(
    tool_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    requirements = get_declared_requirements(programs.get_library_install_dir(tool_name, "lib"))
    if not requirements:
        return True
    pip_args = ["install", "--no-index"]
    wheels_dir = get_wheels_dir(tool_name)
    if os.path.isdir(wheels_dir):
        pip_args += ["--find-links", wheels_dir]
    if not run_pip(pip_args + requirements, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
        logger.log_error("Unable to install the requirements of %s offline" % tool_name)
        return False
    return True
