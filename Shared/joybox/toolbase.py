# Imports
import os
import re

# Local imports
from joybox import command
from joybox import commandbase
from joybox import config
from joybox import desktopentry
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import programcatalog
from joybox import programs
from joybox import programsetup

# A launch value that is the path of a JoyBox command, by its name
COMMAND_PATH_VALUE = re.compile(r"^\{command_path:([A-Za-z0-9_]+)\}$")

# Base tool
class ToolBase:

    # The name the tool is registered under, which also files its program data
    NAME = ""

    # The tool's registered name
    def get_name(self):
        return self.NAME

    # Get config, from the tool's program data
    def get_config(self):
        return programcatalog.get_tool_config(self.get_name())

    # Get the files setup writes, by path, with their contents
    def get_config_files(self):
        return programcatalog.get_config_files(programcatalog.FAMILY_TOOLS, self.get_name())

    # Download and install the tool by the [[setup]] steps in its program data; succeeds when it has none
    def setup(self, setup_params = None):
        return programsetup.run_setup_steps(programcatalog.FAMILY_TOOLS, self.get_name(), setup_params = setup_params)

    # Install the tool from its stored backups by the [[setup_offline]] steps in its program data
    def setup_offline(self, setup_params = None):
        return programsetup.run_setup_steps(programcatalog.FAMILY_TOOLS, self.get_name(), offline = True, setup_params = setup_params)

    # Write the tool's config files after install; succeeds in the base
    def configure(self, setup_params = None):
        del setup_params
        return True

    # Write each config file, its own by default, under the tools root; False, after logging,
    # at the first that fails
    def write_config_files(self, setup_params = None, config_files = None):
        if not setup_params:
            setup_params = config.SetupParams()
        if config_files is None:
            config_files = self.get_config_files()
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup %s config files" % self.get_name())
                return False
        return True

    # Add the tool's app menu entry, named after it, or remove it when not enabled; False,
    # after logging, when that fails
    def set_menu_launcher(self, enabled, filename, description, command_name, icon, setup_params):
        success = desktopentry.set_launcher(
            enabled = enabled,
            filename = filename,
            name = self.get_name(),
            description = description,
            command = command_name,
            icon = icon,
            verbose = setup_params.verbose,
            pretend_run = setup_params.pretend_run,
            exit_on_failure = setup_params.exit_on_failure)
        if not success:
            logger.log_error("Could not setup the %s launcher" % self.get_name())
            return False
        return True

    # The installed tool program; quits with an error when the tool is not installed
    def get_installed_program(self):
        program = None
        if programs.is_tool_installed(self.get_name()):
            program = programs.get_tool_program(self.get_name())
        if not program:
            logger.log_error("%s was not found" % self.get_name(), quit_program = True)
        return program

    # A [launch] cwd or env value with its placeholder filled in: {program_dir} is the program's
    # folder, {command_path:<name>} a JoyBox command's path
    def fill_launch_value(self, value, program):
        if value == "{program_dir}":
            return paths.get_filename_directory(program)
        match = COMMAND_PATH_VALUE.match(value)
        return environment.get_command_path(match[1]) if match else value

    # Command options for the program from its [launch] cwd and env; env adds to the inherited environment
    def get_launch_options(self, program, launch):
        options = commandbase.create_command_options()
        if "cwd" in launch:
            options.set_cwd(self.fill_launch_value(launch["cwd"], program))
        if "env" in launch:
            options.set_env(dict(os.environ))
            for key, value in launch["env"].items():
                options.set_env_var(key, self.fill_launch_value(value, program))
        return options

    # Run a launch command; quits with an error when it fails
    def run_launch_command(self, launch_cmd, options = None, verbose = False, pretend_run = False, exit_on_failure = False):
        code = command.run_returncode_command(
            cmd = launch_cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            logger.log_error("Launch command failed with code %d" % code, quit_program = True)

    # Run the installed program with the args, cwd and env of its [launch] data and wait for it to exit;
    # quits when it is not installed or fails
    def launch(self, verbose = False, pretend_run = False, exit_on_failure = False):
        program = self.get_installed_program()
        launch = programcatalog.get_launch(programcatalog.FAMILY_TOOLS, self.get_name())
        self.run_launch_command(
            [program] + launch.get("args", []),
            options = self.get_launch_options(program, launch),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
