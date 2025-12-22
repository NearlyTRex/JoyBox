#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import command
import programs
import arguments
import setup
import logger
import paths

# Parse arguments
parser = arguments.ArgumentParser(description = "Launch pegasus.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get tool
    pegasus_tool = None
    if programs.is_tool_installed("Pegasus"):
        pegasus_tool = programs.get_tool_program("Pegasus")
    if not pegasus_tool:
        logger.log_error("Pegasus was not found", quit_program = True)

    # Get launch command
    launch_cmd = [
        pegasus_tool
    ]

    # Get launch options
    launch_options = command.create_command_options()
    launch_options.set_cwd(paths.get_filename_directory(pegasus_tool))
    launch_options.set_env(os.environ)
    launch_options.set_env_var("JOYBOX_LAUNCH_JSON", paths.join_paths(environment.get_scripts_bin_dir(), "launch_json" + environment.get_scripts_command_extension()))

    # Run launch command
    code = command.run_returncode_command(
        cmd = launch_cmd,
        options = launch_options,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if code != 0:
        logger.log_error("Launch command failed with code %d" % code)

# Start
if __name__ == "__main__":
    system.run_main(main)
