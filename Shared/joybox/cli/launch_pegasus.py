# Imports
import os
import os.path
from joybox import system
from joybox import environment
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import paths

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "launch_pegasus")
    parser.add_common_arguments()
    return parser

# Run Pegasus from its tools folder with JOYBOX_LAUNCH_JSON set to the launcher command, and wait for it to exit
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

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
    launch_options = commandbase.create_command_options()
    launch_options.set_cwd(paths.get_filename_directory(pegasus_tool))
    launch_options.set_env(dict(os.environ))
    launch_options.set_env_var("JOYBOX_LAUNCH_JSON", environment.get_command_path("launch_game_json"))

    # Run launch command
    code = command.run_returncode_command(
        cmd = launch_cmd,
        options = launch_options,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if code != 0:
        logger.log_error("Launch command failed with code %d" % code, quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
