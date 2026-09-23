#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.environment as environment
import joybox.command as command
import joybox.programs as programs
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Start the Pegasus game frontend installed by setup_tools.",
    details = (
        "Runs the Pegasus program from the tools directory, with its own folder as the working\n"
        "directory and the current environment passed through. It also sets\n"
        "`JOYBOX_LAUNCH_JSON` to the JoyBox launcher command, which the `launch:` lines in the\n"
        "Pegasus metadata files JoyBox writes call to start a game.\n"
        "\n"
        "It waits for Pegasus to exit and logs an error if it exits with a non-zero code. It\n"
        "takes only the common options."),
    examples = [
        ("Start Pegasus", "launch_pegasus"),
        ("Dry run without starting Pegasus", "launch_pegasus -p -v"),
    ],
    notes = [
        "Pegasus must be installed first (`setup_tools -k Pegasus`); the command exits with an error if it is not found.",
    ],
    see_also = ["setup_tools", "setup_game_assets", "build_game_metadata_files", "launch_game_json"],
    section = "Game Launching")
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
