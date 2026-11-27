# Imports
from joybox import system
from joybox import programs
from joybox import command
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "list_dupes")
    parser.add_input_path_argument(description = "Directory to search, including all subdirectories; it must exist")
    parser.add_common_arguments()
    return parser

# Print the sets of duplicate files under the input dir with jdupes; deletes nothing
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Get tool
    dupes_tool = None
    if programs.is_tool_installed("JDupes"):
        dupes_tool = programs.get_tool_program("JDupes")
    if not dupes_tool:
        logger.log_error("JDupes was not found", quit_program = True)

    # Get list command
    list_cmd = [
        dupes_tool,
        "--recurse",
        "--print-summarize",
        "--size",
        input_path
    ]

    # Run list command
    code = command.run_returncode_command(
        cmd = list_cmd,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if code != 0:
        logger.log_error("List command failed with code %d" % code, quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
