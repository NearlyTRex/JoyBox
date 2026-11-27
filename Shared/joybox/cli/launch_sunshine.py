# Imports
from joybox import system
from joybox import command
from joybox import programs
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "launch_sunshine")
    parser.add_common_arguments()
    return parser

# Run the Sunshine streaming host from its tools folder and wait for it to exit
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get tool
    sunshine_tool = None
    if programs.is_tool_installed("Sunshine"):
        sunshine_tool = programs.get_tool_program("Sunshine")
    if not sunshine_tool:
        logger.log_error("Sunshine was not found", quit_program = True)

    # Get launch command
    launch_cmd = [
        sunshine_tool
    ]

    # Run launch command
    code = command.run_returncode_command(
        cmd = launch_cmd,
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
