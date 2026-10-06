# Imports
import joybox.system as system
import joybox.command as command
import joybox.programs as programs
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Start the Sunshine game-streaming host installed by setup_tools.",
        details = (
            "Runs the Sunshine program from the tools directory so a Moonlight client can stream\n"
            "games from this machine. It waits for Sunshine to exit and logs an error if it exits\n"
            "with a non-zero code. It takes only the common options."),
        examples = [
            ("Start Sunshine", "launch_sunshine"),
            ("Dry run without starting Sunshine", "launch_sunshine -p -v"),
        ],
        notes = [
            "Sunshine must be installed first (`setup_tools -k Sunshine`); the command exits with an error if it is not found.",
        ],
        see_also = ["setup_tools", "launch_pegasus"],
        section = "Game Launching")
    parser.add_common_arguments()
    return parser

# Main
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

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
