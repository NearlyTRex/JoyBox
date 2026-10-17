# Imports
import joybox.system as system
import joybox.command as command
import joybox.programs as programs
import joybox.arguments as arguments
import joybox.settings as settings
import joybox.setup as setup
import joybox.logger as logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Start the Moonlight game-streaming client installed by setup_tools.",
        details = (
            "Runs the Moonlight program from the tools directory. With a host, from `--host` or\n"
            "`[Tools.Moonlight] moonlight_host`, it streams that host's app straight away, from\n"
            "`--app` or `[Tools.Moonlight] moonlight_app` (Pegasus by default). Without one it\n"
            "opens Moonlight's host list.\n"
            "\n"
            "`--pair` pairs with the host instead: Moonlight shows a PIN, which is entered on the\n"
            "host's Sunshine web page (port 47990). A host only has to be paired once.\n"
            "\n"
            "It waits for Moonlight to exit and logs an error if it exits with a non-zero code."),
        examples = [
            ("Stream the configured host's app", "launch_moonlight"),
            ("Pair with a host", "launch_moonlight --host 192.168.1.20 --pair"),
            ("Stream Steam Big Picture from a host", "launch_moonlight --host 192.168.1.20 --app \"Steam Big Picture\""),
        ],
        notes = [
            "Moonlight must be installed first (`setup_tools -k Moonlight`); the command exits with an error if it is not found.",
            "Set `[Tools.Moonlight] moonlight_autostart` and install the bootstrap's `autostart` component to start it at every login.",
        ],
        see_also = ["setup_tools", "launch_sunshine"],
        section = "Game Launching")
    parser.add_group("Stream")
    parser.add_string_argument(args = ("--host"), description = "Sunshine host to stream from, by address or name; defaults to `[Tools.Moonlight] moonlight_host`")
    parser.add_string_argument(args = ("--app"), description = "App on the host to start; defaults to `[Tools.Moonlight] moonlight_app`")
    parser.add_boolean_argument(args = ("--pair"), description = "Pair with the host instead of streaming")
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
    moonlight_tool = None
    if programs.is_tool_installed("Moonlight"):
        moonlight_tool = programs.get_tool_program("Moonlight")
    if not moonlight_tool:
        logger.log_error("Moonlight was not found", quit_program = True)

    # Get host and app
    host = args.host or settings.get_value("Tools.Moonlight", "moonlight_host", "", throw_exception = False)
    app = args.app or settings.get_value("Tools.Moonlight", "moonlight_app", "", throw_exception = False)
    if args.pair and not host:
        logger.log_error("Pairing needs a host, from --host or [Tools.Moonlight] moonlight_host", quit_program = True)

    # Get launch command
    launch_cmd = [moonlight_tool]
    if args.pair:
        launch_cmd += ["pair", host]
    elif host and app:
        launch_cmd += ["stream", host, app]

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
