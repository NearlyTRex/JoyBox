# Imports
from joybox import system
from joybox.tools import moonlight
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "launch_moonlight")
    parser.add_group("Stream")
    parser.add_string_argument(args = ("--host"), description = "Sunshine host to stream from, by address or name; defaults to `[Tools.Moonlight] moonlight_host`")
    parser.add_string_argument(args = ("--app"), description = "App on the host to start; defaults to `[Tools.Moonlight] moonlight_app`")
    parser.add_boolean_argument(args = ("--pair"), description = "Pair with the host instead of streaming")
    parser.add_boolean_argument(args = ("--list"), description = "List the apps the host offers instead of streaming")
    parser.add_common_arguments()
    return parser

# Start Moonlight streaming the configured or given host and app, or pair with the host
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Launch Moonlight
    moonlight.launch_moonlight(
        host = args.host,
        app = args.app,
        pair = args.pair,
        list_apps = args.list,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
