# Imports
from joybox import system
from joybox.tools import sunshine
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

    # Launch Sunshine
    sunshine.Sunshine().launch(verbose = args.verbose, pretend_run = args.pretend_run, exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
