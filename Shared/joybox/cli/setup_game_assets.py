# Imports
from joybox import arguments
from joybox import system
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "setup_game_assets")
    parser.add_common_arguments()
    return parser

# Symlink the Pegasus asset folders of every category to the locker's artwork folders, creating missing targets
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Setup assets
    setup.setup_assets(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
