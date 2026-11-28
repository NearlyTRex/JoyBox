# Imports
from joybox import system
from joybox.tools import pegasus
from joybox import arguments
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "launch_pegasus")
    parser.add_common_arguments()
    return parser

# Run Pegasus from its tools folder with JOYBOX_LAUNCH_JSON set to the launcher command, and wait for it to exit
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Launch Pegasus
    pegasus.Pegasus().launch(verbose = args.verbose, pretend_run = args.pretend_run, exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
