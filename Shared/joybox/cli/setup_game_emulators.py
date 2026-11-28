# Imports
from joybox import emulators
from joybox import config
from joybox import arguments
from joybox import system
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "setup_game_emulators")
    parser.add_package_setup_arguments("emulator", "emulators", "Dolphin,PCSX2")
    parser.add_common_arguments()
    return parser

# Install, update or rebuild the selected emulators, or all of them, with the setup options given
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Setup the selected emulators, after checking their names
    success = setup.setup_emulators(
        offline = args.offline,
        configure = args.configure,
        clean = args.clean,
        force = args.force,
        packages = parser.get_selected_packages([package.get_name() for package in emulators.get_emulator_list()], "emulator"),
        setup_params = config.SetupParams.from_args(args))
    if not success:
        logger.log_error("Setup of emulators failed", quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
