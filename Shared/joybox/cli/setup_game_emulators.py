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
    parser.add_group("Selection")
    parser.add_boolean_argument(args = ("-e", "--offline"), description = "Install from the copies backed up in the locker instead of downloading")
    parser.add_boolean_argument(args = ("-c", "--configure"), description = "Run each emulator's configuration step after installing it")
    parser.add_boolean_argument(args = ("--clean",), description = "Remove the entire emulators directory before installing anything")
    parser.add_boolean_argument(args = ("-f", "--force"), description = "Remove each selected emulator's install directory and reinstall it, even if already installed")
    parser.add_string_argument(args = ("-k", "--packages"), description = "Comma-separated emulator names to install, e.g. `\"Dolphin,PCSX2\"`; all emulators when omitted")
    parser.add_group("Backup")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.ALL,
        description = "Locker to back downloaded release files up to")
    parser.add_boolean_argument(args = ("-s", "--skip_autobackup"), description = "Do not back downloaded release files up to the locker")
    parser.add_common_arguments()
    return parser

# Install, update or rebuild the selected emulators, or all of them, with the setup options given
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Parse package list
    packages = None
    if args.packages:
        packages = [p.strip() for p in args.packages.split(",") if p.strip()]
        known_packages = [package.get_name() for package in emulators.get_emulator_list()]
        unknown_packages = [package for package in packages if package not in known_packages]
        if unknown_packages:
            logger.log_error("Unknown emulator packages: %s" % ", ".join(unknown_packages), quit_program = True)

    # Create setup params from args
    setup_params = config.SetupParams.from_args(args)

    # Setup emulators
    success = setup.setup_emulators(
        offline = args.offline,
        configure = args.configure,
        clean = args.clean,
        force = args.force,
        packages = packages,
        setup_params = setup_params)
    if not success:
        logger.log_error("Setup of emulators failed", quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
