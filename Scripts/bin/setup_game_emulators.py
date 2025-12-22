#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import arguments
import system
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Setup emulators.")
parser.add_boolean_argument(args = ("-e", "--offline"), description = "Enable offline mode")
parser.add_boolean_argument(args = ("-c", "--configure"), description = "Enable configuration mode")
parser.add_boolean_argument(args = ("-l", "--clean"), description = "Clean emulators directory before setup")
parser.add_boolean_argument(args = ("-f", "--force"), description = "Force rebuild of packages (even if already installed)")
parser.add_string_argument(args = ("-k", "--packages"), description = "Comma-separated list of package names to install (default: all)")
parser.add_enum_argument(
    args = ("-r", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.ALL,
    description = "Locker type for backup upload")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Parse package list
    packages = None
    if args.packages:
        packages = [p.strip() for p in args.packages.split(",")]

    # Create setup params from args
    setup_params = config.SetupParams.from_args(args)

    # Setup emulators
    setup.SetupEmulators(
        offline = args.offline,
        configure = args.configure,
        clean = args.clean,
        force = args.force,
        packages = packages,
        setup_params = setup_params)

# Start
if __name__ == "__main__":
    system.run_main(main)
