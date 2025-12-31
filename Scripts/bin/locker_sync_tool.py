#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import lockersync
import arguments
import setup
import logger

# Setup argument parser
parser = arguments.ArgumentParser(description = "Locker sync tool - sync between primary and secondary lockers.")
parser.add_enum_argument(
    args = ("-l", "--primary_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Primary locker type (authoritative source)")
parser.add_string_argument(
    args = ("-s", "--secondary_lockers"),
    default = "Gdrive,External",
    description = "Secondary locker types (comma-separated)")
parser.add_boolean_argument(
    args = ("--skip_cache",),
    description = "Skip using cached hash maps (rebuild fresh)")
parser.add_boolean_argument(
    args = ("--clear_cache",),
    description = "Clear all cached hash maps before running")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Parse secondary locker types
    secondary_locker_types = []
    for locker_str in args.secondary_lockers.split(","):
        locker_str = locker_str.strip()
        if locker_str:
            locker_type = config.LockerType.from_string(locker_str)
            if locker_type:
                secondary_locker_types.append(locker_type)
            else:
                logger.log_warning("Unknown locker type: %s" % locker_str)
    if not secondary_locker_types:
        logger.log_error("No valid secondary locker types specified", quit_program = True)

    # Clear cache if requested
    if args.clear_cache:
        logger.log_info("Clearing hash map cache...")
        lockersync.clear_cache()

    # Log configuration
    logger.log_info("Primary locker: %s" % args.primary_locker)
    logger.log_info("Secondary lockers: %s" % ", ".join([lt.val() for lt in secondary_locker_types]))

    # Run sync
    success = lockersync.sync_lockers(
        primary_locker_type = args.primary_locker,
        secondary_locker_types = secondary_locker_types,
        skip_cache = args.skip_cache,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if success:
        logger.log_info("Locker sync completed successfully")
    else:
        logger.log_error("Locker sync failed")
        sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
