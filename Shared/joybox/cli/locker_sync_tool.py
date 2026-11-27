# Imports
import sys
from joybox import config
from joybox import system
from joybox import lockersync
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "locker_sync_tool")
    parser.add_enum_argument(
        args = ("-l", "--primary_locker"),
        arg_type = config.LockerType,
        default = config.LockerType.HETZNER,
        description = "Authoritative locker that the secondaries are brought in line with")
    parser.add_string_argument(
        args = ("-s", "--secondary_lockers"),
        default = "Gdrive,External",
        description = "Comma-separated locker names to update; an unknown name stops the run")
    parser.add_boolean_argument(
        args = ("--skip_cache",),
        description = "Rebuild every hash map instead of reusing one cached within the last 24 hours")
    parser.add_boolean_argument(
        args = ("--clear_cache",),
        description = "Delete every cached hash map before starting, not just those of the lockers in this run")
    parser.add_common_arguments()
    return parser

# Sync the primary locker to each secondary, reviewing the planned changes in an editor before applying them
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Run sync
    success = lockersync.run_locker_sync(
        primary_locker_type = args.primary_locker,
        secondary_locker_names = args.secondary_lockers,
        skip_cache = args.skip_cache,
        clear_hash_cache = args.clear_cache,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        sys.exit(1)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
