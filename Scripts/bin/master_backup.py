#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.lockerinfo as lockerinfo
import joybox.masterbackup as masterbackup
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Setup argument parser
parser = arguments.ArgumentParser(description = "Master backup - back up the local locker (authoritative source) to remote lockers.")
parser.add_enum_argument(
    args = ("-l", "--local_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.LOCAL,
    description = "Authoritative source locker")
parser.add_string_argument(
    args = ("-r", "--remote_lockers"),
    default = "Hetzner,Gdrive",
    description = "Backup destination lockers (comma-separated)")
parser.add_boolean_argument(
    args = ("--no_rebuild_sidecars",),
    description = "Skip refreshing remote hash sidecars after syncing")
parser.add_boolean_argument(
    args = ("--recycle_orphans",),
    description = "Recycle remote files missing from the source (default: keep, additive only)")
parser.add_boolean_argument(
    args = ("--skip_cache",),
    description = "Rebuild hash maps fresh (ignore the 24h cache)")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Parse remote locker types
    remote_locker_types = []
    for locker_str in args.remote_lockers.split(","):
        locker_str = locker_str.strip()
        if locker_str:
            locker_type = config.LockerType.from_string(locker_str)
            if locker_type:
                remote_locker_types.append(locker_type)
            else:
                logger.log_warning("Unknown locker type: %s" % locker_str)
    if not remote_locker_types:
        logger.log_error("No valid remote locker types specified", quit_program = True)

    # Show preview
    if not args.no_preview:
        local_name = lockerinfo.LockerInfo(args.local_locker).get_locker_name()
        details = [
            "Source (authoritative): %s" % local_name,
            "Destinations: %s" % ", ".join([lt.val() for lt in remote_locker_types]),
            "Orphan handling: %s" % ("recycle to .recycle_bin" if args.recycle_orphans else "keep (additive only)"),
            "Rebuild hash sidecars: %s" % ("No" if args.no_rebuild_sidecars else "Yes"),
            "Phase 1: hash source + each destination, compute differences",
            "Phase 2: upload new/changed files to each destination",
        ]
        if not args.no_rebuild_sidecars:
            details.append("Phase 3: refresh remote hash sidecars (e.g. Hetzner)")
        if not prompts.prompt_for_preview("Master backup", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Run backup
    success = masterbackup.run_master_backup(
        local_locker_type = args.local_locker,
        remote_locker_types = remote_locker_types,
        rebuild_sidecars = not args.no_rebuild_sidecars,
        recycle_orphans = args.recycle_orphans,
        skip_cache = args.skip_cache,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if success:
        logger.log_info("Master backup completed successfully")
    else:
        logger.log_error("Master backup failed")
        sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
