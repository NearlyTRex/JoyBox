#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import lockerinfo
import sync
import paths
import arguments
import setup
import logger
import prompts
import reports

# Setup argument parser
parser = arguments.ArgumentParser(description = "Find files on remote that are missing hash sidecars.")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Remote locker to check")
parser.add_string_argument(
    args = ("--path",),
    default = "",
    description = "Specific subpath to check (e.g., 'Gaming/Roms'). Leave empty for root.")
parser.add_string_argument(
    args = ("-r", "--report"),
    default = "",
    description = "Path to write full report file (optional)")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get remote locker info
    remote_info = lockerinfo.LockerInfo(args.locker_type)
    if not remote_info:
        logger.log_error("Could not get locker info for %s" % args.locker_type, quit_program = True)

    # Get remote details
    remote_name = remote_info.get_name()
    remote_type = remote_info.get_type()
    locker_root = remote_info.get_remote_path() or ""
    remote_path = locker_root
    subpath = args.path or ""

    # Apply subpath if specified
    if subpath:
        remote_path = paths.join_paths(locker_root, subpath).replace("\\", "/")

    # Validate
    if not sync.is_remote_configured(remote_name, remote_type):
        logger.log_error("Remote '%s' is not configured" % remote_name, quit_program = True)

    # Log action
    logger.log_info("Checking for missing hash sidecars on %s" % args.locker_type)
    logger.log_info("Remote path: %s:%s" % (remote_name, remote_path))

    # Get all files on remote (with hashes if available)
    logger.log_info("Listing remote files...")
    remote_files = sync.list_files_with_hashes(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        excludes = [sync.HASH_DATABASE_FILE],
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    logger.log_info("Found %d files on remote" % len(remote_files))

    # Get files covered by sidecars (always read from locker root)
    logger.log_info("Listing hash sidecars...")
    sidecar_files = sync.list_files_with_hashes_from_sidecar(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = locker_root,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    logger.log_info("Found %d files in sidecars" % len(sidecar_files))

    # Find missing - need to prefix remote_files paths with subpath for comparison
    missing = []
    for rel_path in remote_files.keys():
        full_rel_path = paths.join_paths(subpath, rel_path).replace("\\", "/") if subpath else rel_path
        if full_rel_path not in sidecar_files:
            missing.append(rel_path)

    # Report
    if missing:
        sorted_missing = sorted(missing)
        logger.log_warning("Files missing hash sidecars:")
        reports.write_list_report(
            items = sorted_missing,
            max_display = 20,
            report_file = args.report if args.report else None,
            verbose = args.verbose,
            pretend_run = args.pretend_run)
    else:
        logger.log_info("All files have hash sidecars")

# Start
if __name__ == "__main__":
    system.run_main(main)
