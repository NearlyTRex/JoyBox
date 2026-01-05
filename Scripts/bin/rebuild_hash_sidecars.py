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

# Setup argument parser
parser = arguments.ArgumentParser(description = "Rebuild hash sidecar files on a remote from local content.")
parser.add_enum_argument(
    args = ("-l", "--source_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.LOCAL,
    description = "Source locker type")
parser.add_enum_argument(
    args = ("-d", "--dest_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Destination locker for hash sidecars")
parser.add_string_argument(
    args = ("--path",),
    default = "",
    description = "Specific subpath to rebuild (e.g., 'Gaming/Roms'). Leave empty for root.")
parser.add_boolean_argument(
    args = ("-c", "--clear"),
    description = "Clear existing sidecars before rebuilding")
parser.add_boolean_argument(
    args = ("-s", "--skip_existing"),
    description = "Skip files that already have hashes in database")
parser.add_integer_argument(
    args = ("-r", "--parallel_dirs"),
    default = 4,
    description = "Number of directories to process in parallel")
parser.add_integer_argument(
    args = ("-f", "--parallel_files"),
    default = 4,
    description = "Number of files to hash in parallel per directory")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get source locker info
    source_info = lockerinfo.LockerInfo(args.source_locker)
    if not source_info:
        logger.log_error("Could not get locker info for %s" % args.source_locker, quit_program = True)

    # Get dest locker info
    dest_info = lockerinfo.LockerInfo(args.dest_locker)
    if not dest_info:
        logger.log_error("Could not get locker info for %s" % args.dest_locker, quit_program = True)

    # Get paths
    source_root = source_info.get_mount_path()
    dest_name = dest_info.get_name()
    dest_type = dest_info.get_type()
    dest_root = dest_info.get_remote_path() or ""
    dest_path = dest_root

    # Apply subpath if specified
    source_path = source_root
    if args.path:
        source_path = paths.join_paths(source_root, args.path)
        dest_path = paths.join_paths(dest_root, args.path).replace("\\", "/")

    # Validate
    if not paths.does_path_exist(source_path):
        logger.log_error("Source path not accessible: %s" % source_path, quit_program = True)
    if not sync.is_remote_configured(dest_name, dest_type):
        logger.log_error("Remote '%s' is not configured" % dest_name, quit_program = True)

    # Show preview
    if not args.no_preview:
        db_path = sync.get_hash_database_path(dest_root)
        details = [
            "Source: %s" % source_path,
            "Destination: %s:%s" % (dest_name, db_path)
        ]
        if args.clear:
            details.append("Clear existing sidecars: Yes")
        if args.skip_existing:
            details.append("Skip existing sidecars: Yes")
        if not prompts.prompt_for_preview("Rebuild hash sidecars", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Clear existing sidecars if requested (always clear at dest root)
    if args.clear:
        logger.log_info("Clearing existing sidecars...")
        if not sync.clear_hash_sidecar_files(
            remote_name = dest_name,
            remote_type = dest_type,
            remote_path = dest_root,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure):
            logger.log_error("Failed to clear sidecars")
            sys.exit(1)

    # Rebuild
    success = sync.upload_hash_sidecar_files(
        remote_name = dest_name,
        remote_type = dest_type,
        remote_path = dest_path,
        local_path = source_path,
        local_root = dest_root,
        skip_existing = args.skip_existing,
        parallel_dirs = args.parallel_dirs,
        parallel_files = args.parallel_files,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if success:
        logger.log_info("Rebuild complete")
    else:
        logger.log_error("Rebuild failed")
        sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
