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

# Setup argument parser
parser = arguments.ArgumentParser(description = "Rebuild hash sidecar files on a remote from local content.")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Remote locker to rebuild hashes for")
parser.add_string_argument(
    args = ("--path",),
    default = "",
    description = "Specific subpath to rebuild (e.g., 'Gaming/Roms'). Leave empty for root.")
parser.add_boolean_argument(
    args = ("-c", "--clear"),
    description = "Clear existing sidecars before rebuilding")
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

    # Get local locker info
    local_info = lockerinfo.LockerInfo(config.LockerType.LOCAL)
    if not local_info:
        logger.log_error("Could not get local locker info", quit_program = True)

    # Get paths
    local_root = local_info.get_mount_path()
    remote_name = remote_info.get_name()
    remote_type = remote_info.get_type()
    locker_root = remote_info.get_remote_path() or ""
    remote_path = locker_root

    # Apply subpath if specified
    local_path = local_root
    if args.path:
        local_path = paths.join_paths(local_root, args.path)
        remote_path = paths.join_paths(locker_root, args.path).replace("\\", "/")

    # Validate
    if not paths.does_path_exist(local_path):
        logger.log_error("Local path not accessible: %s" % local_path, quit_program = True)
    if not sync.is_remote_configured(remote_name, remote_type):
        logger.log_error("Remote '%s' is not configured" % remote_name, quit_program = True)

    # Log action
    logger.log_info("Rebuilding hash sidecars for %s" % args.locker_type)
    logger.log_info("Local source: %s" % local_path)
    logger.log_info("Remote target: %s:%s" % (remote_name, remote_path))
    logger.log_info("Locker root: %s:%s" % (remote_name, locker_root))

    # Clear existing sidecars if requested (always clear at locker root)
    if args.clear:
        logger.log_info("Clearing existing sidecars...")
        if not sync.clear_hash_sidecar_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = locker_root,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure):
            logger.log_error("Failed to clear sidecars")
            sys.exit(1)

    # Rebuild
    success = sync.upload_hash_sidecar_files(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        local_path = local_path,
        local_root = locker_root,
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
