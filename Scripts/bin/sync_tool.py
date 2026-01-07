#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import sync
import lockerinfo
import arguments
import setup
import logger
import prompts
import paths

# Parse arguments
parser = arguments.ArgumentParser(description = "Sync tool.")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.RemoteActionType,
    default = config.RemoteActionType.INIT,
    description = "Remote action type")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker type")
parser.add_string_argument(args = ("--excludes"), default = "", description = "Excludes (comma delimited, defaults to locker config)")
parser.add_string_argument(args = ("--diff_combined_path"), default = "diff_combined.txt", description = "Diff path (combined)")
parser.add_string_argument(args = ("--diff_intersected_path"), default = "diff_intersected.txt", description = "Diff path (intersection)")
parser.add_string_argument(args = ("--diff_missing_src_path"), default = "diff_missing_src.txt", description = "Diff path (missing src)")
parser.add_string_argument(args = ("--diff_missing_dest_path"), default = "diff_missing_dest.txt", description = "Diff path (missing dest)")
parser.add_string_argument(args = ("--diff_error_path"), default = "diff_errors.txt", description = "Diff path (errors)")
parser.add_string_argument(args = ("--diff_dir"), description = "Directory containing diff files")
parser.add_boolean_argument(args = ("-e", "--resync"), description = "Enable resync mode")
parser.add_boolean_argument(args = ("-i", "--interactive"), description = "Enable interactive mode")
parser.add_boolean_argument(args = ("-q", "--quick"), description = "Enable quick mode")
parser.add_boolean_argument(args = ("-r", "--recycle_missing"), description = "Move remote-only files to recycle bin instead of downloading")
parser.add_string_argument(args = ("--recycle_folder"), default = ".recycle_bin", description = "Folder name for recycled files on remote")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get locker info
    locker_info = lockerinfo.LockerInfo(args.locker_type)
    if not locker_info:
        logger.log_error("Invalid locker", quit_program = True)

    # Sync options
    remote_type = locker_info.get_type()
    remote_name = locker_info.get_name()
    remote_path = locker_info.get_remote_path()
    remote_token = locker_info.get_token()
    remote_config = locker_info.get_config()
    local_path = locker_info.get_mount_path()
    mount_path = locker_info.get_mount_path()
    mount_flags = locker_info.get_mount_flags()

    # Actions that require local/mount path to exist
    actions_requiring_local_path = [
        config.RemoteActionType.DOWNLOAD,
        config.RemoteActionType.UPLOAD,
        config.RemoteActionType.PULL,
        config.RemoteActionType.PUSH,
        config.RemoteActionType.MERGE,
        config.RemoteActionType.DIFF,
        config.RemoteActionType.DIFFSYNC,
    ]

    # Validate local path exists for actions that need it
    if args.action in actions_requiring_local_path:
        if not local_path:
            logger.log_error("Action '%s' requires a mount path, but none is configured for locker '%s'" % (
                args.action, args.locker_type), quit_program = True)
        if not paths.does_path_exist(local_path):
            logger.log_error("Action '%s' requires mount path to exist: %s\nTry mounting first with: sync_tool -a Mount -l %s" % (
                args.action, local_path, args.locker_type), quit_program = True)

    # Get excludes from CLI or locker config
    if args.excludes:
        excludes = [e.strip() for e in args.excludes.split(",") if e.strip()]
    else:
        excludes = locker_info.get_excluded_dirs()

    # Show preview
    if not args.no_preview:
        details = []
        if local_path:
            details.append("Local: %s" % local_path)
        if remote_path:
            details.append("Remote: %s:%s" % (remote_name, remote_path))
        if mount_path:
            details.append("Mount: %s" % mount_path)
        if not prompts.prompt_for_preview("Sync %s (%s)" % (args.action, args.locker_type), details):
            logger.log_warning("Operation cancelled by user")
            return

    # Init sync
    if args.action == config.RemoteActionType.INIT:
        sync.setup_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_token = remote_token,
            remote_config = remote_config,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Download files
    elif args.action == config.RemoteActionType.DOWNLOAD:
        sync.download_files_from_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Upload files
    elif args.action == config.RemoteActionType.UPLOAD:
        sync.upload_files_to_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Pull files
    elif args.action == config.RemoteActionType.PULL:
        sync.pull_files_from_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Push files
    elif args.action == config.RemoteActionType.PUSH:
        sync.push_files_to_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Merge files
    elif args.action == config.RemoteActionType.MERGE:
        sync.merge_files_both_ways(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            resync = args.resync,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Diff files
    elif args.action == config.RemoteActionType.DIFF:
        diff_excludes = list(excludes)
        if args.recycle_folder:
            diff_excludes.append(args.recycle_folder + "/**")
        sync.diff_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = diff_excludes,
            diff_combined_path = args.diff_combined_path,
            diff_intersected_path = args.diff_intersected_path,
            diff_missing_src_path = args.diff_missing_src_path,
            diff_missing_dest_path = args.diff_missing_dest_path,
            diff_error_path = args.diff_error_path,
            quick = args.quick,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Diff sync files
    elif args.action == config.RemoteActionType.DIFFSYNC:
        diffsync_excludes = list(excludes)
        if args.recycle_folder:
            diffsync_excludes.append(args.recycle_folder + "/**")
        sync.diff_sync_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = diffsync_excludes,
            diff_dir = args.diff_dir,
            diff_combined_file = args.diff_combined_path,
            diff_intersected_file = args.diff_intersected_path,
            diff_missing_src_file = args.diff_missing_src_path,
            diff_missing_dest_file = args.diff_missing_dest_path,
            recycle_missing = args.recycle_missing,
            recycle_folder = args.recycle_folder,
            quick = args.quick,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Empty recycle bin
    elif args.action == config.RemoteActionType.EMPTYRECYCLE:
        sync.empty_recycle_bin(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            recycle_folder = args.recycle_folder,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # List files
    elif args.action == config.RemoteActionType.LIST:
        sync.list_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            recursive = True,
            only_directories = False,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Mount files
    elif args.action == config.RemoteActionType.MOUNT:
        sync.mount_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            mount_path = mount_path,
            no_cache = "no_cache" in mount_flags,
            no_checksum = "no_checksum" in mount_flags,
            no_modtime = "no_modtime" in mount_flags,
            no_seek = "no_seek" in mount_flags,
            read_only = "read_only" in mount_flags,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
