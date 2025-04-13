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
import ini
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Sync tool.")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.RemoteActionType,
    default = config.RemoteActionType.INIT,
    description = "Remote action type")
parser.add_string_argument(args = ("--excludes"), default = ",".join(config.excluded_sync_paths), description = "Excludes (comma delimited)")
parser.add_string_argument(args = ("--diff_combined_path"), default = "diff_combined.txt", description = "Diff path (combined)")
parser.add_string_argument(args = ("--diff_intersected_path"), default = "diff_intersected.txt", description = "Diff path (intersection)")
parser.add_string_argument(args = ("--diff_missing_src_path"), default = "diff_missing_src.txt", description = "Diff path (missing src)")
parser.add_string_argument(args = ("--diff_missing_dest_path"), default = "diff_missing_dest.txt", description = "Diff path (missing dest)")
parser.add_string_argument(args = ("--diff_error_path"), default = "diff_errors.txt", description = "Diff path (errors)")
parser.add_boolean_argument(args = ("-e", "--resync"), description = "Enable resync mode")
parser.add_boolean_argument(args = ("-i", "--interactive"), description = "Enable interactive mode")
parser.add_boolean_argument(args = ("-q", "--quick"), description = "Enable quick mode")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Sync options
    remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")
    remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    remote_path = ini.GetIniValue("UserData.Share", "locker_remote_path")
    remote_token = ini.GetIniValue("UserData.Share", "locker_remote_token")
    remote_config = ini.GetIniValue("UserData.Share", "locker_remote_config")
    local_path = ini.GetIniPathValue("UserData.Share", "locker_local_path")
    mount_path = ini.GetIniPathValue("UserData.Share", "locker_remote_mount_path")
    mount_flags = ini.GetIniValue("UserData.Share", "locker_remote_mount_flags").split(",")

    # Init sync
    if args.action == config.RemoteActionType.INIT:
        sync.SetupRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_token = remote_token,
            remote_config = remote_config,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Download files
    elif args.action == config.RemoteActionType.DOWNLOAD:
        sync.DownloadFilesFromRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = args.excludes.split(","),
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Upload files
    elif args.action == config.RemoteActionType.UPLOAD:
        sync.UploadFilesToRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = args.excludes.split(","),
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Pull files
    elif args.action == config.RemoteActionType.PULL:
        sync.PullFilesFromRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = args.excludes.split(","),
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Push files
    elif args.action == config.RemoteActionType.PUSH:
        sync.PushFilesToRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = args.excludes.split(","),
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Merge files
    elif args.action == config.RemoteActionType.MERGE:
        sync.MergeFilesBothWays(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = args.excludes.split(","),
            resync = args.resync,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Diff files
    elif args.action == config.RemoteActionType.DIFF:
        sync.DiffFiles(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = args.excludes.split(","),
            diff_combined_path = args.diff_combined_path,
            diff_intersected_path = args.diff_intersected_path,
            diff_missing_src_path = args.diff_missing_src_path,
            diff_missing_dest_path = args.diff_missing_dest_path,
            diff_error_path = args.diff_error_path,
            quick = args.quick,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # List files
    elif args.action == config.RemoteActionType.LIST:
        sync.ListFiles(
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
        sync.MountFiles(
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
main()
