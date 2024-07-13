#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import sync
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Sync tool.")
parser.add_argument("-a", "--action",
    choices=[
        "init",
        "download",
        "upload",
        "pull",
        "push",
        "merge",
        "diff",
        "list",
        "mount"
    ],
    default="init", help="Sync action"
)
parser.add_argument("--diff_combined_path", type=str, default="diff_combined.txt", help="Diff path (combined)")
parser.add_argument("--diff_intersected_path", type=str, default="diff_intersected.txt", help="Diff path (intersection)")
parser.add_argument("--diff_missing_src_path", type=str, default="diff_missing_src.txt", help="Diff path (missing src)")
parser.add_argument("--diff_missing_dest_path", type=str, default="diff_missing_dest.txt", help="Diff path (missing dest)")
parser.add_argument("--diff_error_path", type=str, default="diff_errors.txt", help="Diff path (errors)")
parser.add_argument("-e", "--resync", action="store_true", help="Enable resync mode")
parser.add_argument("-i", "--interactive", action="store_true", help="Enable interactive mode")
parser.add_argument("-q", "--quick", action="store_true", help="Enable quick mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Sync options
    remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")
    remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    remote_path = ini.GetIniValue("UserData.Share", "locker_remote_path")
    local_path = ini.GetIniPathValue("UserData.Share", "locker_local_path")
    mount_path = ini.GetIniPathValue("UserData.Share", "locker_mount_path")
    mount_flags = ini.GetIniValue("UserData.Share", "locker_mount_flags").split(",")

    # Init sync
    if args.action == "init":
        sync.SetupRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Download files
    elif args.action == "download":
        sync.DownloadFilesFromRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Upload files
    elif args.action == "upload":
        sync.UploadFilesToRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Pull files
    elif args.action == "pull":
        sync.SyncFilesFromRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Push files
    elif args.action == "push":
        sync.SyncFilesToRemote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Merge files
    elif args.action == "merge":
        sync.SyncFilesBothWays(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            resync = args.resync,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Diff files
    elif args.action == "diff":
        sync.CheckFiles(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            diff_combined_path = args.diff_combined_path,
            diff_intersected_path = args.diff_intersected_path,
            diff_missing_src_path = args.diff_missing_src_path,
            diff_missing_dest_path = args.diff_missing_dest_path,
            diff_error_path = args.diff_error_path,
            quick = args.quick,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # List files
    elif args.action == "list":
        sync.ListFiles(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            recursive = True,
            only_directories = False,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Mount files
    elif args.action == "mount":
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
            exit_on_failure = args.exit_on_failure)

# Start
main()
