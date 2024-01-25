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

# Parse arguments
parser = argparse.ArgumentParser(description="Sync tool.")
parser.add_argument("-t", "--type",
    choices=[
        config.sync_type_gdrive
    ],
    default=config.sync_type_gdrive, help="Sync type"
)
parser.add_argument("-a", "--action",
    choices=[
        "init",
        "download",
        "upload",
        "pull",
        "push",
        "merge",
        "diff"
    ],
    default="init", help="Sync action"
)
parser.add_argument("-l", "--local_path", type=str, default=environment.GetSyncRootDir(), help="Local path")
parser.add_argument("-r", "--remote_path", type=str, default="/", help="Remote path")
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

    # Init sync
    if args.action == "init":
        if args.type == config.sync_type_gdrive:
            sync.SetupGoogleDriveRemote(
                remote_type = args.type,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

    # Download files
    elif args.action == "download":
        sync.DownloadFilesFromRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Upload files
    elif args.action == "upload":
        sync.UploadFilesToRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Pull files
    elif args.action == "pull":
        sync.SyncFilesFromRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Push files
    elif args.action == "push":
        sync.SyncFilesToRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Merge files
    elif args.action == "merge":
        sync.SyncFilesBothWays(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            resync = args.resync,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Diff files
    elif args.action == "diff":
        sync.CheckFiles(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            diff_combined_path = args.diff_combined_path,
            diff_intersected_path = args.diff_intersected_path,
            diff_missing_src_path = args.diff_missing_src_path,
            diff_missing_dest_path = args.diff_missing_dest_path,
            diff_error_path = args.diff_error_path,
            quick = args.quick,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
