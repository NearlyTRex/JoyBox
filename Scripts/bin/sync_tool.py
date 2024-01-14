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
parser.add_argument("-e", "--resync", action="store_true", help="Enable resync mode")
parser.add_argument("-i", "--interactive", action="store_true", help="Enable interactive mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Init sync
    if args.action == "init":
        if args.type == config.sync_type_gdrive:
            sync.SetupGoogleDriveRemote(
                remote_type = args.type,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Download files
    elif args.action == "download":
        sync.DownloadFilesFromRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = exit_on_failure)

    # Upload files
    elif args.action == "upload":
        sync.UploadFilesToRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = exit_on_failure)

    # Pull files
    elif args.action == "pull":
        sync.SyncFilesFromRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = exit_on_failure)

    # Push files
    elif args.action == "push":
        sync.SyncFilesToRemote(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            interactive = args.interactive,
            verbose = verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = exit_on_failure)

    # Merge files
    elif args.action == "merge":
        sync.SyncFilesBothWays(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            resync = args.resync,
            interactive = args.interactive,
            verbose = verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = exit_on_failure)

    # Diff files
    elif args.action == "diff":
        sync.CheckFiles(
            local_path = args.local_path,
            remote_type = args.type,
            remote_path = args.remote_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Start
main()
