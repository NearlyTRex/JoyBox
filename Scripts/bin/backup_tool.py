#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import archive
import setup

# Setup argument parser
parser = argparse.ArgumentParser(description="Backup tool.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-t", "--type",
    choices=[
        "Storage",
        "Sync"
    ],
    default="Storage", help="Backup type"
)
parser.add_argument("-u", "--storage_supercategory",
    choices=config.game_supercategories,
    default=config.game_supercategory_roms,
    help="Storage supercategory"
)
parser.add_argument("-c", "--storage_category", type=str, help="Storage category")
parser.add_argument("-s", "--storage_subcategory", type=str, help="Storage subcategory")
parser.add_argument("-n", "--storage_offset", type=str, help="Storage offset")
parser.add_argument("-o", "--output_base_path", type=str, default=".", help="Output base path")
parser.add_argument("-e", "--skip_existing", action="store_true", help="Skip existing files")
parser.add_argument("-i", "--skip_identical", action="store_true", help="Skip identical files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Get output base path
output_base_path = os.path.realpath(args.output_base_path)
if not os.path.exists(output_base_path):
    system.LogError("Output base path '%s' does not exist" % args.output_base_path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = ""
    if args.type == "Storage":
        input_path = os.path.join(environment.GetGamingStorageRootDir(), args.storage_supercategory)
        if args.storage_category:
            input_path = os.path.join(input_path, args.storage_category)
            if args.storage_subcategory:
                input_path = os.path.join(input_path, args.storage_subcategory)
                if args.storage_offset:
                    input_path = os.path.join(input_path, args.storage_offset)
    elif args.type == "Sync":
        input_path = environment.GetSyncRootDir()

    # Check input path
    if not os.path.exists(input_path):
        system.LogError("Input path '%s' does not exist" % input_path)
        sys.exit(1)

    # Backup storage files
    if args.type == "Storage":
        for src_file in system.BuildFileList(input_path):
            dest_file = system.RebaseFilePath(src_file, environment.GetGamingStorageRootDir(), output_base_path)
            system.SmartCopy(
                src = src_file,
                dest = dest_file,
                show_progress = True,
                skip_existing = args.skip_existing,
                skip_identical = args.skip_identical,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

    # Backup sync files
    elif args.type == "Sync":
        for sync_base_obj in system.GetDirectoryContents(input_path):
            sync_base_dir = os.path.join(input_path, sync_base_obj)
            if os.path.isdir(sync_base_dir):
                for sync_sub_obj in system.GetDirectoryContents(sync_base_dir):
                    sync_sub_dir = os.path.join(sync_base_dir, sync_sub_obj)
                    sync_sub_file = os.path.join(output_base_path, sync_base_obj, sync_sub_obj + ".7z")
                    if not os.path.isdir(sync_sub_dir):
                        continue
                    if system.DoesPathExist(sync_sub_file, case_sensitive_paths = False, partial_paths = True):
                        continue
                    system.MakeDirectory(
                        dir = system.GetFilenameDirectory(sync_sub_file),
                        verbose = args.verbose,
                        exit_on_failure = args.exit_on_failure)
                    archive.CreateArchiveFromFolder(
                        archive_file = sync_sub_file,
                        source_dir = sync_sub_dir,
                        volume_size = "4092m",
                        verbose = args.verbose,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
