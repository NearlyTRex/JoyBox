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
import backup
import setup

# Setup argument parser
parser = argparse.ArgumentParser(description="Backup tool.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-b", "--backup_type",
    choices=config.BackupType.values(),
    default=config.BackupType.COPY.value,
    type=config.BackupType,
    action=config.EnumArgparseAction,
    help="Backup type"
)
parser.add_argument("-i", "--input_path", type=str, help="Input path")
parser.add_argument("-o", "--output_path", type=str, help="Output path")
parser.add_argument("-u", "--game_supercategory",
    choices=config.game_supercategories,
    default=config.game_supercategory_roms,
    help="Game supercategory"
)
parser.add_argument("-c", "--game_category", type=str, help="Game category")
parser.add_argument("-s", "--game_subcategory", type=str, help="Game subcategory")
parser.add_argument("-n", "--gaming_offset", type=str, help="Game offset")
parser.add_argument("-l", "--source_type",
    choices=config.SourceType.values(),
    default=config.SourceType.LOCAL.value,
    type=config.SourceType,
    action=config.EnumArgparseAction,
    help="Source type"
)
parser.add_argument("-q", "--destination_type",
    choices=config.SourceType.values(),
    default=config.SourceType.LOCAL.value,
    type=config.SourceType,
    action=config.EnumArgparseAction,
    help="Destination type"
)
parser.add_argument("-w", "--exclude_paths", type=str, default="", help="Excluded paths (comma separated list)")
parser.add_argument("-e", "--skip_existing", action="store_true", help="Skip existing files")
parser.add_argument("-a", "--skip_identical", action="store_true", help="Skip identical files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get source file root
    source_file_root = backup.ResolvePath(
        path = args.input_path,
        source_type = args.source_type,
        game_supercategory = args.game_supercategory,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_offset = args.game_offset)
    if not system.IsPathDirectory(source_file_root):
        system.LogErrorAndQuit("Could not resolve source path")

    # Get destination file root
    dest_file_root = backup.ResolvePath(
        path = args.output_path,
        source_type = args.destination_type,
        game_supercategory = args.game_supercategory,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_offset = args.game_offset)
    if not system.IsPathDirectory(dest_file_root):
        system.LogErrorAndQuit("Could not resolve destination path")

    # Copy files
    if args.backup_type == config.BackupType.COPY:
        backup.CopyFiles(
            input_base_path = source_file_root,
            output_base_path = dest_file_root,
            exclude_paths = args.exclude_paths.split(","),
            show_progress = True,
            skip_existing = args.skip_existing,
            skip_identical = args.skip_identical,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Archive files
    elif args.backup_type == config.BackupType.ARCHIVE:
        backup.ArchiveFiles(
            input_base_path = source_file_root,
            output_base_path = dest_file_root,
            archive_type = config.ArchiveType.SEVENZIP,
            exclude_paths = args.exclude_paths.split(","),
            show_progress = True,
            skip_existing = args.skip_existing,
            skip_identical = args.skip_identical,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
main()
