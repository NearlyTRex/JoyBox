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
parser.add_argument("-b", "--backup_type",
    choices=[
        config.backup_type_copy,
        config.backup_type_archive
    ],
    default=config.backup_type_copy, help="Backup type"
)
parser.add_argument("-l", "--source_type",
    choices=[
        config.source_type_local,
        config.source_type_remote
    ],
    default=config.source_type_local, help="Source type"
)
parser.add_argument("-u", "--gaming_supercategory", type=str, help="Gaming supercategory")
parser.add_argument("-c", "--gaming_category", type=str, help="Gaming category")
parser.add_argument("-s", "--gaming_subcategory", type=str, help="Gaming subcategory")
parser.add_argument("-n", "--gaming_offset", type=str, help="Gaming offset")
parser.add_argument("-d", "--exclude_paths", type=str, default="", help="Excluded paths (comma separated list)")
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
    input_path = environment.GetLockerRootDir(args.source_type)
    if args.supercategory:
        input_path = os.path.join(input_path, config.locker_type_gaming, args.supercategory)
        if args.category:
            input_path = os.path.join(input_path, args.category)
            if args.subcategory:
                input_path = os.path.join(input_path, args.subcategory)
                if args.offset:
                    input_path = os.path.join(input_path, args.offset)

    # Get exclude paths
    exclude_paths = args.exclude_paths.split(",")

    # Check input path
    if not os.path.exists(input_path):
        system.LogError("Input path '%s' does not exist" % input_path)
        sys.exit(1)

    # Copy files
    if args.backup_type == config.backup_type_copy:
        for src_file in system.BuildFileList(input_path, excludes = exclude_paths, use_relative_paths = True):
            system.SmartCopy(
                src = os.path.join(input_path, src_file),
                dest = os.path.join(output_base_path, src_file),
                show_progress = True,
                skip_existing = args.skip_existing,
                skip_identical = args.skip_identical,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

    # Archive files
    elif args.backup_type == config.backup_type_archive:
        for base_obj in system.GetDirectoryContents(input_path, excludes = exclude_paths):
            base_dir = os.path.join(input_path, base_obj)
            if os.path.isdir(base_dir):
                for sub_obj in system.GetDirectoryContents(base_dir):
                    sub_dir = os.path.join(base_dir, sub_obj)
                    sub_file = os.path.join(output_base_path, base_obj, sub_obj + ".7z")
                    if not os.path.isdir(sub_dir):
                        continue
                    if system.DoesPathExist(sub_file, case_sensitive_paths = False, partial_paths = True):
                        continue
                    system.MakeDirectory(
                        dir = system.GetFilenameDirectory(sub_file),
                        verbose = args.verbose,
                        exit_on_failure = args.exit_on_failure)
                    archive.CreateArchiveFromFolder(
                        archive_file = sub_file,
                        source_dir = sub_dir,
                        volume_size = "4092m",
                        verbose = args.verbose,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
