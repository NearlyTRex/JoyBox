#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import archive
import system
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Compress folders.")
parser.add_argument("path", help="Input path")
parser.add_argument("-a", "--archive_type",
    choices=[
        config.archive_type_zip,
        config.archive_type_7z
    ],
    default=config.archive_type_zip, help="Archive type"
)
parser.add_argument("-p", "--password", type=str, help="Password to set")
parser.add_argument("-s", "--volume_size", type=str, help="Volume size for output files (100m, etc)")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
root_path = os.path.realpath(args.path)
if not os.path.exists(root_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Compress folders
    for obj in system.GetDirectoryContents(root_path):
        obj_path = os.path.join(root_path, obj)
        if not os.path.isdir(obj_path):
            continue

        # Get output file
        output_file = output_file = os.path.join(root_path, obj + "." + args.archive_type)
        if os.path.exists(output_file):
            continue

        # Compress folder
        archive.CreateArchiveFromFolder(
            archive_file = output_file,
            source_dir = obj_path,
            password = args.password,
            volume_size = args.volume_size,
            delete_original = args.delete_originals,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Start
main()
