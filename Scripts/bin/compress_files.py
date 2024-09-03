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
import archive
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Compress files.")
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
parser.add_argument("-t", "--file_types", type=str, default="", help="List of file types (comma delimited)")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Check that path exists first
root_path = os.path.realpath(args.path)
if not os.path.exists(root_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Compress files
    for obj in system.GetDirectoryContents(root_path):
        obj_path = os.path.join(root_path, obj)
        if not os.path.isfile(obj_path):
            continue

        # Check file type
        should_compress = False
        for file_type in args.file_types.split(","):
            if obj_path.endswith(file_type):
                should_compress = True
        if not should_compress:
            continue

        # Get output file
        output_file = output_file = os.path.join(root_path, system.GetFilenameBasename(obj_path) + "." + args.archive_type)
        if os.path.exists(output_file):
            continue

        # Compress file
        archive.CreateArchiveFromFile(
            archive_file = output_file,
            source_file = obj_path,
            password = args.password,
            volume_size = args.volume_size,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
