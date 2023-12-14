#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import archive
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Decompress archive files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--archive_types", type=str, default=".zip,.7z,.rar", help="List of archive types (comma delimited)")
parser.add_argument("-s", "--same_dir", action="store_true", help="Extract to same directory as original file")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
root_path = os.path.realpath(args.path)
if not os.path.exists(root_path):
    print("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Decompress archives
    for file in system.BuildFileListByExtensions(root_path, extensions = args.archive_types.split(",")):

        # Get file info
        current_file = file
        file_dir = system.GetFilenameDirectory(current_file)
        file_basename = system.GetFilenameBasename(current_file)
        output_dir = os.path.join(file_dir, file_basename)
        if args.same_dir:
            output_dir = file_dir

        # Decompress file
        archive.ExtractArchive(
            archive_file = current_file,
            extract_dir = output_dir,
            delete_original = args.delete_originals,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Start
main()
