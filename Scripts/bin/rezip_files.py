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
parser = argparse.ArgumentParser(description="Rezip files deterministically.")
parser.add_argument("input_path", help="Input path")
args, unknown = parser.parse_known_args()
if not args.input_path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
input_path = os.path.realpath(args.input_path)
if not os.path.exists(input_path):
    print("Path '%s' does not exist" % args.input_path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Rezip zip files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".zip"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)
        current_file_extract_dir = os.path.join(current_file_dir, current_file_basename + "_extracted")

        # Unzip file
        print("Unzipping file %s ..." % current_file)
        archive.ExtractArchive(
            archive_file = current_file,
            extract_dir = current_file_extract_dir,
            delete_original = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Deterministically zip file
        print("Deterministically rezipping ...")
        archive.CreateZipFromFolder(
            zip_file = current_file,
            source_dir = current_file_extract_dir,
            delete_original = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Start
main()
