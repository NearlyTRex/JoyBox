#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import system
import archive
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Compress files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--file_types", type=str, default="", help="List of file types (comma delimited)")
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

    # Compress files
    for file in system.BuildFileListByExtensions(root_path, extensions = args.file_types.split(",")):

        # Get file info
        file_dir = system.GetFilenameDirectory(file)
        file_basename = system.GetFilenameBasename(file)

        # Check if zip already exists
        output_file = os.path.join(file_dir, file_basename + ".zip")
        if os.path.exists(output_file):
            continue

        # Compress file
        archive.CreateZipFromFile(
            zip_file = output_file,
            source_file = file,
            delete_original = args.delete_originals,
            verbose = True)

# Start
environment.RunAsRootIfNecessary(main)
