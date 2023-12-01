#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import archive
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Compress folders.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--output_type",
    choices=[
        "zip",
        "exe"
    ],
    default="zip", help="Output type"
)
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
    for obj in system.GetDirectoryContents(root_path):
        obj_path = os.path.join(root_path, obj)
        if not os.path.isdir(obj_path):
            continue

        # Get output file
        output_file = output_file = os.path.join(root_path, obj + "." + args.output_type)
        if os.path.exists(output_file):
            continue

        # Compress folder
        if args.output_type == "zip":
            archive.CreateZipFromFolder(
                zip_file = output_file,
                source_dir = obj_path,
                delete_original = args.delete_originals,
                verbose = True)
        elif args.output_type == "exe":
            archive.CreateExeFromFolder(
                exe_file = output_file,
                source_dir = obj_path,
                delete_original = args.delete_originals,
                verbose = True)

# Start
environment.RunAsRootIfNecessary(main)
