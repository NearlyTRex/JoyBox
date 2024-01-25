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
import iso
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Make ISO images out of all folders or zips in a path.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--input_type",
    choices=[
        "folder",
        "zip"
    ],
    default="folder", help="Input type"
)
parser.add_argument("-n", "--volume_name", type=str, default="", help="Volume name to use")
parser.add_argument("-a", "--auto_volume_name", action="store_true", help="Choose volume name based automatically")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check input path
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Create iso images from folders
    if args.input_type == "folder":
        for obj in system.GetDirectoryContents(input_path):
            obj_path = os.path.join(input_path, obj)
            if not os.path.isdir(obj_path):
                continue

            # Check if iso already exists
            output_file = os.path.join(input_path, obj + ".iso")
            if os.path.exists(output_file):
                continue

            # Get volume name
            volume_name = args.volume_name
            if args.auto_volume_name:
                volume_name = obj

            # Create iso
            iso.CreateISO(
                iso_file = output_file,
                source_dir = obj_path,
                volume_name = volume_name,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

    # Create iso images from zips
    elif args.input_type == "zip":
        for file in system.BuildFileListByExtensions(input_path, extensions = [".zip"]):

            # Get file info
            current_file = file
            current_dir = system.GetFilenameDirectory(current_file)
            current_basename = system.GetFilenameBasename(current_file)

            # Check if iso already exists
            output_file = os.path.join(current_dir, current_basename + ".iso")
            if os.path.exists(output_file):
                continue

            # Decompress zip
            extracted_dir = os.path.join(current_dir, current_basename + "_extracted")
            archive.ExtractArchive(
                archive_file = current_file,
                extract_dir = extracted_dir,
                work_dir = current_dir,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

            # Get volume name
            volume_name = args.volume_name
            if args.auto_volume_name:
                volume_name = current_basename

            # Create iso
            iso.CreateISO(
                iso_file = output_file,
                source_dir = extracted_dir,
                work_dir = extracted_dir,
                volume_name = volume_name,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

# Start
main()
