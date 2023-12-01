#!/usr/bin/env python3

# Imports
import os
import os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import setup
import iso
import archive

# Parse arguments
parser = argparse.ArgumentParser(description="Extract data from ISO files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-e", "--extract_method",
    choices=[
        "iso",
        "archive"
    ],
    default="iso", help="Extract method"
)
parser.add_argument("-s", "--skip_existing", action="store_true", help="Skip existing extracted files")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    print("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Convert disc image files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".iso"]):

        # Get file info
        current_file = file
        current_dir = system.GetFilenameDirectory(current_file)
        current_basename = system.GetFilenameBasename(current_file)

        # Check if output dir already exists
        output_dir = os.path.join(current_dir, current_basename)
        if os.path.isdir(output_dir):
            continue

        # Extract as iso
        if args.extract_method == "iso":
            iso.ExtractISO(
                iso_file = current_file,
                extract_dir = output_dir,
                delete_original = args.delete_originals,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

        # Extract as archive
        elif args.extract_method == "archive":
            archive.ExtractArchive(
                archive_file = current_file,
                extract_dir = output_dir,
                skip_existing = args.skip_existing,
                delete_original = args.delete_originals,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
