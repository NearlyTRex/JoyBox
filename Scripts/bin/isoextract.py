#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
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
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Check that path exists first
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.path)

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
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract as archive
        elif args.extract_method == "archive":
            archive.ExtractArchive(
                archive_file = current_file,
                extract_dir = output_dir,
                skip_existing = args.skip_existing,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
main()
