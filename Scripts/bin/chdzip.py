#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import chd
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Convert CHD files into zip files.")
parser.add_argument("path", help="Input path")
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
    for file in system.BuildFileListByExtensions(input_path, extensions = [".chd"]):

        # Get file info
        current_file = file
        current_dir = system.GetFilenameDirectory(current_file)
        current_basename = system.GetFilenameBasename(current_file)

        # Check if output already exists
        output_zip = os.path.join(current_dir, current_basename + ".zip")
        if os.path.exists(output_zip):
            continue

        # Extract disc chd
        chd.ArchiveDiscCHD(
            chd_file = current_file,
            zip_file = output_zip,
            disc_type = None,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
main()
