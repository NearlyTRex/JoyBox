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
parser = argparse.ArgumentParser(description="Convert disc images to CHD files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--disc_image_types", type=str, default=".iso,.cue,.gdi", help="List of disc image types (comma delimited)")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
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
    for file in system.BuildFileListByExtensions(input_path, extensions = args.disc_image_types.split(",")):

        # Get file info
        current_file = file
        current_dir = system.GetFilenameDirectory(current_file)
        current_basename = system.GetFilenameBasename(current_file)

        # Check if output already exists
        output_chd = os.path.join(current_dir, current_basename + ".chd")
        if os.path.exists(output_chd):
            continue

        # Create disc chd
        chd.CreateDiscCHD(
            chd_file = output_chd,
            source_iso = current_file,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
