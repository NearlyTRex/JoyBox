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
parser = argparse.ArgumentParser(description="Extract disc images from CHD files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--toc_ext", type=str, default=".cue", help="Table of contents output extension")
parser.add_argument("-b", "--bin_ext", type=str, default=".bin", help="Binary output extension")
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
    for file in system.BuildFileListByExtensions(input_path, extensions = [".chd"]):

        # Get file info
        current_file = file
        current_dir = system.GetFilenameDirectory(current_file)
        current_basename = system.GetFilenameBasename(current_file)

        # Check if output already exists
        output_bin = os.path.join(current_dir, current_basename + args.bin_ext)
        output_toc = os.path.join(current_dir, current_basename + args.toc_ext)
        if os.path.exists(output_bin) or os.path.exists(output_toc):
            continue

        # Extract disc chd
        chd.ExtractDiscCHD(
            chd_file = current_file,
            binary_file = output_bin,
            toc_file = output_toc,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
