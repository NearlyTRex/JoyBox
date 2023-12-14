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
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Extract disc images from CHD files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--toc_ext", type=str, default=".cue", help="Table of contents output extension")
parser.add_argument("-b", "--bin_ext", type=str, default=".bin", help="Binary output extension")
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

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

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
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Start
main()
