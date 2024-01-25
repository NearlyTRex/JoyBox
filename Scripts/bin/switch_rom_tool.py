#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import nintendo
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Nintendo Switch rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--trim", action="store_true", help="Trim XCI files")
parser.add_argument("-u", "--untrim", action="store_true", help="Untrim XCI files")
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

    # Find xci files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".xci"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)

        # Trim xci
        if args.trim:
            nintendo.TrimSwitchXCI(
                src_xci_file = current_file,
                dest_xci_file = os.path.join(current_file_dir, current_file_basename + "_trimmed.xci"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

        # Untrim xci
        elif args.untrim:
            nintendo.UntrimSwitchXCI(
                src_xci_file = current_file,
                dest_xci_file = os.path.join(current_file_dir, current_file_basename + "_untrimmed.xci"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

# Start
main()
