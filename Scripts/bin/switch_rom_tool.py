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
import nintendo
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Nintendo Switch rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--trim", action="store_true", help="Trim XCI files")
parser.add_argument("-u", "--untrim", action="store_true", help="Untrim XCI files")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check input path
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
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Untrim xci
        elif args.untrim:
            nintendo.UntrimSwitchXCI(
                src_xci_file = current_file,
                dest_xci_file = os.path.join(current_file_dir, current_file_basename + "_untrimmed.xci"),
                delete_original = args.delete_originals,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
