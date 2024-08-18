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

# Parse arguments
parser = argparse.ArgumentParser(description="Create folders from certain file types.")
parser.add_argument("path", help="Input path")
parser.add_argument("-f", "--file_types", type=str, default=".iso,.chd,.rvz,.zip,.7z,.rar,.pkg", help="List of file types (comma delimited)")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Make folders from file types
    for obj in system.GetDirectoryContents(input_path):
        obj_path = os.path.join(input_path, obj)
        if os.path.isfile(obj_path):
            if obj.endswith(tuple(args.file_types.split(","))):
                selected_file = obj_path
                selected_file_basename = system.GetFilenameBasename(selected_file)
                new_folder = os.path.join(input_path, selected_file_basename)
                new_file = os.path.join(input_path, selected_file_basename, obj)
                system.MakeDirectory(
                    new_folder,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)
                system.MoveFileOrDirectory(
                    selected_file,
                    new_file,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)

# Start
main()
