#!/usr/bin/env python3

# Imports
import os
import os.path
import sys
import argparse
from pathlib import Path

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Create folders from certain file types.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--file_types", type=str, default=".iso,.chd,.rvz,.zip,.7z,.rar,.pkg", help="List of file types (comma delimited)")
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

    # Make folders from file types
    for obj in system.GetDirectoryContents(input_path):
        obj_path = os.path.join(input_path, obj)
        if os.path.isfile(obj_path):
            if obj.endswith(tuple(args.file_types.split(","))):
                selected_file = obj_path
                selected_file_path = Path(selected_file)
                selected_file_basename = selected_file_path.stem
                new_folder = os.path.join(input_path, selected_file_basename)
                new_file = os.path.join(input_path, selected_file_basename, obj)
                system.MakeDirectory(new_folder, exit_on_failure = True)
                system.MoveFileOrDirectory(selected_file, new_file, exit_on_failure = True)

# Start
environment.RunAsRootIfNecessary(main)
