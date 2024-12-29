#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Create folders from certain file types.")
parser.add_input_path_argument()
parser.add_string_argument("-f", "--file_types", default = ".iso,.chd,.rvz,.zip,.7z,.rar,.pkg", description = "List of file types (comma delimited)")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Make folders from file types
    for obj in system.GetDirectoryContents(input_path):
        obj_path = os.path.join(input_path, obj)
        if system.IsPathFile(obj_path):
            if obj.endswith(tuple(args.file_types.split(","))):
                selected_file = obj_path
                selected_file_basename = system.GetFilenameBasename(selected_file)
                new_folder = os.path.join(input_path, selected_file_basename)
                new_file = os.path.join(input_path, selected_file_basename, obj)
                system.MakeDirectory(
                    dir = new_folder,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                system.MoveFileOrDirectory(
                    src = selected_file,
                    dest = new_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
main()
