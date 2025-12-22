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
import logger
import fileops
import paths

# Parse arguments
parser = arguments.ArgumentParser(description = "Create folders from certain file types.")
parser.add_input_path_argument()
parser.add_string_argument(args = ("-f", "--file_types"), default = ".iso,.chd,.rvz,.zip,.7z,.rar,.pkg", description = "List of file types (comma delimited)")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Make folders from file types
    for obj in paths.get_directory_contents(input_path):
        obj_path = paths.join_paths(input_path, obj)
        if paths.is_path_file(obj_path):
            if obj.endswith(tuple(args.file_types.split(","))):
                selected_file = obj_path
                selected_file_basename = paths.get_filename_basename(selected_file)
                new_folder = paths.join_paths(input_path, selected_file_basename)
                new_file = paths.join_paths(input_path, selected_file_basename, obj)
                fileops.make_directory(
                    src = new_folder,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                fileops.move_file_or_directory(
                    src = selected_file,
                    dest = new_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
