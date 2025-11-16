#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import nintendo
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Nintendo Wii U rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-r", "--decrypt_nus"), description = "Decrypt NUS packages")
parser.add_boolean_argument(args = ("-e", "--verify_nus"), description = "Verify NUS packages")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete original files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Find rom files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".tik"]):
        if file.endswith("title.tik"):
            current_file = file
            current_file_dir = system.GetFilenameDirectory(current_file)
            current_file_basename = system.GetFilenameBasename(current_file)

            # Decrypt NUS package
            if args.decrypt_nus:
                nintendo.DecryptWiiUNUSPackage(
                    nus_package_dir = current_file_dir,
                    delete_original = args.delete_originals,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

            # Verify NUS package
            elif args.verify_nus:
                nintendo.VerifyWiiUNUSPackage(
                    nus_package_dir = current_file_dir,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
