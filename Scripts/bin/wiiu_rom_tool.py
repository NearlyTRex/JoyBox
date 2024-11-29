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
parser = argparse.ArgumentParser(description="Nintendo Wii U rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-r", "--decrypt_nus", action="store_true", help="Decrypt NUS packages")
parser.add_argument("-e", "--verify_nus", action="store_true", help="Verify NUS packages")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Check input path
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

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
main()
