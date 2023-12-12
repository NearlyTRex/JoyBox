#!/usr/bin/env python3

# Imports
import os, os.path
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
parser = argparse.ArgumentParser(description="Nintendo Wii U rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-r", "--decrypt_nus", action="store_true", help="Decrypt NUS packages")
parser.add_argument("-v", "--verify_nus", action="store_true", help="Verify NUS packages")
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
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

            # Verify NUS package
            elif args.verify_nus:
                nintendo.VerifyWiiUNUSPackage(
                    nus_package_dir = current_file_dir,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
