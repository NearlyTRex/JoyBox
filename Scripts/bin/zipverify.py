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
import archive
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Verify zip files.")
parser.add_argument("path", help="Input path")
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
    for file in system.BuildFileListByExtensions(input_path, extensions = [".zip"]):

        # Verify zip file
        system.Log("Verifying %s ..." % file)
        verification_success = archive.TestArchive(
            archive_file = file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if verification_success:
            system.LogSuccess("Verified!")
        else:
            system.LogError("Verification failed!")
            sys.exit(1)

# Start
main()
