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

# Parse arguments
parser = argparse.ArgumentParser(description="Verify archive files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-t", "--archive_types", type=str, default=".zip,.7z,.rar", help="List of archive types (comma delimited)")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Check that path exists first
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Verify archives
    for file in system.BuildFileListByExtensions(input_path, extensions = args.archive_types.split(",")):
        system.Log("Verifying %s ..." % file)
        verification_success = archive.TestArchive(
            archive_file = file,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if verification_success:
            system.LogSuccess("Verified!")
        else:
            system.LogErrorAndQuit("Verification failed!")

# Start
main()
