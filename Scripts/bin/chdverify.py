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
import chd

# Parse arguments
parser = argparse.ArgumentParser(description="Verify disc images from CHD files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
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

    # Convert disc image files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".chd"]):

        # Verify disc chd
        system.Log("Verifying %s ..." % file)
        verification_success = chd.VerifyDiscCHD(file)
        if verification_success:
            system.LogSuccess("Verified!")
        else:
            system.LogErrorAndQuit("Verification failed!")

# Start
main()
