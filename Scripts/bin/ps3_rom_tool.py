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
import setup
import playstation

# Parse arguments
parser = argparse.ArgumentParser(description="Sony PlayStation 3 rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-v", "--verify_chd", action="store_true", help="Verify PS3 chd files")
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

    # Find rom files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".chd"]):

        # Verify chd
        if args.verify_chd:
            playstation.VerifyPS3CHD(
                chd_file = file,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
