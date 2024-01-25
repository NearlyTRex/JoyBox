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

# Parse arguments
parser = argparse.ArgumentParser(description="Check computer archives.")
parser.add_argument("path", help="Input path")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Check computer archives
    for file in system.BuildFileListByExtensions(input_path, extensions = [".exe"]):

        # Check exe size
        system.Log("Checking exe file %s ..." % file)
        exe_filesize = os.path.getsize(file)
        if exe_filesize > 4290772992:
            system.LogError("Executable '%s' is larger than 4092 MB" % file)
            sys.exit(1)

# Start
main()
