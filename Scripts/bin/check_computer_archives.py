#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import json
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Check computer archives.")
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

    # Check computer archives
    for file in system.BuildFileListByExtensions(input_path, extensions = [".exe"]):

        # Check exe size
        print("Checking exe file %s ..." % file)
        exe_filesize = os.path.getsize(file)
        if exe_filesize > 4290772992:
            print("Executable '%s' is larger than 4092 MB" % file)
            sys.exit(1)

# Start
environment.RunAsRootIfNecessary(main)
