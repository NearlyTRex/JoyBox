#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import command
import programs
import asset
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Clean exif data.")
parser.add_argument("input_path", type=str, help="Input path")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Get input path
input_path = os.path.realpath(args.input_path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.input_path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Clean exif data
    asset.CleanExifData(
        asset_file = input_path,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
