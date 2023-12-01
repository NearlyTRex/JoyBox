#!/usr/bin/env python3

# Imports
import os
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import command
import environment
import programs
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Clean exif data.")
parser.add_argument("input_path", type=str, help="Input path")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Clean exif data
    command.RunCheckedCommand(
        cmd = [
            programs.GetToolProgram("ExifTool"),
            "-overwrite_original",
            "-All=",
            "-r",
            os.path.realpath(args.input_path)
        ],
        verbose = True)

# Start
environment.RunAsRootIfNecessary(main)
