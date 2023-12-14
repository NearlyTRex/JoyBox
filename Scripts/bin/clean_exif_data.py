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
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Clean exif data.")
parser.add_argument("input_path", type=str, help="Input path")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Clean exif data
    command.RunCheckedCommand(
        cmd = [
            programs.GetToolProgram("ExifTool"),
            "-overwrite_original",
            "-All=",
            "-r",
            os.path.realpath(args.input_path)
        ],
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
