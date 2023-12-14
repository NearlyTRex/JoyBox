#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import command
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Restore save files.")
parser.add_argument("-i", "--input_path", type=str, required=True, help="Input path for saves")
args, unknown = parser.parse_known_args()

# Check input path
if not os.path.exists(args.input_path):
    print("Saves path '%s' does not exist" % args.input_path)
    sys.exit(1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Start ludusavi
    command.RunCheckedCommand(
        cmd = [
            programs.GetToolProgram("Ludusavi"),
            "restore",
            "--path", os.path.realpath(args.input_path)
        ],
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
