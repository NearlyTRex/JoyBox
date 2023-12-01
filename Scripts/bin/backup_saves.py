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
parser = argparse.ArgumentParser(description="Backup save files.")
parser.add_argument("-o", "--output_path", type=str, required=True, help="Output path for saves")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Start ludusavi
    command.RunCheckedCommand(
        cmd = [
            programs.GetToolProgram("Ludusavi"),
            "backup",
            "--try-update",
            "--merge",
            "--path", os.path.realpath(args.output_path)
        ],
        verbose = True)

# Start
environment.RunAsRootIfNecessary(main)
