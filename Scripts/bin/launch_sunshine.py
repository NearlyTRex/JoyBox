#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import command
import programs
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Launch sunshine.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get tool
    sunshine_tool = None
    if programs.IsToolInstalled("Sunshine"):
        sunshine_tool = programs.GetToolProgram("Sunshine")
    if not sunshine_tool:
        system.LogError("Sunshine was not found")
        sys.exit(1)

    # Get launch command
    launch_cmd = [
        sunshine_tool
    ]

    # Run launch command
    command.RunCheckedCommand(
        cmd = launch_cmd,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
