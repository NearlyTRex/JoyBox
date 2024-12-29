#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import command
import programs
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Launch sunshine.")
parser.add_common_arguments()
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
        system.LogErrorAndQuit("Sunshine was not found")

    # Get launch command
    launch_cmd = [
        sunshine_tool
    ]

    # Run launch command
    command.RunCheckedCommand(
        cmd = launch_cmd,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
main()
