#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import programs
import command
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="List duplicate files.")
parser.add_argument("path", help="Input path")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
root_path = os.path.realpath(args.path)
if not os.path.exists(root_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Get tool
    dupes_tool = None
    if programs.IsToolInstalled("Jdupes"):
        dupes_tool = programs.GetToolProgram("Jdupes")
    if not dupes_tool:
        system.LogError("Jdupes was not found")
        sys.exit(1)

    # Get list command
    list_cmd = [
        dupes_tool,
        "--recurse",
        "--print-summarize",
        "--size",
        root_path
    ]

    # Run list command
    command.RunCheckedCommand(
        cmd = list_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
