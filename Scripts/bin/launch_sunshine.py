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
import ini

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

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
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
