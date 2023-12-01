#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import command
import programs
import setup

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Start pegasus
    command.RunCheckedCommand(
        cmd = [programs.GetToolProgram("Pegasus")],
        options = command.CommandOptions(
            cwd = os.path.dirname(programs.GetToolProgram("Pegasus"))),
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
