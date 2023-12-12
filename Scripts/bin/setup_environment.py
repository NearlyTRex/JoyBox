#!/usr/bin/env python3

# Imports
import os
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import setup
import ini

# Main
def main():

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Setup environment
    setup.SetupEnvironment(verbose = verbose, exit_on_failure = exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
