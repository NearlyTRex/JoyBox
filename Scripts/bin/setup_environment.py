#!/usr/bin/env python3

# Imports
import os
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import setup

# Main
def main():

    # Setup environment
    setup.SetupEnvironment()

# Start
environment.RunAsRootIfNecessary(main)
