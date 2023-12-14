#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import setup

# Main
def main():

    # Setup environment
    setup.SetupEnvironment(verbose = True, exit_on_failure = True)

# Start
main()
