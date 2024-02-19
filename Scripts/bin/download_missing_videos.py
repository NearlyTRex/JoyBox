#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import metadata
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download missing videos.")
parser.add_argument("metadata_dir", help="Metadata dir")
args, unknown = parser.parse_known_args()

# Check metadata dir
if not os.path.exists(args.metadata_dir):
    system.LogError("Could not find metadata path '%s'" % args.metadata_dir)
    sys.exit(1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

# Start
main()
