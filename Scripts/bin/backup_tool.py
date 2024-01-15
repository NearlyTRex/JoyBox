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
import environment
import setup
import ini

# Setup argument parser
parser = argparse.ArgumentParser(description="Backup tool.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-t", "--type",
    choices=[
        "storage",
        "sync"
    ],
    default="storage", help="Backup type"
)
parser.add_argument("-c", "--category", type=str, help="Storage category")
parser.add_argument("-s", "--subcategory", type=str, help="Storage subcategory")
parser.add_argument("-n", "--name", type=str, help="Storage name")
parser.add_argument("-o", "--output_path", type=str, default=".", help="Output path")

# Parse arguments
args, unknownargs = parser.parse_known_args()

# Get output path
output_path = os.path.realpath(args.output_path)
if not os.path.exists(output_path):
    system.LogError("Output path '%s' does not exist" % args.output_path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

# Start
main()
