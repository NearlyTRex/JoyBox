#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import setup
import saves
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Save tool.")
parser.add_argument("-i", "--input_path", help="Input path")
parser.add_argument("-o", "--output_path", type=str, help="Output path")
parser.add_argument("-a", "--action",
    choices=[
        "backup",
        "restore",
        "pack",
        "unpack"
    ],
    default="backup", help="Save action"
)
args, unknown = parser.parse_known_args()

# Check input path
input_path = ""
if args.input_path:
    input_path = os.path.realpath(args.input_path)
if args.action == "restore":
    if len(input_path) == 0:
        print("Input path needs to be set for restoring saves")
        sys.exit(-1)
    if not os.path.exists(input_path):
        print("Path '%s' does not exist" % args.input_path)
        sys.exit(-1)

# Check output path
output_path = ""
if args.output_path:
    output_path = os.path.realpath(args.output_path)
if args.action == "backup":
    if len(output_path) == 0:
        print("Output path needs to be set for backing up saves")
        sys.exit(-1)
    if not os.path.exists(output_path):
        print("Output path '%s' does not exist" % args.output_path)
        sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Backup saves
    if args.action == "backup":
        saves.BackupSaves(
            output_path = output_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Restore saves
    elif args.action == "restore":
        saves.RestoreSaves(
            input_path = input_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Pack saves
    elif args.action == "pack":
        saves.PackSaves(
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Unpack saves
    elif args.action == "unpack":
        saves.UnpackSaves(
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Start
main()
