#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import setup
import system
import saves

# Parse arguments
parser = argparse.ArgumentParser(description="Save tool.")
parser.add_argument("-i", "--input_path", type=str, help="Input path")
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
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Check input path
input_path = ""
if args.input_path:
    input_path = os.path.realpath(args.input_path)
if args.action == "restore":
    if len(input_path) == 0:
        system.LogErrorAndQuit("Input path needs to be set for restoring saves")
    if not os.path.exists(input_path):
        system.LogErrorAndQuit("Path '%s' does not exist" % args.input_path)

# Check output path
output_path = ""
if args.output_path:
    output_path = os.path.realpath(args.output_path)
if args.action == "backup":
    if len(output_path) == 0:
        system.LogErrorAndQuit("Output path needs to be set for backing up saves")
    if not os.path.exists(output_path):
        system.LogErrorAndQuit("Output path '%s' does not exist" % args.output_path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Backup saves
    if args.action == "backup":
        saves.BackupSaves(
            output_path = output_path,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Restore saves
    elif args.action == "restore":
        saves.RestoreSaves(
            input_path = input_path,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Pack saves
    elif args.action == "pack":
        saves.PackSaves(
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Unpack saves
    elif args.action == "unpack":
        saves.UnpackSaves(
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
