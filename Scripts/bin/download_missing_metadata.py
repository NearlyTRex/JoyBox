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
parser = argparse.ArgumentParser(description="Download missing metadata.")
parser.add_argument("metadata_dir", help="Metadata dir")
parser.add_argument("-s", "--metadata_source",
    choices=config.metadata_source_types,
    default=config.metadata_source_type_gamefaqs
)
parser.add_argument("--keys_to_check", type=str, help="Check against specific keys (comma delimited)")
parser.add_argument("--force_download", action="store_true", help="Force download")
parser.add_argument("--allow_replacing", action="store_true", help="Allow replacing")
parser.add_argument("-a", "--select_automatically", action="store_true", help="Select game automatically")
parser.add_argument("-i", "--ignore_unowned", action="store_true", help="Ignore unowned games")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Check metadata dir
if not os.path.exists(args.metadata_dir):
    system.LogErrorAndQuit("Could not find metadata path '%s'" % args.metadata_dir)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get keys
    keys_to_check = []
    if args.keys_to_check:
        keys_to_check = args.keys_to_check.split(",")

    # Collect metadata
    metadata.CollectMetadata(
        metadata_dir = args.metadata_dir,
        metadata_source = args.metadata_source,
        keys_to_check = keys_to_check,
        force_download = args.force_download,
        allow_replacing = args.allow_replacing,
        select_automatically = args.select_automatically,
        ignore_unowned = args.ignore_unowned,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
