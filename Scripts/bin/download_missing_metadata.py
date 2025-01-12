#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import metadata
import metadatacollector
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Download missing metadata.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-s", "--metadata_source"),
    arg_type = config.MetadataSourceType,
    default = config.MetadataSourceType.GAMEFAQS,
    description = "Metadata source type"
)
parser.add_string_argument(args = ("--keys_to_check"), description = "Check against specific keys (comma delimited)")
parser.add_boolean_argument(args = ("--force_download"), description = "Force download")
parser.add_boolean_argument(args = ("--allow_replacing"), description = "Allow replacing")
parser.add_boolean_argument(args = ("-a", "--select_automatically"), description = "Select game automatically")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Check metadata dir
if not os.path.exists(args.input_path):
    system.LogError("Could not find metadata path '%s'" % args.input_path, quit_program = True)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get keys
    keys_to_check = []
    if args.keys_to_check:
        keys_to_check = args.keys_to_check.split(",")

    # Collect metadata
    metadatacollector.CollectMetadataFromDirectory(
        metadata_dir = args.input_path,
        metadata_source = args.metadata_source,
        keys_to_check = keys_to_check,
        force_download = args.force_download,
        allow_replacing = args.allow_replacing,
        select_automatically = args.select_automatically,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
main()
