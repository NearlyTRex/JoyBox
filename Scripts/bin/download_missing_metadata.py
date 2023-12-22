#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import metadata
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download missing metadata.")
parser.add_argument("metadata_dir", help="Metadata dir")
parser.add_argument("-s", "--metadata_source",
    choices=[
        config.metadata_source_thegamesdb,
        config.metadata_source_gamefaqs,
        config.metadata_source_itchio
    ],
    default=config.metadata_source_gamefaqs
)
parser.add_argument("--only_check_description", action="store_true", help="Only check descriptions")
parser.add_argument("--only_check_genre", action="store_true", help="Only check genres")
parser.add_argument("--only_check_developer", action="store_true", help="Only check developers")
parser.add_argument("--only_check_publisher", action="store_true", help="Only check publishers")
parser.add_argument("--only_check_release", action="store_true", help="Only check releases")
parser.add_argument("--force_download", action="store_true", help="Force download")
parser.add_argument("-a", "--select_automatically", action="store_true", help="Select game automatically")
parser.add_argument("-i", "--ignore_unowned", action="store_true", help="Ignore unowned games")
args, unknown = parser.parse_known_args()

# Check metadata dir
if not os.path.exists(args.metadata_dir):
    print("Could not find metadata path '%s'" % args.metadata_dir)
    sys.exit(1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Collect metadata
    metadata.CollectMetadata(
        metadata_dir = args.metadata_dir,
        metadata_source = args.metadata_source,
        only_check_description = args.only_check_description,
        only_check_genre = args.only_check_genre,
        only_check_developer = args.only_check_developer,
        only_check_publisher = args.only_check_publisher,
        only_check_release = args.only_check_release,
        force_download = args.force_download,
        select_automatically = args.select_automatically,
        ignore_unowned = args.ignore_unowned)

# Start
main()
