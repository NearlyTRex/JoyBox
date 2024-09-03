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
parser = argparse.ArgumentParser(description="Download missing assets.")
parser.add_argument("metadata_dir", help="Metadata dir")
parser.add_argument("-a", "--asset_type",
    choices=config.asset_types_all,
    default=config.asset_type_video,
    help="Asset type"
)
parser.add_argument("--video_search_terms", type=str, default="game trailer", help="Video search terms")
parser.add_argument("--video_search_num_results", type=int, default=20, help="Video search num results")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Check metadata dir
metadata_dir = os.path.realpath(args.metadata_dir)
if not os.path.exists(metadata_dir):
    system.LogErrorAndQuit("Could not find metadata path '%s'" % args.metadata_dir)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Examine metadata files
    for metadata_file in system.BuildFileListByExtensions(metadata_dir, extensions = [".txt"]):
        if metadata_file.endswith("metadata.pegasus.txt"):
            if os.path.isfile(metadata_file):
                metadata_obj = metadata.Metadata()
                metadata_obj.import_from_metadata_file(metadata_file)

                # Download missing videos
                if args.asset_type == config.asset_type_video:
                    metadata_obj.download_missing_videos(
                        search_terms = args.video_search_terms,
                        num_results = args.video_search_num_results,
                        verbose = args.verbose,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
