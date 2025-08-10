#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import audio
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Download audio files.")
parser.add_enum_argument(
    args = ("-g", "--genre_type"),
    arg_type = config.AudioGenreType,
    description = "Genre type")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Story
    if args.genre_type == config.AudioGenreType.STORY:
        audio.DownloadStoryAudioFiles(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # ASMR
    elif args.genre_type == config.AudioGenreType.ASMR:
        audio.DownloadASMRAudioFiles(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
main()
