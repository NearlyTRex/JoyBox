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
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Download audio files.")
parser.add_enum_argument(
    args = ("-g", "--genre_type"),
    arg_type = config.AudioGenreType,
    description = "Genre type")
parser.add_string_argument(args = ("-c", "--cookie_source"), default = "firefox", description = "Cookie source")
parser.add_enum_argument(
    args = ("-k", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.ALL,
    description = "Locker type for backup upload")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Story
    if args.genre_type == config.AudioGenreType.STORY:
        success = audio.DownloadStoryAudioFiles(
            cookie_source = args.cookie_source,
            locker_type = args.locker_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Story audio download failed")
            sys.exit(1)

    # ASMR
    elif args.genre_type == config.AudioGenreType.ASMR:
        success = audio.DownloadASMRAudioFiles(
            cookie_source = args.cookie_source,
            locker_type = args.locker_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("ASMR audio download failed")
            sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
