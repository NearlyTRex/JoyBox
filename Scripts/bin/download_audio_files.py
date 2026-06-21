#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.audio as audio
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Download audio files.")
parser.add_enum_argument(
    args = ("-g", "--genre_type"),
    arg_type = config.AudioGenreType,
    description = "Genre type")
parser.add_string_argument(args = ("-c", "--cookie_source"), default = "firefox", description = "Cookie source")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.ALL,
    description = "Locker type for backup upload")
parser.add_output_path_argument(description = "Persistent output folder (resumable; downloads are kept here per channel instead of a temp dir)")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Story
    if args.genre_type == config.AudioGenreType.STORY:
        success = audio.download_story_audio_files(
            cookie_source = args.cookie_source,
            locker_type = args.locker_type,
            output_path = args.output_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Story audio download failed")
            sys.exit(1)

    # ASMR
    elif args.genre_type == config.AudioGenreType.ASMR:
        success = audio.download_asmr_audio_files(
            cookie_source = args.cookie_source,
            locker_type = args.locker_type,
            output_path = args.output_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("ASMR audio download failed")
            sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
