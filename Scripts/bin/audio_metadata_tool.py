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
parser = arguments.ArgumentParser(description = "Audio metadata management tool for scanning, clearing, and applying ID3 tags.")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.AudioMetadataAction,
    default = config.AudioMetadataAction.TAG,
    description = "Action to perform")
parser.add_enum_argument(
    args = ("-g", "--genre"),
    arg_type = config.AudioGenreType,
    default = config.AudioGenreType.REGULAR,
    description = "Music genre directory")
parser.add_string_argument(
    args = ("-b", "--album"),
    description = "Specific album name to process")
parser.add_string_argument(
    args = ("-r", "--artist"),
    description = "Specific artist name (for albums with artist structure)")
parser.add_boolean_argument(
    args = ("--preserve_artwork",),
    description = "Preserve artwork when clearing tags")
parser.add_boolean_argument(
    args = ("--clear_existing",),
    description = "Clear existing tags before applying new ones")
parser.add_boolean_argument(
    args = ("--exclude_comments",),
    description = "Exclude comments from tag extraction")
parser.add_boolean_argument(
    args = ("--use_index_for_track_number",),
    description = "Override track numbers with file index")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Execute action
    if args.action == config.AudioMetadataAction.TAG:
        return audio.BuildAudioMetadataFiles(
            genre_type = args.genre,
            album_name = args.album,
            artist_name = args.artist,
            exclude_comments = args.exclude_comments,
            use_index_for_track_number = args.use_index_for_track_number,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
    elif args.action == config.AudioMetadataAction.CLEAR:
        return audio.ClearAudioMetadataTags(
            genre_type = args.genre,
            album_name = args.album,
            artist_name = args.artist,
            preserve_artwork = args.preserve_artwork,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
    elif args.action == config.AudioMetadataAction.APPLY:
        return audio.ApplyAudioMetadataTags(
            genre_type = args.genre,
            album_name = args.album,
            artist_name = args.artist,
            clear_existing = args.clear_existing,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
    else:
        logger.log_error(f"Unknown action: {args.action}")
        return False

# Main
if __name__ == "__main__":
    system.run_main(main)
