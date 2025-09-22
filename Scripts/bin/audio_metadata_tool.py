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
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Execute action
    if args.action == config.AudioMetadataAction.TAG:
        return audio.BuildAudioMetadataFiles(
            genre_type = args.genre,
            album_name = args.album,
            artist_name = args.artist,
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
        system.LogError(f"Unknown action: {args.action}")
        return False

# Main
if __name__ == "__main__":
    try:
        success = main()
        if success:
            system.LogInfo("Script completed successfully")
        else:
            system.LogError("Script completed with errors")
            sys.exit(1)
    except KeyboardInterrupt:
        system.LogInfo("Script interrupted")
        sys.exit(1)
    except Exception as e:
        system.LogError(f"Script failed with exception: {e}")
        sys.exit(1)
