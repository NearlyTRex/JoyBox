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
import joybox.audiometadata as audiometadata
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

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
    default = None,
    description = "Music genre directory (if omitted, all genres are processed)")
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
parser.add_string_list_argument(
    args = ("--set",),
    description = "Force a curated tag on every track, as field=value (repeatable), e.g. --set genre=Regular --set album_artist=\"Various Artists\"")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Resolve forced tag overrides (TAG only)
    force_tags = None
    if args.action == config.AudioMetadataAction.TAG:
        force_tags = audiometadata.parse_force_tags(args.set)
        if force_tags is None:
            return False

    # Run the selected action for one genre
    def run_for_genre(genre_type):
        return audio.run_metadata_action(
            action = args.action,
            genre_type = genre_type,
            album_name = args.album,
            artist_name = args.artist,
            exclude_comments = args.exclude_comments,
            use_index_for_track_number = args.use_index_for_track_number,
            preserve_artwork = args.preserve_artwork,
            clear_existing = args.clear_existing,
            force_tags = force_tags,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Single genre
    if args.genre is not None:
        return run_for_genre(args.genre)

    # All genres (genre omitted)
    return audio.process_all_genres(run_for_genre, args.album, args.artist)

# Main
if __name__ == "__main__":
    system.run_main(main)
