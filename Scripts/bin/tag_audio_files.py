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
parser = arguments.ArgumentParser(description = "Tag audio files with the right per-genre defaults, then apply them in one run.")
parser.add_enum_argument(
    args = ("-g", "--genre"),
    arg_type = config.AudioGenreType,
    default = None,
    description = "Music genre directory (if omitted, all genres with albums are processed)")
parser.add_string_argument(
    args = ("-b", "--album"),
    description = "Specific album name to process")
parser.add_string_argument(
    args = ("-r", "--artist"),
    description = "Specific artist name (for albums with artist structure)")
parser.add_string_list_argument(
    args = ("--set",),
    description = "Force an extra curated tag on every track, as field=value (repeatable), e.g. --set album_artist=\"Various Artists\"")
parser.add_boolean_argument(
    args = ("--clear_existing",),
    description = "Clear existing tags before applying new ones")
parser.add_boolean_argument(
    args = ("--no_apply",),
    description = "Build the metadata files only; do not write tags back to the audio files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Resolve extra forced tag overrides
    extra_force_tags = audiometadata.parse_force_tags(args.set)
    if extra_force_tags is None:
        return False

    # Tag one genre using its policy
    def run_for_genre(genre_type):
        return audio.tag_genre_with_policy(
            genre_type = genre_type,
            album_name = args.album,
            artist_name = args.artist,
            extra_force_tags = extra_force_tags,
            apply_tags = not args.no_apply,
            clear_existing = args.clear_existing,
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
