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

# Parse extra forced tag overrides
def parse_force_tags(set_values):
    force_tags = {}
    for entry in set_values or []:
        if "=" not in entry:
            logger.log_error(f"Invalid --set value (expected field=value): {entry}")
            return None
        field, value = entry.split("=", 1)
        field = field.strip()
        if field not in audiometadata.curated_tag_fields:
            logger.log_error(f"Unknown tag field '{field}'. Allowed fields: {', '.join(audiometadata.curated_tag_fields)}")
            return None
        force_tags[field] = value
    return force_tags

# Tag (and optionally apply) a single genre using its policy
def run_for_genre(genre_type, extra_force_tags):

    # Nothing to do for a genre with no albums (not a failure)
    if not audio.get_album_directories(genre_type, args.album, args.artist):
        logger.log_warning(f"No albums found for genre: {genre_type.value}")
        return True

    # Universal policy: comments excluded, genre forced to the genre folder
    force_tags = { "genre": genre_type.value }
    force_tags.update(extra_force_tags)

    # Per-genre policy: renumber tracks by index for YouTube-sourced genres
    use_index_for_track_number = genre_type.value in config.audio_track_index_genres

    logger.log_info(
        f"Tagging genre: {genre_type.value}"
        + (" (renumbering tracks by index)" if use_index_for_track_number else ""))

    # Build the metadata files (reads existing tags, writes JSON sidecars)
    if not audio.build_audio_metadata_files(
        genre_type = genre_type,
        album_name = args.album,
        artist_name = args.artist,
        exclude_comments = True,
        use_index_for_track_number = use_index_for_track_number,
        force_tags = force_tags,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        return False

    # Apply the metadata files back to the audio files
    if args.no_apply:
        return True
    return audio.apply_audio_metadata_tags(
        genre_type = genre_type,
        album_name = args.album,
        artist_name = args.artist,
        clear_existing = args.clear_existing,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Resolve extra forced tag overrides
    extra_force_tags = parse_force_tags(args.set)
    if extra_force_tags is None:
        return False

    # Single genre
    if args.genre is not None:
        return run_for_genre(args.genre, extra_force_tags)

    # All genres (genre omitted): process each genre that has albums
    overall = True
    processed = 0
    for genre_type in config.AudioGenreType.members():
        if not audio.get_album_directories(genre_type, args.album, args.artist):
            continue
        processed += 1
        logger.log_info(f"Processing genre: {genre_type.value}")
        if not run_for_genre(genre_type, extra_force_tags):
            overall = False
    if processed == 0:
        logger.log_error("No albums found in any genre")
        return False
    return overall

# Main
if __name__ == "__main__":
    system.run_main(main)
