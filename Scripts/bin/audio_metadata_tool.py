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

# Parse forced tag overrides
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

# Run the selected action for a single genre
def run_for_genre(genre_type, force_tags):
    if args.action == config.AudioMetadataAction.TAG:
        return audio.build_audio_metadata_files(
            genre_type = genre_type,
            album_name = args.album,
            artist_name = args.artist,
            exclude_comments = args.exclude_comments,
            use_index_for_track_number = args.use_index_for_track_number,
            force_tags = force_tags,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
    elif args.action == config.AudioMetadataAction.CLEAR:
        return audio.clear_audio_metadata_tags(
            genre_type = genre_type,
            album_name = args.album,
            artist_name = args.artist,
            preserve_artwork = args.preserve_artwork,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
    elif args.action == config.AudioMetadataAction.APPLY:
        return audio.apply_audio_metadata_tags(
            genre_type = genre_type,
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
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Resolve forced tag overrides (TAG only)
    force_tags = None
    if args.action == config.AudioMetadataAction.TAG:
        force_tags = parse_force_tags(args.set)
        if force_tags is None:
            return False

    # Single genre
    if args.genre is not None:
        return run_for_genre(args.genre, force_tags)

    # All genres (genre omitted): process each genre that has albums
    overall = True
    processed = 0
    for genre_type in config.AudioGenreType.members():
        if not audio.get_album_directories(genre_type, args.album, args.artist):
            continue
        processed += 1
        logger.log_info(f"Processing genre: {genre_type.value}")
        if not run_for_genre(genre_type, force_tags):
            overall = False
    if processed == 0:
        logger.log_error("No albums found in any genre")
        return False
    return overall

# Main
if __name__ == "__main__":
    system.run_main(main)
