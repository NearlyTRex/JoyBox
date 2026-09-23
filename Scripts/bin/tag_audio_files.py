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
parser = arguments.ArgumentParser(
    description = "Tag audio files with the right per-genre defaults, then apply them in one run.",
    details = (
        "Runs `audio_metadata_tool`'s `Tag` and `Apply` steps with the settings always used\n"
        "for the library, so they do not have to be remembered. For each genre it:\n"
        "\n"
        "1. Reads each album's tags into its JSON file, leaving out comments and forcing the\n"
        "   `genre` tag to the genre folder's name.\n"
        "2. Writes the JSON tags back into the audio files, unless `--no_apply` is given.\n"
        "\n"
        "The one per-genre difference is track numbering. Genres downloaded from YouTube by\n"
        "`download_audio_files` carry meaningless, identical track numbers, so their tracks are\n"
        "renumbered by file order. The genres treated this way are listed in\n"
        "`audio_track_index_genres` in `Shared/joybox/config/audio.py` (`ASMR` and `Story`);\n"
        "every other genre keeps its track numbers.\n"
        "\n"
        "Albums are found as in `audio_metadata_tool`, and without `-g` every genre with albums\n"
        "is processed. Use `audio_metadata_tool` directly for `Clear` or other settings."),
    examples = [
        ("Tag and apply the Story genre (renumbered by file order)", "tag_audio_files -g Story"),
        ("Tag and apply the whole library", "tag_audio_files"),
        ("Preview tagging a genre without writing anything", "tag_audio_files -g Story -p -v"),
        ("Tag and apply one album", "tag_audio_files -g Regular -b \"Some Album\""),
        ("Force an extra field on top of the defaults", "tag_audio_files -g Soundtrack --set album_artist=\"Various Artists\""),
        ("Write the JSON files only, leaving the audio files alone", "tag_audio_files -g ASMR --no_apply"),
    ],
    notes = [
        "`tag_audio_files -g Story` is the same as `audio_metadata_tool -a Tag -g Story --exclude_comments --set genre=Story --use_index_for_track_number` followed by `audio_metadata_tool -a Apply -g Story`.",
        "`--set genre=...` replaces the automatic genre. Use `--set` for other fields; it accepts the same fields as `audio_metadata_tool --set`.",
        "A genre with no albums is skipped with a warning.",
    ],
    see_also = ["audio_metadata_tool", "download_audio_files", "generate_playlist"],
    section = "Audio & Video")
parser.add_group("Selection")
parser.add_enum_argument(
    args = ("-g", "--genre"),
    arg_type = config.AudioGenreType,
    default = None,
    description = "Genre folder under `Music` to process; every genre with albums when omitted")
parser.add_string_argument(
    args = ("-b", "--album"),
    description = "Name of the one album folder to process; every album in the genre when omitted")
parser.add_string_argument(
    args = ("-r", "--artist"),
    description = "Artist folder that holds the `-b` album, for albums stored as `<artist>/<album>`")
parser.add_group("Behavior")
parser.add_string_list_argument(
    args = ("--set",),
    description = "Force an extra tag to a value on every track, as `field=value`; repeat for more fields, e.g. `--set album_artist=\"Various Artists\"`")
parser.add_boolean_argument(
    args = ("--clear_existing",),
    description = "Remove each file's existing tags before writing the ones from the JSON")
parser.add_boolean_argument(
    args = ("--no_apply",),
    description = "Write the JSON metadata files only; do not change the audio files")
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
