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
    description = "Extract, clear or apply the tags of albums in the local locker's music tree.",
    details = (
        "Works on albums: folders of audio files (MP3, M4A, M4B, MP4, AAC) under\n"
        "`Music/<genre>` in the local locker. A folder that holds sub-folders and no MP3 files\n"
        "is taken as an artist, and each sub-folder as one of its albums. Without `-g` the\n"
        "action runs for every genre that has albums.\n"
        "\n"
        "Actions:\n"
        "\n"
        "- `Tag` (default): read each album's tags into a JSON file,\n"
        "  `Audio/Tag/<genre>/[<artist>/]<album>.json` under the file metadata directory. The\n"
        "  audio files are not changed. Tracks are numbered by their sorted position when they\n"
        "  have no track number; a missing album is filled in from the folder name and a\n"
        "  missing album artist from the track artist. The first track's cover art is kept as\n"
        "  the album's.\n"
        "- `Apply`: write the tags and cover art from each album's JSON file back into its\n"
        "  audio files, matching tracks by file name.\n"
        "- `Clear`: remove the tags from every audio file in each album.\n"
        "\n"
        "The usual flow is `Tag`, edit the JSON if needed, then `Apply`. `tag_audio_files`\n"
        "runs both with the settings each genre needs."),
    examples = [
        ("Extract the tags of every Soundtrack album to JSON", "audio_metadata_tool -a Tag -g Soundtrack"),
        ("Extract one album's tags, leaving out comments", "audio_metadata_tool -a Tag -g Regular -b \"Some Album\" --exclude_comments"),
        ("Renumber tracks by file order while extracting", "audio_metadata_tool -a Tag -g Audiobook -b \"Some Book\" --use_index_for_track_number"),
        ("Force fields to fixed values while extracting", "audio_metadata_tool -a Tag -g Regular -b \"Some Album\" --set genre=Regular --set album_artist=\"Various Artists\""),
        ("Write an album's JSON tags back into its files", "audio_metadata_tool -a Apply -g Soundtrack -b \"Some Album\""),
        ("Preview applying tags without writing anything", "audio_metadata_tool -a Apply -g Soundtrack -b \"Some Album\" -p -v"),
        ("Rewrite the tags of the whole library from JSON, dropping any others", "audio_metadata_tool -a Apply --clear_existing"),
        ("Remove all tags from an album but keep the cover art", "audio_metadata_tool -a Clear -g Regular -b \"Some Album\" --preserve_artwork"),
        ("Extract the tags of an album stored under an artist folder", "audio_metadata_tool -a Tag -g Regular -r \"Some Artist\" -b \"Some Album\""),
    ],
    notes = [
        "`Apply` needs the album's JSON file; run `Tag` first. It stops at the first track in the JSON whose file no longer exists, so run `Tag` again after renaming files.",
        "`--set` is read by `Tag` only. It writes the value to every track and to the album information, overriding what was read from the files and `--use_index_for_track_number`. The field must be one of `title`, `artist`, `album`, `year`, `genre`, `album_artist`, `track_number`, `disc_number`, `bpm`, `key`, `conductor`; an unknown field or a value without `=` stops the tool before anything is read.",
        "A run over all genres fails if no genre has albums; a genre with no albums is otherwise skipped.",
    ],
    see_also = ["tag_audio_files", "download_audio_files", "audio_conversion_tool", "generate_playlist"],
    section = "Audio & Video")
parser.add_group("Selection")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.AudioMetadataAction,
    default = config.AudioMetadataAction.TAG,
    description = "What to do with each selected album; see the list above")
parser.add_enum_argument(
    args = ("-g", "--genre"),
    arg_type = config.AudioGenreType,
    default = None,
    description = "Genre folder under `Music` to work in; every genre with albums when omitted")
parser.add_string_argument(
    args = ("-b", "--album"),
    description = "Name of the one album folder to process; every album in the genre when omitted")
parser.add_string_argument(
    args = ("-r", "--artist"),
    description = "Artist folder that holds the `-b` album, for albums stored as `<artist>/<album>`")
parser.add_group("Behavior")
parser.add_boolean_argument(
    args = ("--preserve_artwork",),
    description = "For `Clear`: keep the embedded cover art")
parser.add_boolean_argument(
    args = ("--clear_existing",),
    description = "For `Apply`: remove each file's existing tags before writing the ones from the JSON")
parser.add_boolean_argument(
    args = ("--exclude_comments",),
    description = "For `Tag`: leave comment tags out of the JSON")
parser.add_boolean_argument(
    args = ("--use_index_for_track_number",),
    description = "For `Tag`: number tracks by their sorted position in the album instead of their existing track numbers")
parser.add_string_list_argument(
    args = ("--set",),
    description = "For `Tag`: force a tag to a value on every track, as `field=value`; repeat for more fields, e.g. `--set album_artist=\"Various Artists\"`")
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
