# Imports
from joybox import config
from joybox import system
from joybox import audio
from joybox import arguments
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "audio_metadata_tool")
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
    return parser

# Run the chosen tag action (extract to JSON, clear or apply) on the albums of one genre in the local locker's music tree, or of every genre
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Run the action on one genre, or on every genre when it is omitted
    return audio.run_metadata_action_for_genres(
        action = args.action,
        genre_type = args.genre,
        album_name = args.album,
        artist_name = args.artist,
        set_values = args.set,
        exclude_comments = args.exclude_comments,
        use_index_for_track_number = args.use_index_for_track_number,
        preserve_artwork = args.preserve_artwork,
        clear_existing = args.clear_existing,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
