# Imports
from joybox import config
from joybox import system
from joybox import audio
from joybox import audiometadata
from joybox import arguments
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "tag_audio_files")
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
    return parser

# Tag each genre's albums to JSON with its fixed defaults, then write the tags back into the audio files unless told not to
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

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

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
