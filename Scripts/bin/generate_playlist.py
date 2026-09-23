#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.playlist as playlist
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Write `.m3u` playlists for the media files in a directory tree.",
    details = (
        "Two playlist types:\n"
        "\n"
        "- `Tree` (default): one playlist at `-o` listing every matching file anywhere under\n"
        "  the input directory, by absolute path.\n"
        "- `Local`: for the input directory and each directory below it that directly holds\n"
        "  matching files, a playlist named `<directory name>.m3u` inside that directory,\n"
        "  listing those files by name only.\n"
        "\n"
        "Entries are ordered by length and then alphabetically. Playlists that would be empty\n"
        "or hold a single entry are not written unless `--allow_empty_lists` or\n"
        "`--allow_single_lists` is given."),
    examples = [
        ("Write one playlist for a whole music folder", "generate_playlist -t Tree -i \"/path/to/music\" -o \"/path/to/music/all.m3u\" -f \".mp3,.flac\""),
        ("Write a playlist inside each album folder", "generate_playlist -t Local -i \"/path/to/music\" -f \".mp3\""),
        ("Include several media types", "generate_playlist -t Tree -i \"/path/to/media\" -o \"/path/to/media/playlist.m3u\" -f \".mp3,.m4a,.flac,.ogg\""),
        ("Also write empty and single-entry playlists", "generate_playlist -t Local -i \"/path/to/music\" -f \".mp3\" --allow_empty_lists --allow_single_lists"),
        ("Show which playlists would be written without writing them", "generate_playlist -t Local -i \"/path/to/music\" -f \".mp3\" -p -v"),
    ],
    notes = [
        "An existing playlist at the same path is overwritten.",
    ],
    see_also = ["download_audio_files", "tag_audio_files", "audio_metadata_tool"],
    section = "Audio & Video")
parser.add_group("Input/Output")
parser.add_input_path_argument(description = "Directory to scan; must exist")
parser.add_output_path_argument(description = "Playlist file to write for `Tree`; not used by `Local`")
parser.add_group("Selection")
parser.add_string_argument(args = ("-f", "--file_types"), description = "Comma-separated file extensions to include, with the leading dot, e.g. `.mp3,.flac`")
parser.add_enum_argument(
    args = ("-t", "--playlist_type"),
    arg_type = config.PlaylistType,
    default = config.PlaylistType.TREE,
    description = "`Tree` writes one playlist for the whole tree; `Local` writes one inside each directory that holds matching files")
parser.add_group("Behavior")
parser.add_boolean_argument(args = ("--allow_empty_lists"), description = "Write playlists that have no entries instead of skipping them")
parser.add_boolean_argument(args = ("--allow_single_lists"), description = "Write playlists that have a single entry instead of skipping them")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Generate tree playlists
    if args.playlist_type == config.PlaylistType.TREE:
        playlist.generate_tree_playlist(
            source_dir = input_path,
            output_file = args.output_path,
            extensions = args.file_types.split(","),
            allow_empty_lists = args.allow_empty_lists,
            allow_single_lists = args.allow_single_lists,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Generate local playlists
    elif args.playlist_type == config.PlaylistType.LOCAL:
        playlist.generate_local_playlists(
            source_dir = input_path,
            extensions = args.file_types.split(","),
            allow_empty_lists = args.allow_empty_lists,
            allow_single_lists = args.allow_single_lists,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
