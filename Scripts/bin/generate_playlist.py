#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import playlist
import arguments
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Generate playlists.")
parser.add_input_path_argument()
parser.add_output_path_argument()
parser.add_string_argument(args = ("-f", "--file_types"), description = "List of file types (comma delimited)")
parser.add_enum_argument(
    args = ("-t", "--playlist_type"),
    arg_type = config.PlaylistType,
    default = config.PlaylistType.TREE,
    description = "Playlist type")
parser.add_boolean_argument(args = ("--allow_empty_lists"), description = "Allow empty lists")
parser.add_boolean_argument(args = ("--allow_single_lists"), description = "Allow single entry lists")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Generate tree playlists
    if args.playlist_type == config.PlaylistType.TREE:
        playlist.GenerateTreePlaylist(
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
        playlist.GenerateLocalPlaylists(
            source_dir = input_path,
            extensions = args.file_types.split(","),
            allow_empty_lists = args.allow_empty_lists,
            allow_single_lists = args.allow_single_lists,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
