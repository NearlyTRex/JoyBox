#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import playlist
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Generate playlists.")
parser.add_argument("input_path", help="Input path")
parser.add_argument("-o", "--output_file", default="playlist.m3u", type=str, help="Output file")
parser.add_argument("-f", "--file_types", type=str, help="List of file types (comma delimited)")
parser.add_argument("-t", "--playlist_type",
    choices=config.PlaylistType.members(),
    default=config.PlaylistType.TREE,
    help="Playlist type"
)
parser.add_argument("--allow_empty_lists", action="store_true", help="Allow empty lists")
parser.add_argument("--allow_single_lists", action="store_true", help="Allow single entry lists")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.input_path:
    parser.print_help()
    system.QuitProgram()

# Check input path
input_path = os.path.realpath(args.input_path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.input_path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Generate tree playlists
    if args.playlist_type == config.PlaylistType.TREE:
        playlist.GenerateTreePlaylist(
            source_dir = input_path,
            output_file = args.output_file,
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
main()
