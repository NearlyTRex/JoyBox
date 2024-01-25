#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import playlist
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Generate playlist.")
parser.add_argument("path", help="Input path")
parser.add_argument("-f", "--format", type=str, help="File format (e.g. mp3, iso, etc)")
parser.add_argument("-o", "--output_file", type=str, default="playlist.m3u", help="Output file")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
root_path = os.path.realpath(args.path)
if not os.path.exists(root_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Make playlist
    playlist.GeneratePlaylist(
        source_dir = root_path,
        source_format = args.format,
        output_file = args.output_file,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
