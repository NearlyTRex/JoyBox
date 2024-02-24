#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import gog
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download GOG game.")
parser.add_argument("game", help="Game to download (regex pattern)")
parser.add_argument("-i", "--include",
    choices=[
        "installers",
        "extras"
    ],
    default="installers",
    help="Files to include"
)
parser.add_argument("-p", "--platform",
    choices=[
        "windows",
        "linux"
    ],
    default="windows",
    help="Download platform"
)
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory for downloads")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Check that output_dir exists first
output_dir = os.path.realpath(args.output_dir)
if not os.path.exists(output_dir):
    system.LogError("Path '%s' does not exist" % args.output_dir)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Download game
    gog.DownloadGame(
        game = args.game,
        output_dir = output_dir,
        platform = args.platform,
        include = args.include,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
