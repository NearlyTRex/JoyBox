#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import programs
import command
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download GOG game.")
parser.add_argument("game_pattern", help="Game to download (regex pattern)")
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

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get tool
    gog_tool = None
    if programs.IsToolInstalled("LGOGDownloader"):
        gog_tool = programs.GetToolProgram("LGOGDownloader")
    if not gog_tool:
        system.LogError("LGOGDownloader was not found")
        sys.exit(1)

    # Get download command
    download_cmd = [
        gog_tool,
        "--download",
        "--platform=%s" % args.platform,
        "--include=%s" % args.include,
        "--directory=%s" % os.path.realpath(args.output_dir),
        "--game=%s" % args.game_pattern
    ]

    # Run download command
    command.RunCheckedCommand(
        cmd = download_cmd,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
