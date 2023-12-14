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
import metadata
import launcher
import cache
import setup
import gui
import ini

# Setup argument parser
parser = argparse.ArgumentParser(description="Launch ROM.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("rom", help="ROM to launch")
parser.add_argument("-l", "--launch_platform", type=str, help="Launch platform")
parser.add_argument("-f", "--force_cache_refresh", action="store_true", help="Force refresh of cached files")
parser.add_argument("-c", "--capture_type",
    choices=[
        config.capture_type_none,
        config.capture_type_screenshot,
        config.capture_type_video,
    ],
    default=config.capture_type_none, help="Capture type"
)

# Parse arguments
args, unknownargs = parser.parse_known_args()
if not args.rom:
    parser.print_help()
    sys.exit(1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Get launch info
    launch_platform = args.launch_platform
    launch_file = system.ResolveVirtualRomPath(args.rom)
    launch_name = metadata.DeriveGameNameFromPath(launch_file)
    if not launch_name:
        gui.DisplayErrorPopup(
            title_text = "Game name could not be resolved",
            message_text = "Game name for '%s' could not be resolved" % launch_file)
    launch_supercategory, launch_category, launch_subcategory = metadata.DeriveMetadataCategoriesFromFile(launch_file)
    if not launch_platform and launch_category and launch_subcategory:
        launch_platform = metadata.DeriveMetadataPlatform(launch_category, launch_subcategory)
    if not launch_platform:
        gui.DisplayErrorPopup(
            title_text = "Game platform could not be resolved",
            message_text = "Game platform for '%s' could not be resolved" % launch_file)

    # Force cache refresh
    if args.force_cache_refresh:
        cache.RemoveGameFromCache(
            game_platform = launch_platform,
            game_name = launch_name,
            game_file = launch_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Launch rom
    launcher.LaunchGame(
        launch_platform = launch_platform,
        file_path = launch_file,
        capture_type = args.capture_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
