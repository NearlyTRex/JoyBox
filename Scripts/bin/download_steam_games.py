#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import steam
import system
import gameinfo
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download Steam games.")
parser.add_argument("input_path", help="Input path")
parser.add_argument("-p", "--platform",
    choices=[
        "windows",
        "linux"
    ],
    default="windows",
    help="Download platform"
)
parser.add_argument("-r", "--arch",
    choices=[
        "32",
        "64"
    ],
    default="64",
    help="Download architecture"
)
parser.add_argument("-l", "--login", type=str, help="Steam login username")
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory")
parser.add_argument("-f", "--force", action="store_true", help="Always download")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Get input path
input_path = os.path.realpath(args.input_path)
if not os.path.exists(input_path):
    system.LogError("Path '%s' does not exist" % args.input_path)
    sys.exit(-1)

# Get output dir
output_dir = os.path.realpath(args.output_dir)
if not os.path.exists(output_dir):
    system.LogError("Path '%s' does not exist" % args.output_dir)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get json files
    for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):

        # Get game info
        game_info = gameinfo.GameInfo(
            json_file = json_file,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

        # Ignore non-steam games
        if game_info.get_steam_appid() == "":
            continue

        # Get latest steam info
        latest_steam_info = steam.GetGameInfo(
            appid = game_info.get_steam_appid(),
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

        # Check if game should be downloaded
        should_download = False
        if args.force:
            should_download = True
        elif game_info.get_steam_branchid() != "":
            should_download = False
        elif game_info.get_steam_changeid() == "":
            should_download = True
        else:
            old_changeid = game_info.get_steam_changeid()
            new_changeid = latest_steam_info[config.json_key_steam_changeid]
            if new_changeid.isnumeric() and old_changeid.isnumeric():
                should_download = int(new_changeid) > int(old_changeid)
        if not should_download:
            continue

        # Download game
        steam.DownloadGame(
            appid = game_info.get_steam_appid(),
            branchid = game_info.get_steam_branchid(),
            output_dir = os.path.join(output_dir, game_info.get_name()),
            output_name = game_info.get_name(),
            platform = args.platform,
            arch = args.arch,
            login = args.login,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

        # Update json file
        json_data = system.ReadJsonFile(
            src = json_file,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)
        json_data[config.json_key_steam] = latest_steam_info
        system.WriteJsonFile(
            src = json_file,
            json_data = json_data,
            sort_keys = True,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
