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
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download Steam game.")
parser.add_argument("game", help="Game to download (appid)")
parser.add_argument("-b", "--branchid", type=str, help="Branch id to download")
parser.add_argument("-l", "--login", type=str, help="Steam login username")
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
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory")
parser.add_argument("-n", "--output_name", type=str, default="game", help="Output name")
parser.add_argument("-j", "--json_file", type=str, help="Json file")
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
    steam.DownloadGame(
        appid = args.game,
        branchid = args.branchid,
        output_dir = output_dir,
        output_name = args.output_name,
        platform = args.platform,
        arch = args.arch,
        login = args.login,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

    # Update json file
    if args.json_file:
        json_file = os.path.realpath(args.json_file)
        json_data = system.ReadJsonFile(
            src = json_file,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)
        json_data[config.json_key_steam] = steam.GetGameInfo(
            appid = args.game,
            branchid = args.branchid,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)
        system.WriteJsonFile(
            src = json_file,
            json_data = json_data,
            sort_keys = True,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
