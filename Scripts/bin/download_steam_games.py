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
parser = argparse.ArgumentParser(description="Download Steam games.")
parser.add_argument("input_path", type=str, default=".", help="Input path")
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
parser.add_argument("-f", "--force_download", action="store_true", help="Always download")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Get input path
input_path = os.path.realpath(args.input_path)
if not os.path.exists(input_path):
    system.LogError("Path '%s' does not exist" % args.input_path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Download games
    for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
        steam.DownloadGameByJsonFile(
            json_file = json_file,
            platform = args.platform,
            arch = args.arch,
            login = args.login,
            force_download = args.force_download,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

# Start
main()
