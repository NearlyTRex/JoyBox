#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import gog
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="GOG tool.")
parser.add_argument("input_path", type=str, default=".", help="Input path")
parser.add_argument("-a", "--action",
    choices=[
        "download",
        "check"
    ],
    default="download",
    help="Program action"
)
parser.add_argument("-p", "--platform",
    choices=[
        "windows",
        "linux"
    ],
    default="windows",
    help="Relevant platform"
)
parser.add_argument("-s", "--skip_existing", action="store_true", help="Skip existing entries")
parser.add_argument("-f", "--force", action="store_true", help="Always run action")
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory")
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
    if args.action == "download":
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            success = gog.DownloadGameByJsonFile(
                json_file = json_file,
                platform = args.platform,
                output_dir = args.output_dir,
                skip_existing = args.skip_existing,
                force = args.force,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                break

    # Check games
    elif args.action == "check":
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            success = gog.CheckGameByJsonFile(
                json_file = json_file,
                platform = args.platform,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                break

# Start
main()
