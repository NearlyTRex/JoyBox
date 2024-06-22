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
from tools import ludusavimanifest

# Parse arguments
parser = argparse.ArgumentParser(description="Download Steam games.")
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
parser.add_argument("-r", "--arch",
    choices=[
        "32",
        "64"
    ],
    default="64",
    help="Relevant architecture"
)
parser.add_argument("-l", "--login", type=str, help="Steam login username")
parser.add_argument("-s", "--skip_existing", action="store_true", help="Skip existing entries")
parser.add_argument("-f", "--force", action="store_true", help="Always run action")
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory")
parser.add_argument("-m", "--load_manifest", action="store_true", help="Load manifest")
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

    # Load manifest
    manifest = None
    if args.load_manifest:
        manifest = system.ReadYamlFile(
            src = ludusavimanifest.GetManifest(),
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Download games
    if args.action == "download":
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            success = steam.DownloadGameByJsonFile(
                json_file = json_file,
                platform = args.platform,
                arch = args.arch,
                login = args.login,
                manifest = manifest,
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
            success = steam.CheckGameByJsonFile(
                json_file = json_file,
                platform = args.platform,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                break

# Start
main()
