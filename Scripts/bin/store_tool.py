#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import stores
import system
import setup
import ini
from stores import steam

# Parse arguments
parser = argparse.ArgumentParser(description="Manage store games.")
parser.add_argument("-i", "--input_path", type=str, default=".", help="Input path")
parser.add_argument("-t", "--store_type",
    choices=config.store_types,
    default=config.store_type_steam,
    help="Store type"
)
parser.add_argument("-a", "--store_action",
    choices=config.store_action_types,
    default=config.store_action_type_download,
    help="Store action"
)
parser.add_argument("-s", "--skip_existing", action="store_true", help="Skip existing entries")
parser.add_argument("-f", "--force", action="store_true", help="Always run action")
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory")
parser.add_argument("-m", "--load_manifest", action="store_true", help="Load manifest")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Get input path
input_path = None
if system.IsPathValid(args.input_path):
    input_path = os.path.realpath(args.input_path)
    if not os.path.exists(input_path):
        system.LogError("Path '%s' does not exist" % args.input_path)
        sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get store
    store_obj = None
    if args.store_type == config.store_type_steam:
        store_obj = steam.Steam()
    else:
        system.LogError("Invalid store")
        sys.exit(-1)

    # Load manifest
    if args.load_manifest:
        store_obj.LoadManifest()

    # Login
    if args.store_action == config.store_action_type_login:
        store_obj.Login()

    # Download
    elif args.store_action == config.store_action_type_download:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            success = store_obj.Download(
                json_file = json_file,
                output_dir = args.output_dir,
                skip_existing = args.skip_existing,
                force = args.force,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                break

    # Check
    elif args.store_action == config.store_action_type_check:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            local_version, remote_version = store_obj.GetVersions(
                json_file = json_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if local_version and remote_version:
                if local_version != remote_version:
                    system.LogWarning("Game '%s' is out of date! Local = '%s', remote = '%s'" % (json_file, local_version, remote_version))

# Start
main()
