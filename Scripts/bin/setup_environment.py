#!/usr/bin/env python3

# Imports
import os
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Setup environment.")
parser.add_argument("-t", "--type",
    choices=[
        "vars",
        "python",
        "packages",
        "mounts",
        "tools",
        "emulators",
        "libs",
        "assets",
        "all"
    ],
    default="all", help="Setup type"
)
parser.add_argument("-f", "--force", action="store_true", help="Force setup actions to always occur")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Setup environment variables
    if args.type == "vars" or args.type == "all":
        setup.WriteRequiredEnvironmentVariables()

    # Setup python
    if args.type == "python" or args.type == "all":
        setup.InstallRequiredPythonModules()

    # Setup packages
    if args.type == "packages" or args.type == "all":
        setup.InstallRequiredSystemPackages()

    # Setup mounts
    if args.type == "mounts" or args.type == "all":
        setup.MountRequiredNetworkShares()

    # Setup tools
    if args.type == "tools" or args.type == "all":
        setup.DownloadRequiredTools(force_downloads = args.force)
        setup.SetupRequiredTools()

    # Setup emulators
    if args.type == "emulators" or args.type == "all":
        setup.DownloadRequiredEmulators(force_downloads = args.force)
        setup.SetupRequiredEmulators()

    # Setup libraries
    if args.type == "libs" or args.type == "all":
        setup.DownloadRequiredLibraries(force_downloads = args.force)

    # Setup assets
    if args.type == "assets" or args.type == "all":
        setup.SetupRequiredMetadataAssets()

# Start
environment.RunAsRootIfNecessary(main)
