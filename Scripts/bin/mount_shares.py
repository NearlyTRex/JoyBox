#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import network

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Mount storage
    network.MountNetworkShare(
        mount_dir = environment.GetStorageRootDir(),
        base_location = environment.GetNetworkShareBaseLocation(),
        network_share = environment.GetNetworkShareStorageFolder(),
        username = environment.GetNetworkShareUsername(),
        password = environment.GetNetworkSharePassword(),
        verbose = config.default_flag_verbose)

    # Mount cache
    network.MountNetworkShare(
        mount_dir = environment.GetRemoteCacheRootDir(),
        base_location = environment.GetNetworkShareBaseLocation(),
        network_share = environment.GetNetworkShareCacheFolder(),
        username = environment.GetNetworkShareUsername(),
        password = environment.GetNetworkSharePassword(),
        verbose = config.default_flag_verbose)

# Start
environment.RunAsRootIfNecessary(main)














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
parser = argparse.ArgumentParser(description="Mount network shares.")
args, unknown = parser.parse_known_args()

# Main
def main():

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
        setup.SetupRequiredTools(force_downloads = args.force)

    # Setup emulators
    if args.type == "emulators" or args.type == "all":
        setup.SetupRequiredEmulators(force_downloads = args.force)

    # Setup assets
    if args.type == "assets" or args.type == "all":
        setup.SetupRequiredMetadataAssets()

# Start
environment.RunAsRootIfNecessary(main)
