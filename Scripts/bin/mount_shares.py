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
import setup

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
