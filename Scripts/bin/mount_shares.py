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
import userdata

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get network share info
    nas_base_location = userdata.GetIniValue("UserData.NAS", "nas_base_location")
    nas_storage_folder = userdata.GetIniValue("UserData.NAS", "nas_storage_folder")
    nas_cache_folder = userdata.GetIniValue("UserData.NAS", "nas_cache_folder")
    nas_username = userdata.GetIniValue("UserData.NAS", "nas_username")
    nas_password = userdata.GetIniValue("UserData.NAS", "nas_password")

    # Get flags
    verbose = userdata.GetIniValue("UserData.Flags", "verbose")
    exit_on_failure = userdata.GetIniValue("UserData.Flags", "exit_on_failure")

    # Mount storage
    network.MountNetworkShare(
        mount_dir = environment.GetStorageRootDir(),
        base_location = nas_base_location,
        network_share = nas_storage_folder,
        username = nas_username,
        password = nas_password,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Mount cache
    network.MountNetworkShare(
        mount_dir = environment.GetRemoteCacheRootDir(),
        base_location = nas_base_location,
        network_share = nas_cache_folder,
        username = nas_username,
        password = nas_password,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
environment.RunAsRootIfNecessary(main)
