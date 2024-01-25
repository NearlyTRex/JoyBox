#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import environment
import network
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Mount shares.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get nas info
    nas_base_location = ini.GetIniValue("UserData.NAS", "nas_base_location")
    nas_storage_folder = ini.GetIniValue("UserData.NAS", "nas_storage_folder")
    nas_cache_folder = ini.GetIniValue("UserData.NAS", "nas_cache_folder")
    nas_username = ini.GetIniValue("UserData.NAS", "nas_username")
    nas_password = ini.GetIniValue("UserData.NAS", "nas_password")

    # Check nas info
    system.AssertIsNonEmptyString(nas_base_location, "nas_base_location")
    system.AssertIsNonEmptyString(nas_storage_folder, "nas_storage_folder")
    system.AssertIsNonEmptyString(nas_cache_folder, "nas_cache_folder")
    system.AssertIsNonEmptyString(nas_username, "nas_username")
    system.AssertIsNonEmptyString(nas_password, "nas_password")

    # Mount storage
    network.MountNetworkShare(
        mount_dir = environment.GetStorageRootDir(),
        base_location = nas_base_location,
        network_share = nas_storage_folder,
        username = nas_username,
        password = nas_password,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

    # Mount cache
    network.MountNetworkShare(
        mount_dir = environment.GetRemoteCacheRootDir(),
        base_location = nas_base_location,
        network_share = nas_cache_folder,
        username = nas_username,
        password = nas_password,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Start
main()
