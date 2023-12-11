#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import network
import setup
import ini

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get config info
    nas_base_location = ini.GetIniValue("UserData.NAS", "nas_base_location")
    nas_storage_folder = ini.GetIniValue("UserData.NAS", "nas_storage_folder")
    nas_cache_folder = ini.GetIniValue("UserData.NAS", "nas_cache_folder")
    nas_username = ini.GetIniValue("UserData.NAS", "nas_username")
    nas_password = ini.GetIniValue("UserData.NAS", "nas_password")
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Check config info
    system.AssertIsNonEmptyString(nas_base_location, "nas_base_location")
    system.AssertIsNonEmptyString(nas_storage_folder, "nas_storage_folder")
    system.AssertIsNonEmptyString(nas_cache_folder, "nas_cache_folder")
    system.AssertIsNonEmptyString(nas_username, "nas_username")
    system.AssertIsNonEmptyString(nas_password, "nas_password")
    system.AssertIsBool(verbose, "verbose")
    system.AssertIsBool(exit_on_failure, "exit_on_failure")

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
