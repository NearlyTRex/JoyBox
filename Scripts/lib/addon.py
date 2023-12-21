# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import metadata
import platforms
import programs
import gameinfo

# Install addons
def InstallAddons(
    json_data,
    verbose = False,
    exit_on_failure = False):

    # Get game info
    game_name = json_data[config.json_key_base_name]
    game_platform = json_data[config.json_key_platform]

    # No addon possible
    if not platforms.AreAddonsPossible(game_platform):
        return True

    # Get directories
    source_dlc_dirs = []
    source_update_dirs = []
    for filename in json_data[config.json_key_dlc]:
        source_dlc_dirs += [os.path.join(environment.GetDLCRootDir(), filename)]
    for filename in json_data[config.json_key_update]:
        source_update_dirs += [os.path.join(environment.GetUpdateRootDir(), filename)]

    # Install add-ons
    for emulator in programs.GetEmulators():
        if game_platform in emulator.GetPlatforms():
            emulator.InstallAddons(
                dlc_dirs = source_dlc_dirs,
                update_dirs = source_update_dirs,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
