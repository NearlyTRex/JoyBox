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
    game_platform,
    game_name,
    json_file,
    verbose = False,
    exit_on_failure = False):

    # No addon possible
    if not platforms.AreAddonsPossible(game_platform):
        return True

    # Get json info
    json_data = gameinfo.ParseGameJson(
        json_file = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

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
