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
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_platform = game_info.get_platform()

    # No addon possible
    if not platforms.AreAddonsPossible(game_platform):
        return True

    # Get directories
    source_dlc_dirs = []
    source_update_dirs = []
    for filename in game_info.get_value(config.json_key_dlc):
        source_dlc_dirs += [system.JoinPaths(environment.GetLockerGamingDLCRootDir(), filename)]
    for filename in game_info.get_value(config.json_key_update):
        source_update_dirs += [system.JoinPaths(environment.GetLockerGamingUpdateRootDir(), filename)]

    # Install add-ons
    for emulator in programs.GetEmulators():
        if game_platform in emulator.GetPlatforms():
            success = emulator.InstallAddons(
                dlc_dirs = source_dlc_dirs,
                update_dirs = source_update_dirs,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True
