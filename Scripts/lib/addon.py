# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__)))
sys.path.append(lib_folder)
import config
import system
import environment
import metadata
import platforms
import programs

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

    # Get categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)

    # Get json info
    json_file_data = system.ReadJsonFile(
        src = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get directories
    source_dlc_dirs = []
    source_update_dirs = []
    if config.general_key_dlc in json_file_data:
        if isinstance(json_file_data[config.general_key_dlc], str):
            source_dlc_dirs += [os.path.join(environment.GetDLCRootDir(), json_file_data[config.general_key_dlc])]
    if config.general_key_update in json_file_data:
        if isinstance(json_file_data[config.general_key_update], str):
            source_update_dirs += [os.path.join(environment.GetUpdateRootDir(), json_file_data[config.general_key_update])]

    # Install add-ons
    for emulator in programs.GetEmulators():
        if game_platform in emulator.GetPlatforms():
            emulator.InstallAddons(
                dlc_dirs = source_dlc_dirs,
                update_dirs = source_update_dirs,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            break
