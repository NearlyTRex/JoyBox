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
import programs
import archive
import playstation
import nintendo
import xbox

# Check if addons are possible
def AreAddonsPossible(game_platform):
    return game_platform in config.addon_platform_mapping

# Check if updates are possible
def AreUpdatesPossible(game_platform):
    if game_platform in config.addon_platform_mapping:
        if "updates" in config.addon_platform_mapping[game_platform]:
            return config.addon_platform_mapping[game_platform]["updates"]
    return False

# Check if dlc are possible
def AreDLCPossible(game_platform):
    if game_platform in config.addon_platform_mapping:
        if "dlc" in config.addon_platform_mapping[game_platform]:
            return config.addon_platform_mapping[game_platform]["dlc"]
    return False

# Install addons
def InstallAddons(
    game_platform,
    game_name,
    json_file,
    verbose = False,
    exit_on_failure = False):

    # No addon possible
    if not AreAddonsPossible(game_platform):
        return True

    # Get categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)

    # Get json info
    json_file_data = system.ReadJsonFile(
        src = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get directories
    source_update_dirs = []
    source_dlc_dirs = []
    if config.general_key_update in json_file_data:
        if isinstance(json_file_data[config.general_key_update], str):
            source_update_dirs += [os.path.join(environment.GetUpdateRootDir(), json_file_data[config.general_key_update])]
    if config.general_key_dlc in json_file_data:
        if isinstance(json_file_data[config.general_key_dlc], str):
            source_dlc_dirs += [os.path.join(environment.GetDLCRootDir(), json_file_data[config.general_key_dlc])]

    # Nintendo 3DS
    if game_platform in config.citra_platforms:

        # Updates/DLC
        for package_dirset in [source_update_dirs, source_dlc_dirs]:
            for package_dir in package_dirset:
                for cia_file in system.BuildFileListByExtensions(package_dir, extensions = [".cia"]):
                    nintendo.Install3DSCIA(
                        src_3ds_file = cia_file,
                        sdmc_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir"), "sdmc"),
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

    # Nintendo Switch
    elif game_platform in config.yuzu_platforms:

        # Updates/DLC
        for package_dirset in [source_update_dirs, source_dlc_dirs]:
            for package_dir in package_dirset:
                for nsp_file in system.BuildFileListByExtensions(package_dir, extensions = [".nsp"]):
                    nintendo.InstallSwitchNSP(
                        nsp_file = nsp_file,
                        nand_dir = os.path.join(programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir"), "nand"),
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

    # Nintendo Wii
    elif game_platform in config.dolphin_platforms:

        # Updates/DLC
        for package_dirset in [source_update_dirs, source_dlc_dirs]:
            for package_dir in package_dirset:
                for wad_file in system.BuildFileListByExtensions(package_dir, extensions = [".wad"]):
                    pass

    # Nintendo Wii U
    elif game_platform in config.cemu_platforms:

        # Updates/DLC
        for package_dirset in [source_update_dirs, source_dlc_dirs]:
            for package_dir in package_dirset:
                for tik_file in system.BuildFileListByExtensions(package_dir, extensions = [".tik"]):
                    if tik_file.endswith("title.tik"):
                        tik_dir = system.GetFilenameDirectory(tik_file)
                        nintendo.InstallWiiUNusPackage(
                            nus_package_dir = tik_dir,
                            nand_dir = os.path.join(programs.GetEmulatorPathConfigValue("Cemu", "setup_dir"), "mlc01"),
                            verbose = verbose,
                            exit_on_failure = exit_on_failure)
