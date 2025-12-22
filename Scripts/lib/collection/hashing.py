# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import environment
import hashing
import lockerinfo

###########################################################

# Build hash files
def BuildHashFiles(
    game_info,
    game_root = None,
    locker_type = None,
    source_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    if not system.IsPathDirectory(game_root):
        game_root = environment.GetLockerGamingFilesDir(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            source_type = source_type)
    if not system.IsPathDirectory(game_root):
        return False

    # Get hash info
    hash_file = environment.GetGameHashesMetadataFile(game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory())
    hash_offset = system.JoinPaths(game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory())

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Hash files
    success = hashing.HashFiles(
        src = game_root,
        offset = hash_offset,
        output_file = hash_file,
        passphrase = locker_info.get_passphrase(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Build all hash files
def BuildAllHashFiles(
    locker_type = None,
    source_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_names = gameinfo.FindJsonGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:
                    game_info = gameinfo.GameInfo(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    success = BuildHashFiles(
                        game_info = game_info,
                        locker_type = locker_type,
                        source_type = source_type,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################

# Sort hash file
def SortHashFile(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get hash file
    hash_file = environment.GetGameHashesMetadataFile(
        game_supercategory = game_info.get_supercategory(),
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory())
    if not system.IsPathFile(hash_file):
        return False

    # Sort hash file
    success = hashing.SortHashFile(
        src = hash_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Sort all hash files
def SortAllHashFiles(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Sort hash files
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:

                # Get hash file
                hash_file = environment.GetGameHashesMetadataFile(
                    game_supercategory = game_supercategory,
                    game_category = game_category,
                    game_subcategory = game_subcategory)
                if not system.IsPathFile(hash_file):
                    continue

                # Sort hash file
                success = hashing.SortHashFile(
                    src = hash_file,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

    # Should be successful
    return True

############################################################
