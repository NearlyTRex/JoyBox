# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import cryption
import locker
import lockerinfo
from .hashing import BuildHashFiles

############################################################

# Upload game files
def UploadGameFiles(
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

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        system.LogError("Locker %s not found" % locker_type)
        return False

    # Encrypt all files
    success = cryption.EncryptFiles(
        src = game_root,
        passphrase = locker_info.get_passphrase(),
        delete_original = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Hash all files
    success = BuildHashFiles(
        game_info = game_info,
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload all files
    success = locker.UploadPath(
        src = game_root,
        verbose = verbose,
        locker_type = locker_type,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Upload all game files
def UploadAllGameFiles(
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
                    success = UploadGameFiles(
                        game_info = game_info,
                        locker_type = locker_type,
                        source_type = source_type,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

    # Should be successful
    return True

############################################################
