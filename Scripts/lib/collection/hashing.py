# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import environment
import hashing
import lockerinfo
import gameinfo

###########################################################

# Build hash files
def build_hash_files(
    game_info,
    game_root = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    if not paths.is_path_directory(game_root):
        game_root = environment.get_locker_gaming_files_dir(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            locker_type = locker_type)
    if not paths.is_path_directory(game_root):
        return False

    # Get hash info
    hash_file = environment.get_game_hashes_metadata_file(game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory())
    game_name_path = gameinfo.derive_game_name_path_from_name(game_info.get_name(), game_info.get_platform())
    hash_offset = paths.join_paths(game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory(), game_name_path)

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Hash files
    success = hashing.hash_files(
        src = game_root,
        output_file = hash_file,
        offset = hash_offset,
        passphrase = locker_info.get_passphrase(),
        hash_format = config.HashFormatType.JSON,
        include_enc_fields = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Clean missing hash entries
def clean_missing_hash_entries(
    game_supercategory,
    game_category,
    game_subcategory,
    locker_root,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get hash file
    hash_file = environment.get_game_hashes_metadata_file(game_supercategory, game_category, game_subcategory)
    if not paths.is_path_file(hash_file):
        return True

    # Clean missing entries
    return hashing.clean_missing_hash_entries(
        hash_file = hash_file,
        locker_root = locker_root,
        hash_format = config.HashFormatType.JSON,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Build all hash files
def build_all_hash_files(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_names = gameinfo.find_json_game_names(
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
                    success = build_hash_files(
                        game_info = game_info,
                        locker_type = locker_type,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################

# Sort hash file
def sort_hash_file(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get hash file
    hash_file = environment.get_game_hashes_metadata_file(
        game_supercategory = game_info.get_supercategory(),
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory())
    if not paths.is_path_file(hash_file):
        return False

    # Sort hash file
    success = hashing.sort_hash_file(
        src = hash_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Sort all hash files
def sort_all_hash_files(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Sort hash files
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:

                # Get hash file
                hash_file = environment.get_game_hashes_metadata_file(
                    game_supercategory = game_supercategory,
                    game_category = game_category,
                    game_subcategory = game_subcategory)
                if not paths.is_path_file(hash_file):
                    continue

                # Sort hash file
                success = hashing.sort_hash_file(
                    src = hash_file,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

    # Should be successful
    return True

############################################################
