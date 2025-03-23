# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import hashing

###########################################################

# Build hash files
def BuildHashFiles(
    game_supercategory,
    game_category,
    game_subcategory,
    game_root = None,
    passphrase = None,
    source_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    if not system.IsPathDirectory(game_root):
        game_root = environment.GetLockerGamingFilesDir(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            source_type = source_type)
    if not system.IsPathDirectory(game_root):
        return False

    # Get hash info
    hash_file = environment.GetHashesMetadataFile(game_supercategory, game_category, game_subcategory)
    hash_offset = system.JoinPaths(game_supercategory, game_category, game_subcategory)

    # Hash files
    success = hashing.HashFiles(
        src = game_root,
        offset = hash_offset,
        output_file = hash_file,
        passphrase = passphrase,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Sort hash files
def SortHashFiles(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Sort hash files
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:

                # Get hash file
                hash_file = environment.GetHashesMetadataFile(
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
