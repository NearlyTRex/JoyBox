# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import hashing

###########################################################

# Hash game files
def HashGameFiles(
    game_supercategory,
    game_category,
    game_subcategory,
    game_root,
    passphrase = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get base path
    base_path = None
    if system.IsPathValid(game_root):
        base_path = os.path.realpath(game_root)
    if not system.DoesPathExist(base_path):
        return False

    # Get hash info
    hash_file = environment.GetHashesMetadataFile(game_supercategory, game_category, game_subcategory)
    hash_offset = system.JoinPaths(game_supercategory, game_category, game_subcategory)

    # Hash files
    success = hashing.HashFiles(
        src = base_path,
        offset = hash_offset,
        output_file = hash_file,
        passphrase = passphrase,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################
