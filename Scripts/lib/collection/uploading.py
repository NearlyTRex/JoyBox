# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import cryption
import locker
from .hashing import BuildHashFiles

############################################################

# Upload game files
def UploadGameFiles(
    game_info,
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

    # Encrypt all files
    success = cryption.EncryptFiles(
        src = base_path,
        passphrase = passphrase,
        delete_original = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Hash all files
    success = BuildHashFiles(
        game_info = game_info,
        game_root = base_path,
        passphrase = passphrase,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload all files
    success = locker.UploadPath(
        src = base_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################
