#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import collection
import gameinfo
import arguments
import metadata
import stores
import manifest
import setup
import ini

# Parse arguments
parser = arguments.ArgumentParser(description = "Scan roms files.")
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.REMOTE,
    description = "Source type")
parser.add_enum_argument(
    args = ("-t", "--passphrase_type"),
    arg_type = config.PassphraseType,
    description = "Passphrase type")
parser.add_string_argument(args = ("-k", "--keys"), description = "Keys to use (comma delimited)")
parser.add_boolean_argument(args = ("-m", "--load_manifest"), description = "Load manifest")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.PassphraseType.GENERAL:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.PassphraseType.LOCKER:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Load manifest
    if args.load_manifest:
        system.LogInfo("Loading manifest ...")
        manifest.GetManifestInstance().load(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Build game store purchases
    system.LogInfo("Building store purchases ...")
    success = collection.BuildAllGameStorePurchases(
        passphrase = passphrase,
        source_type = args.source_type,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Building store purchases failed", quit_program = True)

    # Build game json files
    system.LogInfo("Building json files ...")
    success = collection.BuildAllGameJsonFiles(
        passphrase = passphrase,
        source_type = args.source_type,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Building json files failed", quit_program = True)

    # Build game metadata files
    system.LogInfo("Building metadata files ...")
    success = collection.BuildAllGameMetadataEntries(
        source_type = args.source_type,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Building metadata files failed", quit_program = True)

    # Download game metadata assets
    system.LogInfo("Downloading metadata assets ...")
    success = collection.DownloadAllMetadataAssets(
        skip_existing = True,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Downloading metadata assets failed", quit_program = True)

    # Publish game metadata files
    system.LogInfo("Publishing metadata files ...")
    success = collection.PublishAllGameMetadataEntries(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Publishing metadata files failed", quit_program = True)

# Start
main()
